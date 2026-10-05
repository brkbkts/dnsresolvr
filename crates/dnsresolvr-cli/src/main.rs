use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use dnsresolvr_core::{
    add_system_resolvers, build_endpoints, bundled_resolvers, dedup_preserve, default_domains, export,
    load_domains_file, load_resolvers_file, merge_resolvers, probe_udp_at, run_bench_with_progress,
    system_resolvers, verdict, BenchConfig, EndpointReport, ExportFormat, PrivacyInfo, RecordType,
    Resolver, Session, Summary, Transport, TransportKind,
};

mod tui;

#[derive(Parser)]
#[command(
    name = "dnsresolvr",
    version,
    about = "DNS resolver benchmark",
    long_about = "Run `dnsresolvr` with no arguments to launch the interactive TUI.\n\
                  Subcommands `bench`, `probe`, and `list` are for scripting.\n\
                  All config can be changed inside the TUI via `:` commands. See `:help`."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

/// Sample-size preset. Overrides `--iterations` when set.
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Preset {
    /// 1 iteration per domain — smoke test
    Quick,
    /// 4 iterations per domain — default
    Standard,
    /// 20 iterations per domain — tighter tail stats
    Thorough,
    /// 50 iterations per domain — high-confidence run
    Exhaustive,
}

impl Preset {
    pub fn iterations(self) -> usize {
        match self {
            Preset::Quick => 1,
            Preset::Standard => 4,
            Preset::Thorough => 20,
            Preset::Exhaustive => 50,
        }
    }

    pub fn parse_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "quick" | "q" => Some(Preset::Quick),
            "standard" | "std" | "s" => Some(Preset::Standard),
            "thorough" | "t" => Some(Preset::Thorough),
            "exhaustive" | "e" | "exh" => Some(Preset::Exhaustive),
            _ => None,
        }
    }
}

/// Which resolvers to test. Shared by every subcommand.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct ResolverArgs {
    /// JSON file with extra resolvers (same format as the bundled list).
    /// An entry with the name of a bundled resolver replaces it.
    #[arg(long, value_name = "PATH")]
    resolvers: Option<PathBuf>,
    /// Add one resolver: NAME=ADDR[,ADDR..][,dot=HOST][,doq=HOST][,doh=URL][,doh3][,port=N].
    /// Repeatable.
    #[arg(long = "add-resolver", value_name = "SPEC")]
    add_resolvers: Vec<String>,
    /// Leave out the bundled list; test only --resolvers / --add-resolver entries.
    #[arg(long)]
    no_bundled: bool,
    /// Do not add the DNS servers this machine is configured to use.
    #[arg(long)]
    no_system: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the resolver list.
    List {
        #[command(flatten)]
        resolvers: ResolverArgs,
    },
    /// Probe every resolver once for <host> over plain UDP and print RTTs.
    Probe {
        host: String,
        #[arg(long, default_value_t = 1500)]
        timeout_ms: u64,
        #[command(flatten)]
        resolvers: ResolverArgs,
    },
    /// Check that every resolver endpoint still answers. Exits with status 1
    /// if any does not. Endpoints on private addresses are skipped.
    Check {
        #[command(flatten)]
        resolvers: ResolverArgs,
        /// Also check IPv6 endpoints.
        #[arg(long)]
        ipv6: bool,
        /// Resolver name to leave out. Repeatable.
        #[arg(long, value_name = "NAME")]
        skip: Vec<String>,
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
    },
    /// Launch the live ratatui TUI (same as running with no subcommand).
    Tui(BenchArgs),
    /// Run the benchmark and print the result table and verdict. In a terminal
    /// this shows the live view while it runs; with --plain, or when the output
    /// is piped, it runs headless (CI / scripting).
    Bench(BenchArgs),
}

#[derive(clap::Args, Debug, Clone)]
pub struct BenchArgs {
    /// Iterations per domain per class. Ignored if --preset is set.
    #[arg(long, default_value_t = 4)]
    iterations: usize,
    #[arg(long, value_enum)]
    preset: Option<Preset>,
    #[arg(long, default_value_t = 1500)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 40)]
    spacing_ms: u64,
    /// Skip the cached class (warm-cache probing).
    #[arg(long)]
    no_cached: bool,
    /// Skip the uncached class (random-subdomain, forces recursion).
    #[arg(long)]
    no_uncached: bool,
    /// Skip the untimed warm-up query per domain before the cached class.
    #[arg(long)]
    no_warmup: bool,
    /// Skip the DNSSEC validation check.
    #[arg(long)]
    no_dnssec_check: bool,
    /// Skip the exit-server and client-subnet (ECS) checks.
    #[arg(long)]
    no_privacy_check: bool,
    /// Uncached class queries <random>.<DOMAIN> and expects an address. Use a
    /// domain with a wildcard record to measure uncached positive answers.
    #[arg(long, value_name = "DOMAIN")]
    wildcard_domain: Option<String>,
    #[arg(long)]
    ipv6: bool,
    /// Probe every listed address of each resolver, not only the first.
    #[arg(long)]
    all_addrs: bool,
    /// Endpoints probed at the same time (0 = no limit).
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// Restrict to specific transports (comma-separated). Options: udp, dot, doh, doh3, doq. Default: all.
    #[arg(long, value_name = "LIST")]
    transports: Option<String>,
    #[arg(long = "add-domain", value_name = "DOMAIN")]
    add_domains: Vec<String>,
    #[arg(long, value_name = "PATH")]
    domains_file: Option<PathBuf>,
    #[arg(long)]
    only_custom: bool,
    /// `bench` only: never open the live view, just print the table at the end.
    /// This is automatic when the output is piped or redirected.
    #[arg(long)]
    plain: bool,
    #[arg(long, value_name = "PATH")]
    export: Option<PathBuf>,
    #[command(flatten)]
    resolvers: ResolverArgs,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        None => {
            let cfg = BenchConfig::default();
            let (resolvers, system) = load_resolvers(&ResolverArgs::default())?;
            run_live(cfg, resolvers, system, None).await
        }
        Some(Cmd::List { resolvers }) => cmd_list(&load_resolvers(&resolvers)?.0),
        Some(Cmd::Probe { host, timeout_ms, resolvers }) => {
            cmd_probe(&host, Duration::from_millis(timeout_ms), load_resolvers(&resolvers)?.0).await
        }
        Some(Cmd::Check { resolvers, ipv6, skip, timeout_ms }) => {
            let (list, _) = load_resolvers(&resolvers)?;
            cmd_check(list, ipv6, &skip, Duration::from_millis(timeout_ms)).await
        }
        Some(Cmd::Tui(args)) => {
            let export_path = args.export.clone();
            let cfg = build_bench_config(&args)?;
            let (resolvers, system) = load_resolvers(&args.resolvers)?;
            run_live(cfg, resolvers, system, export_path).await
        }
        Some(Cmd::Bench(args)) if !args.plain && std::io::stdout().is_terminal() => {
            let export_path = args.export.clone();
            let cfg = build_bench_config(&args)?;
            let (resolvers, system) = load_resolvers(&args.resolvers)?;
            run_live(cfg, resolvers, system, export_path).await
        }
        Some(Cmd::Bench(args)) => cmd_bench(args).await,
    }
}

/// Run the live view. The TUI's screen disappears on exit, so the final table
/// and verdict are printed afterwards and stay in the terminal's scrollback.
async fn run_live(
    cfg: BenchConfig,
    resolvers: Vec<Resolver>,
    system: Vec<IpAddr>,
    export_path: Option<PathBuf>,
) -> Result<()> {
    let outcome = tui::run(tui::TuiOpts { cfg, resolvers, system: system.clone(), export_path }).await?;
    let has_data = outcome.reports.iter().any(|r| r.cached.is_some() || r.uncached.is_some());
    if has_data {
        print_results(&outcome.reports, &outcome.cfg, &system);
    }
    Ok(())
}

fn print_results(reports: &[EndpointReport], cfg: &BenchConfig, system: &[IpAddr]) {
    print_bench_table(reports, cfg.cached, cfg.uncached);
    println!("\nVerdict");
    for line in verdict(reports, system).lines() {
        println!("  {}", line);
    }
}

/// Assemble the resolver list: bundled entries, then the user's file and
/// `--add-resolver` specs (which override by name), then the system resolvers.
/// Also returns the system's DNS server addresses (empty with `--no-system`).
fn load_resolvers(args: &ResolverArgs) -> Result<(Vec<Resolver>, Vec<IpAddr>)> {
    let mut list = if args.no_bundled { Vec::new() } else { bundled_resolvers() };
    if let Some(path) = &args.resolvers {
        let extra = load_resolvers_file(path).with_context(|| format!("reading {}", path.display()))?;
        list = merge_resolvers(list, extra);
    }
    let specs = args
        .add_resolvers
        .iter()
        .map(|s| Resolver::parse_spec(s).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    list = merge_resolvers(list, specs);
    let system = if args.no_system { Vec::new() } else { system_resolvers() };
    list = add_system_resolvers(list, &system);
    if list.is_empty() {
        anyhow::bail!("no resolvers to test (drop --no-bundled or add some with --add-resolver)");
    }
    Ok((list, system))
}

fn cmd_list(resolvers: &[Resolver]) -> Result<()> {
    println!(
        "{:<24} {:<12} {:<14} {:<18} {:<32} ipv6",
        "name", "provider", "filtering", "transports", "ipv4"
    );
    for r in resolvers {
        let v4 = r.ipv4.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",");
        let v6 = r.ipv6.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",");
        let mut kinds: Vec<TransportKind> = Vec::new();
        for t in r.transports(true, false) {
            if !kinds.contains(&t.kind()) { kinds.push(t.kind()); }
        }
        let kinds = kinds.iter().map(|k| k.label()).collect::<Vec<_>>().join(",");
        println!(
            "{:<24} {:<12} {:<14} {:<18} {:<32} {}",
            r.name, r.provider, r.filtering.as_deref().unwrap_or("-"), kinds, v4, v6
        );
    }
    println!("\n{} resolvers", resolvers.len());
    Ok(())
}

async fn cmd_probe(host: &str, rtt_timeout: Duration, resolvers: Vec<Resolver>) -> Result<()> {
    println!(
        "Probing {} resolvers for {} (UDP, A, timeout={:?})\n",
        resolvers.len(), host, rtt_timeout
    );
    println!("{:<24} {:<16} {:>10}  {:<8} answer", "resolver", "addr", "rtt", "rcode");
    println!("{}", "-".repeat(90));

    let mut handles = Vec::new();
    for r in resolvers.into_iter().filter(|r| r.plain) {
        if let Some(addr) = r.primary_addr() {
            let host = host.to_string();
            let name = r.name.clone();
            let target = std::net::SocketAddr::new(addr, r.port.unwrap_or(53));
            handles.push(tokio::spawn(async move {
                let res = probe_udp_at(target, &host, RecordType::A, rtt_timeout).await;
                (name, addr, res)
            }));
        }
    }

    let mut rows = Vec::new();
    for h in handles {
        if let Ok((name, addr, res)) = h.await {
            rows.push((name, addr, res));
        }
    }
    rows.sort_by_key(|(_, _, r)| match r {
        Ok(o) => (0u8, o.rtt.as_micros() as u64),
        Err(_) => (1u8, u64::MAX),
    });

    for (name, addr, res) in rows {
        match res {
            Ok(o) => {
                let answer = o.first_answer.clone().unwrap_or_default();
                println!(
                    "{:<24} {:<16} {:>8.1}ms  {:<8} {}",
                    name, addr.to_string(), o.rtt.as_secs_f64() * 1000.0,
                    format!("{:?}", o.rcode), answer
                );
            }
            Err(e) => {
                println!("{:<24} {:<16} {:>10}  {:<8} {}", name, addr.to_string(), "—", "ERR", e);
            }
        }
    }
    Ok(())
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// One query per endpoint over every transport it advertises. Used by the
/// scheduled CI job to notice bundled resolvers that have gone away.
async fn cmd_check(resolvers: Vec<Resolver>, ipv6: bool, skip: &[String], timeout: Duration) -> Result<()> {
    const ATTEMPTS: usize = 3;
    let cfg = BenchConfig { include_ipv6: ipv6, ..BenchConfig::default() };
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(8));

    let mut handles = Vec::new();
    let mut skipped = 0usize;
    for ep in build_endpoints(&resolvers, &cfg) {
        let private = match &ep.transport {
            Transport::Udp { addr, .. } | Transport::Dot { addr, .. } | Transport::Doq { addr, .. } => is_private(*addr),
            _ => false,
        };
        if private || skip.iter().any(|s| s.eq_ignore_ascii_case(&ep.resolver)) {
            skipped += 1;
            continue;
        }
        let slots = slots.clone();
        handles.push(tokio::spawn(async move {
            let _slot = slots.acquire().await;
            let mut last = String::new();
            for _ in 0..ATTEMPTS {
                let mut session = Session::new(ep.transport.clone());
                let started = std::time::Instant::now();
                let attempt = async {
                    session.connect(timeout).await?;
                    session.query("example.com", RecordType::A, timeout).await
                };
                match attempt.await {
                    Ok(o) if o.answer_count > 0 => return (ep, Ok(started.elapsed())),
                    Ok(o) => last = format!("{:?}, {} answers", o.rcode, o.answer_count),
                    Err(e) => last = e.to_string(),
                }
            }
            (ep, Err(last))
        }));
    }

    let mut failed = 0usize;
    let total = handles.len();
    println!("{:<6} {:<22} {:<4} {:<44} result", "status", "resolver", "t", "addr");
    println!("{}", "-".repeat(100));
    for h in handles {
        let Ok((ep, result)) = h.await else { continue };
        let (status, detail) = match result {
            Ok(d) => ("ok", format!("{:.0} ms (connect + query)", d.as_secs_f64() * 1000.0)),
            Err(e) => {
                failed += 1;
                ("FAIL", e)
            }
        };
        println!(
            "{:<6} {:<22} {:<4} {:<44} {}",
            status,
            truncate(&ep.resolver, 22),
            ep.transport.kind().label(),
            truncate(&ep.transport.display_addr(), 44),
            detail,
        );
    }
    println!("\n{} endpoints checked, {} failed, {} skipped", total, failed, skipped);
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

pub fn build_bench_config(args: &BenchArgs) -> Result<BenchConfig> {
    let cached = !args.no_cached;
    let uncached = !args.no_uncached;
    if !cached && !uncached {
        anyhow::bail!("both --no-cached and --no-uncached set — nothing to benchmark");
    }

    let mut domains = if args.only_custom { Vec::new() } else { default_domains() };
    if let Some(path) = &args.domains_file {
        let from_file = load_domains_file(path)
            .with_context(|| format!("reading {}", path.display()))?;
        domains.extend(from_file);
    }
    domains.extend(args.add_domains.iter().cloned());
    domains = dedup_preserve(domains);

    if domains.is_empty() {
        anyhow::bail!("no domains to test (use --add-domain or drop --only-custom)");
    }

    if let Some(p) = &args.export {
        if ExportFormat::from_path(p).is_none() {
            anyhow::bail!("--export path must end in .csv or .json ({})", p.display());
        }
    }

    let iterations = args.preset.map(Preset::iterations).unwrap_or(args.iterations);

    let transports = match &args.transports {
        None => Vec::new(),
        Some(s) if s.eq_ignore_ascii_case("all") => Vec::new(),
        Some(s) => {
            let mut kinds = Vec::new();
            for tok in s.split([',', ' ']) {
                if tok.is_empty() { continue; }
                match TransportKind::parse(tok) {
                    Some(k) if !kinds.contains(&k) => kinds.push(k),
                    Some(_) => {}
                    None => anyhow::bail!("unknown transport: {} (expected udp, dot, doh, doh3, doq, or all)", tok),
                }
            }
            kinds
        }
    };

    Ok(BenchConfig {
        domains,
        iterations,
        timeout: Duration::from_millis(args.timeout_ms),
        cached,
        uncached,
        include_ipv6: args.ipv6,
        all_addrs: args.all_addrs,
        transports,
        inter_query: Duration::from_millis(args.spacing_ms),
        max_concurrent: args.concurrency,
        warmup: !args.no_warmup,
        dnssec_check: !args.no_dnssec_check,
        privacy_check: !args.no_privacy_check,
        wildcard_domain: args.wildcard_domain.clone(),
        ..BenchConfig::default()
    })
}

async fn cmd_bench(args: BenchArgs) -> Result<()> {
    let export_path = args.export.clone();
    let cfg = build_bench_config(&args)?;

    let (resolvers, system) = load_resolvers(&args.resolvers)?;
    let endpoints_per_resolver = if cfg.include_ipv6 { "v4+v6" } else { "v4" };
    let classes = match (cfg.cached, cfg.uncached) {
        (true, true) => "cached + uncached",
        (true, false) => "cached only",
        (false, true) => "uncached only",
        _ => unreachable!(),
    };
    println!(
        "Benchmarking {} resolvers ({}), {} domains × {} iterations, classes: {}, timeout {:?}, spacing {:?}, {} at a time\n",
        resolvers.len(), endpoints_per_resolver, cfg.domains.len(),
        cfg.iterations, classes, cfg.timeout, cfg.inter_query,
        if cfg.max_concurrent == 0 { "all".to_string() } else { cfg.max_concurrent.to_string() },
    );
    println!("domains: {}", cfg.domains.join(", "));
    println!();

    // Nothing is printed until the run ends, so show progress on stderr when
    // someone is watching. Piped or redirected output stays clean.
    let show_progress = std::io::stderr().is_terminal();
    let started = std::time::Instant::now();
    let mut last_drawn = started;
    let reports = run_bench_with_progress(&resolvers, &cfg, |done, total| {
        if show_progress && (done == total || last_drawn.elapsed() >= Duration::from_millis(200)) {
            last_drawn = std::time::Instant::now();
            eprint!(
                "\r  {}/{} probes ({:.0}%) · {:.0}s elapsed ",
                done, total,
                done as f64 / total.max(1) as f64 * 100.0,
                started.elapsed().as_secs_f64(),
            );
            let _ = std::io::stderr().flush();
        }
    })
    .await;
    if show_progress {
        eprintln!();
        eprintln!();
    }
    print_results(&reports, &cfg, &system);

    if let Some(path) = export_path {
        let fmt = ExportFormat::from_path(&path).expect("validated earlier");
        export(&reports, &cfg, &path, fmt).with_context(|| format!("writing {}", path.display()))?;
        println!("\nExported {} rows to {}", reports.len(), path.display());
    }
    Ok(())
}

/// Cells for one query class: p50, p90, p99, reliability. Latencies are
/// blank when every query failed; p99 is blank below 100 samples.
pub(crate) fn class_cells(s: &Option<Summary>) -> [String; 4] {
    let ms = |d: Duration| format!("{:.1}", d.as_secs_f64() * 1000.0);
    let dash = || "—".to_string();
    match s {
        Some(s) if s.has_samples() => [
            ms(s.p50),
            ms(s.p90),
            s.p99_if_meaningful().map(ms).unwrap_or_else(dash),
            format!("{:.0}%", s.reliability() * 100.0),
        ],
        Some(s) => [dash(), dash(), dash(), format!("{:.0}%", s.reliability() * 100.0)],
        None => [dash(), dash(), dash(), dash()],
    }
}

pub(crate) fn dnssec_label(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "yes",
        Some(false) => "no",
        None => "?",
    }
}

/// Does the endpoint send a client subnet (EDNS Client Subnet) upstream?
pub(crate) fn ecs_label(p: &Option<PrivacyInfo>) -> &'static str {
    dnssec_label(p.as_ref().and_then(|p| p.ecs_sent))
}

fn print_bench_table(reports: &[EndpointReport], cached: bool, uncached: bool) {
    print!("{:<22} {:<4} {:<30} {:<13} {:<6} {:<3} {:>8} ", "resolver", "t", "addr", "filtering", "dnssec", "ecs", "setup");
    if cached { print!("{:>7} {:>7} {:>7} {:>5} ", "c_p50", "c_p90", "c_p99", "c_rel"); }
    if uncached { print!("{:>7} {:>7} {:>7} {:>5} ", "u_p50", "u_p90", "u_p99", "u_rel"); }
    println!();
    let base_width = 22 + 1 + 4 + 1 + 30 + 1 + 13 + 1 + 6 + 1 + 3 + 1 + 8 + 1;
    println!(
        "{}",
        "-".repeat(base_width + if cached { 30 } else { 0 } + if uncached { 30 } else { 0 })
    );

    for ep in reports {
        let setup = match ep.setup {
            Some(d) => format!("{:.1}", d.as_secs_f64() * 1000.0),
            None => "—".to_string(),
        };
        print!(
            "{:<22} {:<4} {:<30} {:<13} {:<6} {:<3} {:>8} ",
            truncate(&ep.resolver, 22),
            ep.transport_kind.label(),
            truncate(&ep.addr_display, 30),
            truncate(ep.filtering.as_deref().unwrap_or("-"), 13),
            dnssec_label(ep.dnssec),
            ecs_label(&ep.privacy),
            setup,
        );
        for (enabled, class) in [(cached, &ep.cached), (uncached, &ep.uncached)] {
            if enabled {
                let [a, b, c, r] = class_cells(class);
                print!("{:>7} {:>7} {:>7} {:>5} ", a, b, c, r);
            }
        }
        println!();
    }
    println!("\nlatencies in ms · setup = fresh connection + first answer · p99 needs 100+ samples");
    println!("ecs = sends a client subnet to the authoritative servers of the sites you look up");
}

pub(crate) fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push_str("..");
        out
    }
}
