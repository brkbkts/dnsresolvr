use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use dnsresolvr_core::{
    bundled_resolvers, dedup_preserve, default_domains, export, load_domains_file, probe_udp,
    run_bench, BenchConfig, EndpointReport, ExportFormat, RecordType, Summary,
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
    /// 5 iterations per domain — default
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
            Preset::Standard => 5,
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

#[derive(Subcommand)]
enum Cmd {
    /// Print the bundled resolver list.
    List,
    /// Probe every bundled resolver once for <host> over UDP/53 and print RTTs.
    Probe {
        host: String,
        #[arg(long, default_value_t = 1500)]
        timeout_ms: u64,
    },
    /// Launch the live ratatui TUI (same as running with no subcommand).
    Tui(BenchArgs),
    /// Headless benchmark: multi-domain, percentiles, cached + uncached. CI / scripting.
    Bench(BenchArgs),
}

#[derive(clap::Args, Debug, Clone)]
pub struct BenchArgs {
    /// Iterations per domain per class. Ignored if --preset is set.
    #[arg(long, default_value_t = 5)]
    iterations: usize,
    #[arg(long, value_enum)]
    preset: Option<Preset>,
    #[arg(long, default_value_t = 1500)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 25)]
    spacing_ms: u64,
    /// Skip the cached class (warm-cache probing).
    #[arg(long)]
    no_cached: bool,
    /// Skip the uncached class (random-subdomain, forces recursion).
    #[arg(long)]
    no_uncached: bool,
    #[arg(long)]
    ipv6: bool,
    #[arg(long = "add-domain", value_name = "DOMAIN")]
    add_domains: Vec<String>,
    #[arg(long, value_name = "PATH")]
    domains_file: Option<PathBuf>,
    #[arg(long)]
    only_custom: bool,
    #[arg(long, value_name = "PATH")]
    export: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        None => {
            let cfg = BenchConfig::default();
            tui::run(tui::TuiOpts { cfg, export_path: None }).await
        }
        Some(Cmd::List) => cmd_list(),
        Some(Cmd::Probe { host, timeout_ms }) => {
            cmd_probe(&host, Duration::from_millis(timeout_ms)).await
        }
        Some(Cmd::Tui(args)) => {
            let export_path = args.export.clone();
            let cfg = build_bench_config(&args)?;
            tui::run(tui::TuiOpts { cfg, export_path }).await
        }
        Some(Cmd::Bench(args)) => cmd_bench(args).await,
    }
}

fn cmd_list() -> Result<()> {
    let resolvers = bundled_resolvers();
    println!("{:<24} {:<14} {:<32} {}", "name", "provider", "ipv4", "ipv6");
    for r in &resolvers {
        let v4 = r.ipv4.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",");
        let v6 = r.ipv6.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",");
        println!("{:<24} {:<14} {:<32} {}", r.name, r.provider, v4, v6);
    }
    println!("\n{} resolvers", resolvers.len());
    Ok(())
}

async fn cmd_probe(host: &str, rtt_timeout: Duration) -> Result<()> {
    let resolvers = bundled_resolvers();
    println!(
        "Probing {} resolvers for {} (UDP/53, A, timeout={:?})\n",
        resolvers.len(), host, rtt_timeout
    );
    println!("{:<24} {:<16} {:>10}  {:<8} {}", "resolver", "addr", "rtt", "rcode", "answer");
    println!("{}", "-".repeat(90));

    let mut handles = Vec::new();
    for r in resolvers {
        if let Some(addr) = r.primary_addr() {
            let host = host.to_string();
            let name = r.name.clone();
            handles.push(tokio::spawn(async move {
                let res = probe_udp(addr, &host, RecordType::A, rtt_timeout).await;
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

    Ok(BenchConfig {
        domains,
        iterations,
        timeout: Duration::from_millis(args.timeout_ms),
        cached,
        uncached,
        include_ipv6: args.ipv6,
        inter_query: Duration::from_millis(args.spacing_ms),
    })
}

async fn cmd_bench(args: BenchArgs) -> Result<()> {
    let export_path = args.export.clone();
    let cfg = build_bench_config(&args)?;

    let resolvers = bundled_resolvers();
    let endpoints_per_resolver = if cfg.include_ipv6 { "v4+v6" } else { "v4" };
    let classes = match (cfg.cached, cfg.uncached) {
        (true, true) => "cached + uncached",
        (true, false) => "cached only",
        (false, true) => "uncached only",
        _ => unreachable!(),
    };
    println!(
        "Benchmarking {} resolvers ({}), {} domains × {} iterations, classes: {}, timeout {:?}, spacing {:?}\n",
        resolvers.len(), endpoints_per_resolver, cfg.domains.len(),
        cfg.iterations, classes, cfg.timeout, cfg.inter_query,
    );
    println!("domains: {}", cfg.domains.join(", "));
    println!();

    let reports = run_bench(&resolvers, &cfg).await;
    print_bench_table(&reports, cfg.cached, cfg.uncached);

    if let Some(path) = export_path {
        let fmt = ExportFormat::from_path(&path).expect("validated earlier");
        export(&reports, &path, fmt).with_context(|| format!("writing {}", path.display()))?;
        println!("\nExported {} rows to {}", reports.len(), path.display());
    }
    Ok(())
}

fn print_bench_table(reports: &[EndpointReport], cached: bool, uncached: bool) {
    let col = |s: &Option<Summary>| -> (String, String, String, String) {
        match s {
            Some(s) => (
                format!("{:.1}", s.p50.as_secs_f64() * 1000.0),
                format!("{:.1}", s.p95.as_secs_f64() * 1000.0),
                format!("{:.1}", s.p99.as_secs_f64() * 1000.0),
                format!("{:.0}%", s.reliability() * 100.0),
            ),
            None => ("—".into(), "—".into(), "—".into(), "—".into()),
        }
    };

    print!("{:<22} {:<16} ", "resolver", "addr");
    if cached { print!("{:>7} {:>7} {:>7} {:>5} ", "c_p50", "c_p95", "c_p99", "c_rel"); }
    if uncached { print!("{:>7} {:>7} {:>7} {:>5} ", "u_p50", "u_p95", "u_p99", "u_rel"); }
    println!();
    println!("{}", "-".repeat(22 + 1 + 16 + 1 + if cached { 31 } else { 0 } + if uncached { 31 } else { 0 }));

    for ep in reports {
        print!("{:<22} {:<16} ", truncate(&ep.resolver, 22), ep.addr.to_string());
        if cached {
            let (a, b, c, r) = col(&ep.cached);
            print!("{:>6}ms {:>6}ms {:>6}ms {:>5} ", a, b, c, r);
        }
        if uncached {
            let (a, b, c, r) = col(&ep.uncached);
            print!("{:>6}ms {:>6}ms {:>6}ms {:>5} ", a, b, c, r);
        }
        println!();
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push_str("..");
        out
    }
}
