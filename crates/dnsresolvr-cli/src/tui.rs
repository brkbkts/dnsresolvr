//! Live ratatui frontend with vim-style command mode.

use std::io;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event as CtEvent, EventStream, KeyCode, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use dnsresolvr_core::{
    bundled_resolvers, default_domains, export, run_bench_streaming, summarize, BenchConfig,
    BenchEvent, Class, EndpointReport, ExportFormat, FailKind, ProbeResult, Resolver, Summary,
};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Gauge, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{Frame, Terminal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::Preset;

pub struct TuiOpts {
    pub cfg: BenchConfig,
    pub export_path: Option<PathBuf>,
}

pub async fn run(opts: TuiOpts) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, opts).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    res
}

// --- sort / mode ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey { CachedP50, UncachedP50, Reliability, Name }

impl SortKey {
    fn next(self) -> Self {
        match self {
            SortKey::CachedP50 => SortKey::UncachedP50,
            SortKey::UncachedP50 => SortKey::Reliability,
            SortKey::Reliability => SortKey::Name,
            SortKey::Name => SortKey::CachedP50,
        }
    }
    fn label(self) -> &'static str {
        match self {
            SortKey::CachedP50 => "cached p50",
            SortKey::UncachedP50 => "uncached p50",
            SortKey::Reliability => "reliability",
            SortKey::Name => "name",
        }
    }
}

#[derive(Debug, Clone)]
enum Mode {
    Normal,
    Command { input: String },
    Help,
}

// --- per-endpoint state ---

#[derive(Default, Debug, Clone)]
struct FailCounts { timeout: usize, network: usize, protocol: usize }

impl FailCounts {
    fn total(&self) -> usize { self.timeout + self.network + self.protocol }
    fn bump(&mut self, k: FailKind) {
        match k {
            FailKind::Timeout => self.timeout += 1,
            FailKind::Network => self.network += 1,
            FailKind::Protocol => self.protocol += 1,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct DomainStats { rtts: Vec<Duration>, fails: FailCounts }

impl DomainStats {
    fn total(&self) -> usize { self.rtts.len() + self.fails.total() }
    fn mean_ms(&self) -> Option<f64> {
        if self.rtts.is_empty() { return None; }
        let sum: f64 = self.rtts.iter().map(|d| d.as_secs_f64()).sum();
        Some(sum / self.rtts.len() as f64 * 1000.0)
    }
}

struct EndpointState {
    name: String,
    provider: String,
    addr: IpAddr,
    cached: Vec<DomainStats>,
    uncached: Vec<DomainStats>,
    total_per_class: usize,
    done: bool,
}

impl EndpointState {
    fn cached_summary(&self) -> Option<Summary> { Self::summarize_class(&self.cached) }
    fn uncached_summary(&self) -> Option<Summary> { Self::summarize_class(&self.uncached) }
    fn summarize_class(per_domain: &[DomainStats]) -> Option<Summary> {
        let mut rtts = Vec::new();
        let mut total = 0usize;
        for d in per_domain {
            rtts.extend(d.rtts.iter().copied());
            total += d.total();
        }
        if total == 0 { return None; }
        summarize(rtts, total)
    }
    fn combined_reliability(&self) -> Option<f64> {
        let s = self.cached_summary();
        let c = self.uncached_summary();
        match (s, c) {
            (None, None) => None,
            (Some(a), None) | (None, Some(a)) => Some(a.reliability()),
            (Some(a), Some(b)) => {
                let total = a.total + b.total;
                if total == 0 { None } else { Some((a.successes + b.successes) as f64 / total as f64) }
            }
        }
    }
    fn progress(&self, cached_enabled: bool, uncached_enabled: bool) -> (usize, usize) {
        let total = self.total_per_class * (cached_enabled as usize + uncached_enabled as usize);
        let done: usize = self.cached.iter().map(|d| d.total()).sum::<usize>()
            + self.uncached.iter().map(|d| d.total()).sum::<usize>();
        (done, total)
    }
    fn fails(&self) -> FailCounts {
        let mut f = FailCounts::default();
        for d in self.cached.iter().chain(self.uncached.iter()) {
            f.timeout += d.fails.timeout;
            f.network += d.fails.network;
            f.protocol += d.fails.protocol;
        }
        f
    }
    fn to_report(&self) -> EndpointReport {
        EndpointReport {
            resolver: self.name.clone(),
            provider: self.provider.clone(),
            addr: self.addr,
            cached: self.cached_summary(),
            uncached: self.uncached_summary(),
        }
    }
}

// --- app state ---

struct StatusMsg { text: String, color: Color, shown_since: Instant }

struct App {
    resolvers: Vec<Resolver>,
    cfg: BenchConfig,
    endpoints: Vec<EndpointState>,
    sort: SortKey,
    started: Instant,
    finished: bool,
    table_state: TableState,
    detail_open: bool,
    last_sorted: Vec<usize>,
    mode: Mode,
    status: Option<StatusMsg>,
    export_path: Option<PathBuf>,
}

impl App {
    fn apply(&mut self, ev: BenchEvent) {
        match ev {
            BenchEvent::Start { id, resolver, provider, addr, total_per_class } => {
                if self.endpoints.len() <= id {
                    let n_domains = self.cfg.domains.len();
                    self.endpoints.resize_with(id + 1, || EndpointState {
                        name: String::new(),
                        provider: String::new(),
                        addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        cached: vec![DomainStats::default(); n_domains],
                        uncached: vec![DomainStats::default(); n_domains],
                        total_per_class: 0,
                        done: false,
                    });
                }
                let e = &mut self.endpoints[id];
                e.name = resolver;
                e.provider = provider;
                e.addr = addr;
                e.total_per_class = total_per_class;
            }
            BenchEvent::Probe { id, class, domain_idx, result } => {
                if let Some(e) = self.endpoints.get_mut(id) {
                    let bucket = match class {
                        Class::Cached => &mut e.cached,
                        Class::Uncached => &mut e.uncached,
                    };
                    if let Some(slot) = bucket.get_mut(domain_idx as usize) {
                        match result {
                            ProbeResult::Ok(rtt) => slot.rtts.push(rtt),
                            ProbeResult::Fail(k) => slot.fails.bump(k),
                        }
                    }
                }
            }
            BenchEvent::Done { id } => {
                if let Some(e) = self.endpoints.get_mut(id) { e.done = true; }
            }
            BenchEvent::AllDone => self.finished = true,
        }
    }

    fn sorted_indices(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.endpoints.len()).collect();
        idx.sort_by(|&a, &b| {
            let ea = &self.endpoints[a];
            let eb = &self.endpoints[b];
            match self.sort {
                SortKey::Name => ea.name.cmp(&eb.name),
                SortKey::CachedP50 => key_p50(ea.cached_summary()).cmp(&key_p50(eb.cached_summary())),
                SortKey::UncachedP50 => key_p50(ea.uncached_summary()).cmp(&key_p50(eb.uncached_summary())),
                SortKey::Reliability => {
                    ((eb.combined_reliability().unwrap_or(-1.0) * 1e9) as i64)
                        .cmp(&((ea.combined_reliability().unwrap_or(-1.0) * 1e9) as i64))
                }
            }
        });
        idx
    }

    fn total_progress(&self) -> (usize, usize) {
        let per_endpoint = self.cfg.domains.len() * self.cfg.iterations
            * (self.cfg.cached as usize + self.cfg.uncached as usize);
        let total = per_endpoint * self.endpoints.len();
        let done: usize = self.endpoints.iter()
            .map(|e| e.cached.iter().map(|d| d.total()).sum::<usize>()
                + e.uncached.iter().map(|d| d.total()).sum::<usize>())
            .sum();
        (done, total)
    }

    fn selected_endpoint(&self) -> Option<&EndpointState> {
        let sel = self.table_state.selected()?;
        let i = *self.last_sorted.get(sel)?;
        self.endpoints.get(i)
    }

    fn move_selection(&mut self, delta: i32) {
        let len = self.last_sorted.len();
        if len == 0 { return; }
        let cur = self.table_state.selected().unwrap_or(0) as i32;
        let mut next = cur + delta;
        if next < 0 { next = 0; }
        if next >= len as i32 { next = len as i32 - 1; }
        self.table_state.select(Some(next as usize));
    }

    fn set_status(&mut self, text: impl Into<String>, color: Color) {
        self.status = Some(StatusMsg {
            text: text.into(),
            color,
            shown_since: Instant::now(),
        });
    }
}

fn key_p50(s: Option<Summary>) -> u64 {
    s.map(|s| s.p50.as_micros() as u64).unwrap_or(u64::MAX)
}

// --- bench lifecycle ---

struct BenchProc {
    rx: mpsc::UnboundedReceiver<BenchEvent>,
    handle: JoinHandle<()>,
}

fn spawn_bench(resolvers: Vec<Resolver>, cfg: BenchConfig) -> BenchProc {
    let (tx, rx) = mpsc::unbounded_channel::<BenchEvent>();
    let handle = tokio::spawn(async move {
        run_bench_streaming(resolvers, cfg, tx).await;
    });
    BenchProc { rx, handle }
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    opts: TuiOpts,
) -> Result<()> {
    let TuiOpts { cfg, export_path } = opts;
    let resolvers = bundled_resolvers();
    let mut app = App {
        resolvers: resolvers.clone(),
        cfg,
        endpoints: Vec::new(),
        sort: SortKey::CachedP50,
        started: Instant::now(),
        finished: false,
        table_state: {
            let mut ts = TableState::default();
            ts.select(Some(0));
            ts
        },
        detail_open: false,
        last_sorted: Vec::new(),
        mode: Mode::Normal,
        status: None,
        export_path,
    };

    let mut bench = Some(spawn_bench(resolvers, app.cfg.clone()));
    let mut key_events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(120));

    loop {
        // clear stale status after 4 seconds
        if let Some(s) = &app.status {
            if s.shown_since.elapsed() > Duration::from_secs(4) { app.status = None; }
        }
        app.last_sorted = app.sorted_indices();
        terminal.draw(|f| draw(f, &mut app))?;

        tokio::select! {
            maybe_ev = async {
                match bench.as_mut() {
                    Some(b) => b.rx.recv().await,
                    None => std::future::pending::<Option<BenchEvent>>().await,
                }
            } => {
                match maybe_ev {
                    Some(ev) => app.apply(ev),
                    None => bench = None,
                }
            }
            maybe_key = key_events.next() => {
                let Some(Ok(CtEvent::Key(k))) = maybe_key else { continue; };
                if k.kind == KeyEventKind::Release { continue; }

                match &mut app.mode {
                    Mode::Normal => {
                        match k.code {
                            KeyCode::Char(':') => app.mode = Mode::Command { input: String::new() },
                            KeyCode::Char('q') if k.modifiers == KeyModifiers::NONE => {
                                maybe_export(&app, &app.export_path.clone());
                                return Ok(());
                            }
                            KeyCode::Esc => { app.detail_open = false; }
                            KeyCode::Char('s') => app.sort = app.sort.next(),
                            KeyCode::Enter => app.detail_open = !app.detail_open,
                            KeyCode::Up => app.move_selection(-1),
                            KeyCode::Down => app.move_selection(1),
                            KeyCode::PageUp => app.move_selection(-10),
                            KeyCode::PageDown => app.move_selection(10),
                            KeyCode::Char('r') => {
                                bench = Some(restart(&mut app, bench.take()));
                            }
                            KeyCode::Char('?') => app.mode = Mode::Help,
                            _ => {}
                        }
                    }
                    Mode::Command { input } => {
                        match k.code {
                            KeyCode::Esc => app.mode = Mode::Normal,
                            KeyCode::Enter => {
                                let cmd = std::mem::take(input);
                                app.mode = Mode::Normal;
                                match execute_command(&mut app, &cmd, bench.take()) {
                                    CommandResult::Continue(b) => bench = b,
                                    CommandResult::Quit => {
                                        maybe_export(&app, &app.export_path.clone());
                                        return Ok(());
                                    }
                                }
                            }
                            KeyCode::Backspace => { input.pop(); }
                            KeyCode::Char(c) => input.push(c),
                            _ => {}
                        }
                    }
                    Mode::Help => {
                        if matches!(k.code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') | KeyCode::Enter) {
                            app.mode = Mode::Normal;
                        }
                    }
                }
            }
            _ = tick.tick() => {}
        }
    }
}

// --- command execution ---

enum CommandResult {
    Continue(Option<BenchProc>),
    Quit,
}

fn execute_command(app: &mut App, cmd: &str, bench: Option<BenchProc>) -> CommandResult {
    let cmd = cmd.trim();
    if cmd.is_empty() { return CommandResult::Continue(bench); }

    let mut parts = cmd.split_whitespace();
    let head = parts.next().unwrap_or("");
    let rest: Vec<&str> = parts.collect();

    match head {
        "q" | "quit" | "exit" => return CommandResult::Quit,
        "w" | "write" | "export" => {
            write_export(app, rest.first().copied());
            CommandResult::Continue(bench)
        }
        "wq" => {
            write_export(app, rest.first().copied());
            return CommandResult::Quit;
        }
        "r" | "run" | "start" | "restart" => {
            CommandResult::Continue(Some(restart(app, bench)))
        }
        "stop" | "abort" => {
            if let Some(b) = bench { b.handle.abort(); }
            app.finished = true;
            app.set_status("bench stopped", Color::Yellow);
            CommandResult::Continue(None)
        }
        "set" => {
            apply_set(app, &rest);
            CommandResult::Continue(bench)
        }
        "cached" => { apply_set(app, &["cached", rest.first().copied().unwrap_or("toggle")]); CommandResult::Continue(bench) }
        "uncached" => { apply_set(app, &["uncached", rest.first().copied().unwrap_or("toggle")]); CommandResult::Continue(bench) }
        "ipv6" => { apply_set(app, &["ipv6", rest.first().copied().unwrap_or("toggle")]); CommandResult::Continue(bench) }
        "add" => {
            for d in &rest {
                if !app.cfg.domains.iter().any(|x| x.eq_ignore_ascii_case(d)) {
                    app.cfg.domains.push(d.to_string());
                }
            }
            app.set_status(format!("domains: {} (config changed — :r to apply)", app.cfg.domains.len()), Color::Cyan);
            CommandResult::Continue(bench)
        }
        "rm" | "del" | "remove" => {
            let before = app.cfg.domains.len();
            app.cfg.domains.retain(|d| !rest.iter().any(|r| r.eq_ignore_ascii_case(d)));
            let removed = before - app.cfg.domains.len();
            app.set_status(format!("removed {} (config changed — :r to apply)", removed), Color::Cyan);
            CommandResult::Continue(bench)
        }
        "reset" => {
            app.cfg.domains = default_domains();
            app.set_status(format!("domains reset to default ({})", app.cfg.domains.len()), Color::Cyan);
            CommandResult::Continue(bench)
        }
        "domains" => {
            app.set_status(format!("{}", app.cfg.domains.join(", ")), Color::White);
            CommandResult::Continue(bench)
        }
        "help" | "?" => { app.mode = Mode::Help; CommandResult::Continue(bench) }
        other => {
            app.set_status(format!("unknown command: {}", other), Color::Red);
            CommandResult::Continue(bench)
        }
    }
}

fn apply_set(app: &mut App, args: &[&str]) {
    if args.is_empty() {
        app.set_status("usage: :set <key> <value>", Color::Red);
        return;
    }
    let key = args[0].to_ascii_lowercase();
    let val = args.get(1).copied().unwrap_or("");

    let parse_bool = |v: &str, current: bool| -> Option<bool> {
        match v.to_ascii_lowercase().as_str() {
            "on" | "true" | "1" | "yes" => Some(true),
            "off" | "false" | "0" | "no" => Some(false),
            "toggle" | "" => Some(!current),
            _ => None,
        }
    };

    match key.as_str() {
        "iter" | "iterations" => {
            match val.parse::<usize>() {
                Ok(n) if n > 0 => { app.cfg.iterations = n; app.set_status(format!("iterations = {} (:r to apply)", n), Color::Cyan); }
                _ => app.set_status("iter: expected positive integer", Color::Red),
            }
        }
        "sp" | "spacing" | "spacing_ms" => {
            match val.parse::<u64>() {
                Ok(n) => { app.cfg.inter_query = Duration::from_millis(n); app.set_status(format!("spacing = {}ms (:r to apply)", n), Color::Cyan); }
                _ => app.set_status("spacing: expected non-negative integer (ms)", Color::Red),
            }
        }
        "to" | "timeout" | "timeout_ms" => {
            match val.parse::<u64>() {
                Ok(n) if n > 0 => { app.cfg.timeout = Duration::from_millis(n); app.set_status(format!("timeout = {}ms (:r to apply)", n), Color::Cyan); }
                _ => app.set_status("timeout: expected positive integer (ms)", Color::Red),
            }
        }
        "preset" => {
            match Preset::parse_name(val) {
                Some(p) => { app.cfg.iterations = p.iterations(); app.set_status(format!("preset {} -> iterations = {} (:r to apply)", val, p.iterations()), Color::Cyan); }
                None => app.set_status("preset: quick | standard | thorough | exhaustive", Color::Red),
            }
        }
        "ipv6" => {
            match parse_bool(val, app.cfg.include_ipv6) {
                Some(v) => { app.cfg.include_ipv6 = v; app.set_status(format!("ipv6 = {} (:r to apply)", v), Color::Cyan); }
                None => app.set_status("ipv6: on | off | toggle", Color::Red),
            }
        }
        "cached" | "warm" => {
            match parse_bool(val, app.cfg.cached) {
                Some(v) => {
                    if !v && !app.cfg.uncached { app.set_status("cannot disable cached while uncached is off", Color::Red); return; }
                    app.cfg.cached = v;
                    app.set_status(format!("cached = {} (:r to apply)", v), Color::Cyan);
                }
                None => app.set_status("cached: on | off | toggle", Color::Red),
            }
        }
        "uncached" | "cold" => {
            match parse_bool(val, app.cfg.uncached) {
                Some(v) => {
                    if !v && !app.cfg.cached { app.set_status("cannot disable uncached while cached is off", Color::Red); return; }
                    app.cfg.uncached = v;
                    app.set_status(format!("uncached = {} (:r to apply)", v), Color::Cyan);
                }
                None => app.set_status("uncached: on | off | toggle", Color::Red),
            }
        }
        _ => app.set_status(format!("unknown setting: {}", key), Color::Red),
    }
}

fn restart(app: &mut App, old: Option<BenchProc>) -> BenchProc {
    if let Some(b) = old { b.handle.abort(); }
    app.endpoints.clear();
    app.finished = false;
    app.started = Instant::now();
    app.table_state.select(Some(0));
    app.set_status("benchmark restarted", Color::Green);
    spawn_bench(app.resolvers.clone(), app.cfg.clone())
}

fn write_export(app: &mut App, arg: Option<&str>) {
    let path: PathBuf = match arg {
        Some(s) => PathBuf::from(s),
        None => match &app.export_path {
            Some(p) => p.clone(),
            None => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                PathBuf::from(format!("dnsresolvr-{}.csv", ts))
            }
        },
    };
    let Some(fmt) = ExportFormat::from_path(&path) else {
        app.set_status(format!("export: path must end in .csv or .json ({})", path.display()), Color::Red);
        return;
    };
    let reports: Vec<EndpointReport> = app.endpoints.iter().map(|e| e.to_report()).collect();
    match export(&reports, &path, fmt) {
        Ok(()) => {
            app.export_path = Some(path.clone());
            app.set_status(format!("exported {} rows to {}", reports.len(), path.display()), Color::Green);
        }
        Err(e) => app.set_status(format!("export failed: {}", e), Color::Red),
    }
}

fn maybe_export(app: &App, path: &Option<PathBuf>) {
    let Some(path) = path else { return; };
    let Some(fmt) = ExportFormat::from_path(path) else { return; };
    let reports: Vec<EndpointReport> = app.endpoints.iter().map(|e| e.to_report()).collect();
    let _ = export(&reports, path, fmt);
}

// --- drawing ---

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header/gauge
            Constraint::Min(5),    // table or detail
            Constraint::Length(1), // config summary (status line)
            Constraint::Length(3), // command/controls
        ])
        .split(f.area());

    draw_header(f, chunks[0], app);
    if app.detail_open { draw_detail(f, chunks[1], app); } else { draw_table(f, chunks[1], app); }
    draw_status_line(f, chunks[2], app);
    draw_footer(f, chunks[3], app);

    if matches!(app.mode, Mode::Help) { draw_help_overlay(f, app); }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let (done, total) = app.total_progress();
    let ratio = if total == 0 { 0.0 } else { done as f64 / total as f64 };
    let elapsed = app.started.elapsed();
    let title = format!(
        " dnsresolvr  {} endpoints · {} domains × {} iters · elapsed {:.1}s{} ",
        app.endpoints.len(), app.cfg.domains.len(), app.cfg.iterations,
        elapsed.as_secs_f64(),
        if app.finished { " · DONE" } else { "" },
    );
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(title))
        .gauge_style(Style::default().fg(if app.finished { Color::Green } else { Color::Cyan }))
        .ratio(ratio.clamp(0.0, 1.0))
        .label(format!("{}/{} probes ({:.0}%)", done, total, ratio * 100.0));
    f.render_widget(gauge, area);
}

fn draw_status_line(f: &mut Frame, area: Rect, app: &App) {
    let cfg = &app.cfg;
    let classes = match (cfg.cached, cfg.uncached) {
        (true, true) => "cached+uncached",
        (true, false) => "cached-only",
        (false, true) => "uncached-only",
        _ => "none",
    };
    let stack = if cfg.include_ipv6 { "v4+v6" } else { "v4" };
    let base = Line::from(vec![
        Span::styled(" cfg ", Style::default().bg(Color::DarkGray).fg(Color::White)),
        Span::raw(format!(
            "  iter:{} sp:{}ms to:{}ms {} {} domains:{} sort:{}",
            cfg.iterations,
            cfg.inter_query.as_millis(),
            cfg.timeout.as_millis(),
            classes, stack, cfg.domains.len(),
            app.sort.label(),
        )),
    ]);

    if let Some(s) = &app.status {
        let combined = Line::from(vec![
            Span::styled(" cfg ", Style::default().bg(Color::DarkGray).fg(Color::White)),
            Span::raw(format!(
                "  iter:{} sp:{}ms to:{}ms {} {} domains:{}  ·  ",
                cfg.iterations, cfg.inter_query.as_millis(), cfg.timeout.as_millis(),
                classes, stack, cfg.domains.len(),
            )),
            Span::styled(s.text.clone(), Style::default().fg(s.color).add_modifier(Modifier::BOLD)),
        ]);
        f.render_widget(Paragraph::new(combined), area);
    } else {
        f.render_widget(Paragraph::new(base), area);
    }
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    match &app.mode {
        Mode::Command { input } => {
            let line = Line::from(vec![
                Span::styled(":", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(input.clone()),
                Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            ]);
            f.render_widget(
                Paragraph::new(line).block(Block::default().borders(Borders::ALL).title(" command ")),
                area,
            );
        }
        _ => {
            let line = if app.detail_open {
                Line::from(vec![
                    Span::styled("[Esc]", Style::default().fg(Color::Cyan)), Span::raw(" back  "),
                    Span::styled("[↑/↓]", Style::default().fg(Color::Cyan)), Span::raw(" endpoint  "),
                    Span::styled("[:]", Style::default().fg(Color::Cyan)), Span::raw(" command  "),
                    Span::styled("[q]", Style::default().fg(Color::Cyan)), Span::raw(" quit"),
                ])
            } else {
                Line::from(vec![
                    Span::styled("[:]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw(" command  "),
                    Span::styled("[Enter]", Style::default().fg(Color::Cyan)), Span::raw(" detail  "),
                    Span::styled("[s]", Style::default().fg(Color::Cyan)), Span::raw(" sort  "),
                    Span::styled("[r]", Style::default().fg(Color::Cyan)), Span::raw(" restart  "),
                    Span::styled("[?]", Style::default().fg(Color::Cyan)), Span::raw(" help  "),
                    Span::styled("[q]", Style::default().fg(Color::Cyan)), Span::raw(" quit"),
                ])
            };
            f.render_widget(
                Paragraph::new(line).block(Block::default().borders(Borders::ALL).title(" controls ")),
                area,
            );
        }
    }
}

fn draw_table(f: &mut Frame, area: Rect, app: &mut App) {
    let mut header_cells = vec![
        Cell::from("resolver").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("addr").style(Style::default().add_modifier(Modifier::BOLD)),
    ];
    let mut widths: Vec<Constraint> = vec![Constraint::Length(22), Constraint::Length(20)];
    if app.cfg.cached {
        for h in ["c_p50", "c_p95", "c_p99", "c_rel"] {
            header_cells.push(Cell::from(h).style(Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)));
            widths.push(Constraint::Length(8));
        }
    }
    if app.cfg.uncached {
        for h in ["u_p50", "u_p95", "u_p99", "u_rel"] {
            header_cells.push(Cell::from(h).style(Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD)));
            widths.push(Constraint::Length(8));
        }
    }
    header_cells.push(Cell::from("progress").style(Style::default().add_modifier(Modifier::BOLD)));
    widths.push(Constraint::Min(16));

    let mut rows: Vec<Row> = Vec::new();
    for &i in &app.last_sorted {
        let e = &app.endpoints[i];
        let mut cells = vec![
            Cell::from(truncate(&e.name, 22)),
            Cell::from(e.addr.to_string()),
        ];
        if app.cfg.cached {
            push_summary_cells(&mut cells, e.cached_summary(), Color::LightGreen);
        }
        if app.cfg.uncached {
            push_summary_cells(&mut cells, e.uncached_summary(), Color::LightMagenta);
        }
        let (d, t) = e.progress(app.cfg.cached, app.cfg.uncached);
        cells.push(Cell::from(progress_bar(d, t, e.done)));
        rows.push(Row::new(cells));
    }

    if let Some(sel) = app.table_state.selected() {
        if sel >= app.last_sorted.len() && !app.last_sorted.is_empty() {
            app.table_state.select(Some(app.last_sorted.len() - 1));
        }
    }

    let table = Table::new(rows, widths)
        .header(Row::new(header_cells).bottom_margin(1))
        .block(Block::default().borders(Borders::ALL).title(format!(" results — sorted by {} ", app.sort.label())))
        .column_spacing(1)
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn push_summary_cells(cells: &mut Vec<Cell>, s: Option<Summary>, color: Color) {
    match s {
        Some(s) => {
            cells.push(Cell::from(fmt_ms(s.p50)).style(Style::default().fg(color)));
            cells.push(Cell::from(fmt_ms(s.p95)));
            cells.push(Cell::from(fmt_ms(s.p99)));
            let rel = s.reliability();
            let style = if rel < 0.80 { Style::default().fg(Color::Red) }
                else if rel < 0.98 { Style::default().fg(Color::Yellow) }
                else { Style::default().fg(Color::Green) };
            cells.push(Cell::from(format!("{:>4.0}%", rel * 100.0)).style(style));
        }
        None => for _ in 0..4 {
            cells.push(Cell::from("—").style(Style::default().fg(Color::DarkGray)));
        },
    }
}

fn draw_detail(f: &mut Frame, area: Rect, app: &App) {
    let Some(ep) = app.selected_endpoint() else {
        let p = Paragraph::new("no endpoint selected")
            .block(Block::default().borders(Borders::ALL).title(" detail "));
        f.render_widget(p, area);
        return;
    };

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(5), Constraint::Length(3)])
        .split(area);

    let cached = ep.cached_summary();
    let uncached = ep.uncached_summary();
    let summary_lines = vec![
        Line::from(vec![
            Span::styled(format!("{} ", ep.name), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(format!("({}) ", ep.provider), Style::default().fg(Color::DarkGray)),
            Span::raw(ep.addr.to_string()),
        ]),
        class_line("cached", &cached, Color::LightGreen),
        class_line("uncached", &uncached, Color::LightMagenta),
    ];
    f.render_widget(
        Paragraph::new(summary_lines).block(Block::default().borders(Borders::ALL).title(" selected endpoint ")),
        inner[0],
    );

    let header = Row::new(vec![
        Cell::from("domain").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("cached mean").style(Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
        Cell::from("cached n/tot").style(Style::default().fg(Color::LightGreen)),
        Cell::from("uncached mean").style(Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD)),
        Cell::from("uncached n/tot").style(Style::default().fg(Color::LightMagenta)),
    ]).bottom_margin(1);

    let mut rows: Vec<Row> = Vec::new();
    for (i, dom) in app.cfg.domains.iter().enumerate() {
        let w = ep.cached.get(i).cloned().unwrap_or_default();
        let c = ep.uncached.get(i).cloned().unwrap_or_default();
        rows.push(Row::new(vec![
            Cell::from(dom.clone()),
            Cell::from(fmt_opt_ms(w.mean_ms())).style(Style::default().fg(Color::LightGreen)),
            Cell::from(format!("{}/{}", w.rtts.len(), w.total())),
            Cell::from(fmt_opt_ms(c.mean_ms())).style(Style::default().fg(Color::LightMagenta)),
            Cell::from(format!("{}/{}", c.rtts.len(), c.total())),
        ]));
    }
    let widths = [
        Constraint::Min(22), Constraint::Length(12), Constraint::Length(12),
        Constraint::Length(14), Constraint::Length(14),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" per-domain (mean RTT · successes/total) "))
        .column_spacing(1);
    f.render_widget(table, inner[1]);

    let f_counts = ep.fails();
    let err_line = Line::from(vec![
        Span::raw("errors: "),
        Span::styled(format!("{} timeout", f_counts.timeout), Style::default().fg(if f_counts.timeout > 0 { Color::Red } else { Color::DarkGray })),
        Span::raw("  "),
        Span::styled(format!("{} network", f_counts.network), Style::default().fg(if f_counts.network > 0 { Color::Red } else { Color::DarkGray })),
        Span::raw("  "),
        Span::styled(format!("{} protocol", f_counts.protocol), Style::default().fg(if f_counts.protocol > 0 { Color::Red } else { Color::DarkGray })),
    ]);
    f.render_widget(
        Paragraph::new(err_line).block(Block::default().borders(Borders::ALL).title(" errors ")),
        inner[2],
    );
}

fn class_line(label: &str, s: &Option<Summary>, color: Color) -> Line<'static> {
    match s {
        Some(s) => Line::from(vec![
            Span::styled(format!("{:<8}", label), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::raw(format!(
                " p50 {:>6.1}ms  p95 {:>6.1}ms  p99 {:>6.1}ms  min {:>6.1}ms  max {:>6.1}ms  stddev {:>5.1}ms  rel {:>3.0}%  ({}/{})",
                s.p50.as_secs_f64() * 1000.0, s.p95.as_secs_f64() * 1000.0, s.p99.as_secs_f64() * 1000.0,
                s.min.as_secs_f64() * 1000.0, s.max.as_secs_f64() * 1000.0,
                s.stddev.as_secs_f64() * 1000.0, s.reliability() * 100.0, s.successes, s.total,
            )),
        ]),
        None => Line::from(vec![
            Span::styled(format!("{:<8}", label), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(" no data yet", Style::default().fg(Color::DarkGray)),
        ]),
    }
}

fn draw_help_overlay(f: &mut Frame, _app: &App) {
    let area = centered_rect(72, 80, f.area());
    f.render_widget(Clear, area);

    let text = vec![
        Line::from(Span::styled("dnsresolvr — help", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::styled("Normal mode", Style::default().add_modifier(Modifier::BOLD))),
        Line::from("  :         enter command mode"),
        Line::from("  Enter     open / close detail pane"),
        Line::from("  s         cycle sort column"),
        Line::from("  r         restart benchmark with current config"),
        Line::from("  ↑/↓       move selection"),
        Line::from("  PgUp/Dn   move 10 rows"),
        Line::from("  ?         this help"),
        Line::from("  q         quit (auto-export if path set)"),
        Line::from(""),
        Line::from(Span::styled("Commands (typed after `:`)", Style::default().add_modifier(Modifier::BOLD))),
        Line::from("  :q   :quit                 exit"),
        Line::from("  :w [path]                  export to CSV/JSON (by extension)"),
        Line::from("  :wq [path]                 export, then quit"),
        Line::from("  :r   :start   :restart     rerun benchmark"),
        Line::from("  :stop                      abort running benchmark"),
        Line::from("  :set iter <N>              sample iterations per domain"),
        Line::from("  :set sp <ms>               spacing between queries"),
        Line::from("  :set to <ms>               per-query timeout"),
        Line::from("  :set preset <q|s|t|e>      quick | standard | thorough | exhaustive"),
        Line::from("  :set ipv6 on|off|toggle    include IPv6 endpoints"),
        Line::from("  :set cached on|off         include cached class (alias :cached)"),
        Line::from("  :set uncached on|off       include uncached class (alias :uncached)"),
        Line::from("  :add <domain> [..]         add domains to probe set"),
        Line::from("  :rm  <domain> [..]         remove domains"),
        Line::from("  :reset                     restore default domain list"),
        Line::from("  :domains                   show current domain list"),
        Line::from(""),
        Line::from(Span::styled("Config changes take effect on the next :r", Style::default().fg(Color::DarkGray))),
        Line::from(""),
        Line::from(Span::styled("Esc to close this help", Style::default().fg(Color::Yellow))),
    ];
    let p = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title(" help "));
    f.render_widget(p, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(v[1])[1]
}

fn fmt_ms(d: Duration) -> String {
    format!("{:>6.1}", d.as_secs_f64() * 1000.0)
}

fn fmt_opt_ms(ms: Option<f64>) -> String {
    match ms {
        Some(v) => format!("{:>7.1}ms", v),
        None => "       —".to_string(),
    }
}

fn progress_bar(done: usize, total: usize, finished: bool) -> String {
    if total == 0 { return String::new(); }
    let width = 14;
    let filled = ((done as f64 / total as f64) * width as f64).round() as usize;
    let filled = filled.min(width);
    let mut s = String::with_capacity(width + 8);
    s.push_str(&"█".repeat(filled));
    s.push_str(&"░".repeat(width - filled));
    if finished { s.push_str(" done"); } else { s.push_str(&format!(" {}/{}", done, total)); }
    s
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n { s.to_string() }
    else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push_str(".."); out
    }
}
