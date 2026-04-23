//! Benchmark orchestrator. Runs probe batches per endpoint, per query class.
//!
//! An *endpoint* is a single (resolver, transport) pair. One resolver can
//! produce up to six endpoints: UDP+DoT+DoH on IPv4, plus the same on IPv6.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::rr::RecordType;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::probe::ProbeError;
use crate::resolver::Resolver;
use crate::stats::{summarize, Summary};
use crate::transport::{probe, Transport, TransportKind};

/// Cheap xorshift RNG seeded per call from wall-clock nanos + a global counter.
/// Good enough for jitter and shuffle — not cryptographic.
fn rng_next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn rng_seed() -> u64 {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(1) as u64;
    let c = COLD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let s = n ^ c.rotate_left(21);
    if s == 0 { 0x9E3779B97F4A7C15 } else { s }
}

fn jitter(base: Duration, state: &mut u64, pct: f64) -> Duration {
    if base.is_zero() || pct <= 0.0 {
        return base;
    }
    let r = rng_next(state);
    let signed = (r as f64 / u64::MAX as f64) * 2.0 - 1.0;
    let factor = 1.0 + signed * pct;
    let nanos = (base.as_nanos() as f64 * factor.max(0.0)) as u64;
    Duration::from_nanos(nanos)
}

fn shuffle<T>(v: &mut [T], state: &mut u64) {
    for i in (1..v.len()).rev() {
        let j = (rng_next(state) as usize) % (i + 1);
        v.swap(i, j);
    }
}

/// Adaptive backoff for a single endpoint. Doubles on timeout/network errors,
/// decays toward 1.0 on success. Capped so we never stall the whole benchmark.
#[derive(Debug, Clone, Copy)]
struct Backoff {
    mult: f64,
}

impl Backoff {
    const MIN: f64 = 1.0;
    const MAX: f64 = 5.0;
    fn new() -> Self { Self { mult: Self::MIN } }
    fn on_success(&mut self) {
        self.mult = (self.mult * 0.9).max(Self::MIN);
    }
    fn on_failure(&mut self, transient: bool) {
        if transient {
            self.mult = (self.mult * 2.0).min(Self::MAX);
        }
    }
    fn apply(&self, base: Duration) -> Duration {
        Duration::from_nanos((base.as_nanos() as f64 * self.mult) as u64)
    }
}

/// Query class. GRC calls these "cached" / "uncached".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Cached,
    Uncached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailKind {
    Timeout,
    Network,
    Protocol,
}

#[derive(Debug, Clone, Copy)]
pub enum ProbeResult {
    Ok(Duration),
    Fail(FailKind),
}

impl ProbeResult {
    pub fn rtt(&self) -> Option<Duration> {
        match self {
            ProbeResult::Ok(d) => Some(*d),
            ProbeResult::Fail(_) => None,
        }
    }
}

/// Events emitted by the streaming benchmark. IDs index into the
/// endpoint list the caller passed in; `total_per_class` lets the UI
/// render a progress bar without knowing the config.
#[derive(Debug, Clone)]
pub enum BenchEvent {
    Start {
        id: usize,
        resolver: String,
        provider: String,
        transport_kind: TransportKind,
        addr_display: String,
        total_per_class: usize,
    },
    Probe {
        id: usize,
        class: Class,
        domain_idx: u16,
        result: ProbeResult,
    },
    Done {
        id: usize,
    },
    AllDone,
}

#[derive(Debug, Clone)]
pub struct BenchConfig {
    pub domains: Vec<String>,
    /// Queries per domain per class.
    pub iterations: usize,
    pub timeout: Duration,
    /// Run the cached class (queries the domain as-is).
    pub cached: bool,
    /// Run the uncached class (queries `<random>.<domain>`, forces recursion).
    pub uncached: bool,
    pub include_ipv6: bool,
    /// Restrict to specific transports. Empty = all available.
    pub transports: Vec<TransportKind>,
    /// Base idle time inserted between consecutive queries to the same endpoint.
    /// Jittered (±jitter_pct) and grows under backoff when the endpoint returns
    /// timeout/network errors.
    pub inter_query: Duration,
    /// Pause between cached and uncached phases of a single endpoint.
    pub inter_class_pause: Duration,
    /// Jitter amplitude for `inter_query`. 0.0 disables, 0.3 = ±30%.
    pub jitter_pct: f64,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            domains: crate::domains::default_domains(),
            iterations: 4,
            timeout: Duration::from_millis(1500),
            cached: true,
            uncached: true,
            include_ipv6: false,
            transports: Vec::new(),
            inter_query: Duration::from_millis(40),
            inter_class_pause: Duration::from_millis(500),
            jitter_pct: 0.30,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EndpointReport {
    pub resolver: String,
    pub provider: String,
    pub transport_kind: TransportKind,
    pub addr_display: String,
    pub cached: Option<Summary>,
    pub uncached: Option<Summary>,
}

impl EndpointReport {
    /// Single-number ranking: p50 of cached if available, else uncached, else max.
    pub fn score(&self) -> Duration {
        self.cached
            .as_ref()
            .map(|s| s.p50)
            .or_else(|| self.uncached.as_ref().map(|s| s.p50))
            .unwrap_or(Duration::MAX)
    }
}

static COLD_COUNTER: AtomicU64 = AtomicU64::new(1);

fn random_label() -> String {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0) as u64;
    let c = COLD_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("b{:x}{:x}", c, n & 0xffff_ffff)
}

/// Flatten resolvers into concrete endpoints — one per transport variant
/// per IP family. Stable order so callers can index by usize id.
pub fn build_endpoints(
    resolvers: &[Resolver],
    cfg: &BenchConfig,
) -> Vec<(String, String, Transport)> {
    let mut out = Vec::new();
    for r in resolvers {
        for t in r.transports(cfg.include_ipv6) {
            if cfg.transports.is_empty() || cfg.transports.contains(&t.kind()) {
                out.push((r.name.clone(), r.provider.clone(), t));
            }
        }
    }
    out
}

async fn run_class_streaming(
    id: usize,
    transport: &Transport,
    cfg: &BenchConfig,
    class: Class,
    tx: &mpsc::UnboundedSender<BenchEvent>,
) {
    let mut rng = rng_seed();
    let mut backoff = Backoff::new();
    let mut order: Vec<usize> = (0..cfg.domains.len()).collect();

    for _ in 0..cfg.iterations {
        shuffle(&mut order, &mut rng);
        for &idx in &order {
            let d = &cfg.domains[idx];
            let host = match class {
                Class::Cached => d.clone(),
                Class::Uncached => format!("{}.{}", random_label(), d),
            };
            let (result, transient) = match probe(transport, &host, RecordType::A, cfg.timeout).await {
                Ok(o) => (ProbeResult::Ok(o.rtt), None),
                Err(ProbeError::Timeout(_)) => (ProbeResult::Fail(FailKind::Timeout), Some(true)),
                Err(ProbeError::Io(_)) => (ProbeResult::Fail(FailKind::Network), Some(true)),
                Err(_) => (ProbeResult::Fail(FailKind::Protocol), Some(false)),
            };
            match transient {
                None => backoff.on_success(),
                Some(t) => backoff.on_failure(t),
            }
            let _ = tx.send(BenchEvent::Probe {
                id,
                class,
                domain_idx: idx as u16,
                result,
            });
            if !cfg.inter_query.is_zero() {
                let base = backoff.apply(cfg.inter_query);
                sleep(jitter(base, &mut rng, cfg.jitter_pct)).await;
            }
        }
    }
}

/// Streaming version: emits `BenchEvent`s over `tx` as probes finish.
pub async fn run_bench_streaming(
    resolvers: Vec<Resolver>,
    cfg: BenchConfig,
    tx: mpsc::UnboundedSender<BenchEvent>,
) {
    let endpoints = build_endpoints(&resolvers, &cfg);
    let total_per_class = cfg.domains.len() * cfg.iterations;

    for (id, (name, provider, transport)) in endpoints.iter().enumerate() {
        let _ = tx.send(BenchEvent::Start {
            id,
            resolver: name.clone(),
            provider: provider.clone(),
            transport_kind: transport.kind(),
            addr_display: transport.display_addr(),
            total_per_class,
        });
    }

    let mut handles = Vec::new();
    for (id, (_, _, transport)) in endpoints.into_iter().enumerate() {
        let cfg = cfg.clone();
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            if cfg.cached {
                run_class_streaming(id, &transport, &cfg, Class::Cached, &tx).await;
            }
            if cfg.cached && cfg.uncached && !cfg.inter_class_pause.is_zero() {
                sleep(cfg.inter_class_pause).await;
            }
            if cfg.uncached {
                run_class_streaming(id, &transport, &cfg, Class::Uncached, &tx).await;
            }
            let _ = tx.send(BenchEvent::Done { id });
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    let _ = tx.send(BenchEvent::AllDone);
}

async fn run_class(
    transport: &Transport,
    domains: &[String],
    iterations: usize,
    timeout: Duration,
    inter_query: Duration,
    jitter_pct: f64,
    cold: bool,
) -> Option<Summary> {
    let mut rtts = Vec::with_capacity(domains.len() * iterations);
    let mut total = 0usize;
    let mut rng = rng_seed();
    let mut backoff = Backoff::new();
    let mut order: Vec<usize> = (0..domains.len()).collect();

    for _ in 0..iterations {
        shuffle(&mut order, &mut rng);
        for &idx in &order {
            let d = &domains[idx];
            let host = if cold {
                format!("{}.{}", random_label(), d)
            } else {
                d.clone()
            };
            total += 1;
            match probe(transport, &host, RecordType::A, timeout).await {
                Ok(outcome) => {
                    rtts.push(outcome.rtt);
                    backoff.on_success();
                }
                Err(e) => {
                    let transient = matches!(e, ProbeError::Timeout(_) | ProbeError::Io(_));
                    backoff.on_failure(transient);
                }
            }
            if !inter_query.is_zero() {
                let base = backoff.apply(inter_query);
                sleep(jitter(base, &mut rng, jitter_pct)).await;
            }
        }
    }
    summarize(rtts, total)
}

/// Headless benchmark. Endpoints in parallel; queries within one endpoint
/// serial with jitter and backoff.
pub async fn run_bench(resolvers: &[Resolver], cfg: &BenchConfig) -> Vec<EndpointReport> {
    let endpoints = build_endpoints(resolvers, cfg);
    let mut handles = Vec::new();

    for (name, provider, transport) in endpoints {
        let cfg = cfg.clone();
        handles.push(tokio::spawn(async move {
            let cached = if cfg.cached {
                run_class(&transport, &cfg.domains, cfg.iterations, cfg.timeout, cfg.inter_query, cfg.jitter_pct, false).await
            } else {
                None
            };
            if cfg.cached && cfg.uncached && !cfg.inter_class_pause.is_zero() {
                sleep(cfg.inter_class_pause).await;
            }
            let uncached = if cfg.uncached {
                run_class(&transport, &cfg.domains, cfg.iterations, cfg.timeout, cfg.inter_query, cfg.jitter_pct, true).await
            } else {
                None
            };
            EndpointReport {
                resolver: name,
                provider,
                transport_kind: transport.kind(),
                addr_display: transport.display_addr(),
                cached,
                uncached,
            }
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(report) = h.await {
            out.push(report);
        }
    }
    out.sort_by_key(EndpointReport::score);
    out
}
