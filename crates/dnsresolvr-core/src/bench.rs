//! Benchmark orchestrator — runs probe batches per resolver, per query class.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::rr::RecordType;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::probe::probe_udp;
use crate::resolver::Resolver;
use crate::stats::{summarize, Summary};

/// Query class. GRC calls these "cached" / "uncached".
///
/// * `Cached` queries the domain as-is; after the first hit the resolver
///   serves from cache, so aggregate timings reflect the cache-hit path.
/// * `Uncached` queries `<random>.<domain>`; the random label is never
///   cached, forcing full recursion on every probe.
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
        addr: IpAddr,
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
    /// Idle time inserted between consecutive queries to the same endpoint.
    /// Keeps us from being punished as abuse and smooths out jitter.
    pub inter_query: Duration,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            domains: crate::domains::default_domains(),
            iterations: 5,
            timeout: Duration::from_millis(1500),
            cached: true,
            uncached: true,
            include_ipv6: false,
            inter_query: Duration::from_millis(25),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EndpointReport {
    pub resolver: String,
    pub provider: String,
    pub addr: IpAddr,
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

fn endpoints_for(r: &Resolver, include_ipv6: bool) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = r.ipv4.iter().copied().take(1).collect();
    if include_ipv6 {
        v.extend(r.ipv6.iter().copied().take(1));
    }
    v
}

async fn run_class(
    addr: IpAddr,
    domains: &[String],
    iterations: usize,
    timeout: Duration,
    inter_query: Duration,
    cold: bool,
) -> Option<Summary> {
    let mut rtts = Vec::with_capacity(domains.len() * iterations);
    let mut total = 0usize;

    for _ in 0..iterations {
        for d in domains {
            let host = if cold {
                format!("{}.{}", random_label(), d)
            } else {
                d.clone()
            };
            total += 1;
            match probe_udp(addr, &host, RecordType::A, timeout).await {
                Ok(outcome) => rtts.push(outcome.rtt),
                Err(_) => { /* counts toward total, reduces reliability */ }
            }
            if !inter_query.is_zero() {
                sleep(inter_query).await;
            }
        }
    }
    summarize(rtts, total)
}

/// Flatten resolvers into concrete endpoints — one per address we'll probe.
/// IPv4 first, then IPv6 if `include_ipv6`. Stable order so callers can index.
pub fn build_endpoints(resolvers: &[Resolver], include_ipv6: bool) -> Vec<(String, String, IpAddr)> {
    let mut out = Vec::new();
    for r in resolvers {
        for addr in endpoints_for(r, include_ipv6) {
            out.push((r.name.clone(), r.provider.clone(), addr));
        }
    }
    out
}

async fn run_class_streaming(
    id: usize,
    addr: IpAddr,
    domains: &[String],
    iterations: usize,
    timeout: Duration,
    inter_query: Duration,
    class: Class,
    tx: &mpsc::UnboundedSender<BenchEvent>,
) {
    for _ in 0..iterations {
        for (idx, d) in domains.iter().enumerate() {
            let host = match class {
                Class::Cached => d.clone(),
                Class::Uncached => format!("{}.{}", random_label(), d),
            };
            let result = match probe_udp(addr, &host, RecordType::A, timeout).await {
                Ok(o) => ProbeResult::Ok(o.rtt),
                Err(crate::probe::ProbeError::Timeout(_)) => ProbeResult::Fail(FailKind::Timeout),
                Err(crate::probe::ProbeError::Io(_)) => ProbeResult::Fail(FailKind::Network),
                Err(_) => ProbeResult::Fail(FailKind::Protocol),
            };
            let _ = tx.send(BenchEvent::Probe {
                id,
                class,
                domain_idx: idx as u16,
                result,
            });
            if !inter_query.is_zero() {
                sleep(inter_query).await;
            }
        }
    }
}

/// Streaming version: emits `BenchEvent`s over `tx` as probes finish.
/// Consumes the channel sender; closes automatically on `AllDone`.
pub async fn run_bench_streaming(
    resolvers: Vec<Resolver>,
    cfg: BenchConfig,
    tx: mpsc::UnboundedSender<BenchEvent>,
) {
    let endpoints = build_endpoints(&resolvers, cfg.include_ipv6);
    let total_per_class = cfg.domains.len() * cfg.iterations;

    for (id, (name, provider, addr)) in endpoints.iter().enumerate() {
        let _ = tx.send(BenchEvent::Start {
            id,
            resolver: name.clone(),
            provider: provider.clone(),
            addr: *addr,
            total_per_class,
        });
    }

    let mut handles = Vec::new();
    for (id, (_, _, addr)) in endpoints.into_iter().enumerate() {
        let cfg = cfg.clone();
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            if cfg.cached {
                run_class_streaming(
                    id,
                    addr,
                    &cfg.domains,
                    cfg.iterations,
                    cfg.timeout,
                    cfg.inter_query,
                    Class::Cached,
                    &tx,
                )
                .await;
            }
            if cfg.uncached {
                run_class_streaming(
                    id,
                    addr,
                    &cfg.domains,
                    cfg.iterations,
                    cfg.timeout,
                    cfg.inter_query,
                    Class::Uncached,
                    &tx,
                )
                .await;
            }
            let _ = tx.send(BenchEvent::Done { id });
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    let _ = tx.send(BenchEvent::AllDone);
}

/// Run the full benchmark. Endpoints are tested in parallel; queries within
/// a single endpoint are serial with jitter for fairness.
pub async fn run_bench(resolvers: &[Resolver], cfg: &BenchConfig) -> Vec<EndpointReport> {
    let mut handles = Vec::new();

    for r in resolvers {
        for addr in endpoints_for(r, cfg.include_ipv6) {
            let name = r.name.clone();
            let provider = r.provider.clone();
            let cfg = cfg.clone();
            handles.push(tokio::spawn(async move {
                let cached = if cfg.cached {
                    run_class(addr, &cfg.domains, cfg.iterations, cfg.timeout, cfg.inter_query, false).await
                } else {
                    None
                };
                let uncached = if cfg.uncached {
                    run_class(addr, &cfg.domains, cfg.iterations, cfg.timeout, cfg.inter_query, true).await
                } else {
                    None
                };
                EndpointReport { resolver: name, provider, addr, cached, uncached }
            }));
        }
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
