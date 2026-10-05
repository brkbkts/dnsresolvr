//! Benchmark orchestrator. Runs probe batches per endpoint, per query class.
//!
//! An *endpoint* is a single (resolver, transport) pair. One resolver can
//! produce several endpoints: UDP, DoT and DoQ per address, plus DoH and DoH3.
//!
//! Each endpoint goes through the same steps:
//!
//! 1. **setup** — open a fresh connection and send one query, timed together
//!    (encrypted transports only),
//! 2. **DNSSEC check** — one untimed query for a deliberately broken zone,
//! 3. **warm-up** — one untimed query per domain so the cached class really
//!    measures cache hits,
//! 4. **cached** and **uncached** classes — the timed samples.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::sleep;

use crate::privacy::{self, AsnCache, PrivacyInfo};
use crate::probe::{ProbeError, ProbeOutcome};
use crate::resolver::Resolver;
use crate::stats::{summarize, Summary};
use crate::transport::{Session, Transport, TransportKind};

/// A zone with intentionally invalid signatures. Validating resolvers answer
/// SERVFAIL; non-validating ones return the address.
const DNSSEC_TEST_DOMAIN: &str = "dnssec-failed.org";

/// Stop probing an endpoint after this many consecutive timeouts or network
/// errors with no success at all, so a dead endpoint does not hold a
/// concurrency slot for the whole run.
const GIVE_UP_AFTER: usize = 5;

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
    /// Malformed or mismatched reply.
    Protocol,
    /// A well-formed reply that does not answer the question: SERVFAIL,
    /// REFUSED, or no address for a domain that should have one.
    BadAnswer,
}

impl FailKind {
    fn is_transient(self) -> bool {
        matches!(self, FailKind::Timeout | FailKind::Network)
    }
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
        filtering: Option<String>,
        transport_kind: TransportKind,
        addr_display: String,
        total_per_class: usize,
    },
    /// The endpoint got a concurrency slot and started probing.
    Running {
        id: usize,
    },
    /// Time to open a fresh connection and get the first answer. `None` if
    /// the connection could not be established. Not sent for UDP.
    Setup {
        id: usize,
        result: Option<Duration>,
    },
    /// Result of the DNSSEC validation check. `None` if inconclusive.
    Dnssec {
        id: usize,
        validates: Option<bool>,
    },
    /// Exit server and client-subnet findings.
    Privacy {
        id: usize,
        info: PrivacyInfo,
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
    /// Probe every listed address of a resolver, not just the first per family.
    pub all_addrs: bool,
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
    /// How many endpoints are probed at the same time. 0 = no limit.
    /// Probing everything at once makes the client itself the bottleneck
    /// and inflates tail latencies.
    pub max_concurrent: usize,
    /// Send one untimed query per domain before the cached class.
    pub warmup: bool,
    /// Check whether each endpoint validates DNSSEC.
    pub dnssec_check: bool,
    /// Find each endpoint's exit server and whether it forwards your subnet.
    pub privacy_check: bool,
    /// If set, the uncached class queries `<random>.<this domain>` and expects
    /// an address back. Use a domain with a wildcard record to measure
    /// uncached *positive* answers; the default random-subdomain mode
    /// measures negative (NXDOMAIN) answers.
    pub wildcard_domain: Option<String>,
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
            all_addrs: false,
            transports: Vec::new(),
            inter_query: Duration::from_millis(40),
            inter_class_pause: Duration::from_millis(500),
            jitter_pct: 0.30,
            max_concurrent: 8,
            warmup: true,
            dnssec_check: true,
            privacy_check: true,
            wildcard_domain: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EndpointReport {
    pub resolver: String,
    pub provider: String,
    pub filtering: Option<String>,
    pub transport_kind: TransportKind,
    pub addr_display: String,
    /// Fresh connection + first answer. `None` for UDP or if it failed.
    pub setup: Option<Duration>,
    /// Whether the endpoint validates DNSSEC. `None` if not checked or unclear.
    pub dnssec: Option<bool>,
    /// Exit server and client-subnet findings. `None` if not checked.
    pub privacy: Option<PrivacyInfo>,
    pub cached: Option<Summary>,
    pub uncached: Option<Summary>,
}

impl EndpointReport {
    /// Single-number ranking: p50 of cached if available, else uncached, else max.
    pub fn score(&self) -> Duration {
        let p50 = |s: &Option<Summary>| s.as_ref().filter(|s| s.has_samples()).map(|s| s.p50);
        p50(&self.cached).or_else(|| p50(&self.uncached)).unwrap_or(Duration::MAX)
    }
}

static COLD_COUNTER: AtomicU64 = AtomicU64::new(1);

fn random_label() -> String {
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0) as u64;
    let c = COLD_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("b{:x}{:x}", c, n & 0xffff_ffff)
}

/// A single (resolver, transport) pair to benchmark.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub resolver: String,
    pub provider: String,
    pub filtering: Option<String>,
    pub transport: Transport,
}

/// Flatten resolvers into concrete endpoints — one per transport variant
/// per address. Stable order so callers can index by usize id.
pub fn build_endpoints(resolvers: &[Resolver], cfg: &BenchConfig) -> Vec<Endpoint> {
    let mut out = Vec::new();
    for r in resolvers {
        for t in r.transports(cfg.include_ipv6, cfg.all_addrs) {
            if cfg.transports.is_empty() || cfg.transports.contains(&t.kind()) {
                out.push(Endpoint {
                    resolver: r.name.clone(),
                    provider: r.provider.clone(),
                    filtering: r.filtering.clone(),
                    transport: t,
                });
            }
        }
    }
    out
}

/// Decide whether a reply counts as a successful sample for its class.
fn classify(class: Class, wildcard: bool, outcome: &ProbeOutcome) -> ProbeResult {
    let has_answer = outcome.rcode == ResponseCode::NoError && outcome.answer_count > 0;
    let ok = match class {
        Class::Cached => has_answer,
        Class::Uncached if wildcard => has_answer,
        // A random subdomain normally does not exist, so NXDOMAIN is the
        // expected answer. NOERROR covers wildcard zones and NXDOMAIN rewriting.
        Class::Uncached => matches!(outcome.rcode, ResponseCode::NXDomain | ResponseCode::NoError),
    };
    if ok { ProbeResult::Ok(outcome.rtt) } else { ProbeResult::Fail(FailKind::BadAnswer) }
}

fn fail_kind(e: &ProbeError) -> FailKind {
    match e {
        ProbeError::Timeout(_) => FailKind::Timeout,
        ProbeError::Io(_) => FailKind::Network,
        _ => FailKind::Protocol,
    }
}

/// Tracks whether an endpoint is alive at all.
struct Health {
    successes: usize,
    consecutive_transient: usize,
    dead: Option<FailKind>,
}

impl Health {
    fn new() -> Self {
        Self { successes: 0, consecutive_transient: 0, dead: None }
    }

    fn record(&mut self, result: &ProbeResult) {
        match result {
            ProbeResult::Ok(_) => {
                self.successes += 1;
                self.consecutive_transient = 0;
            }
            ProbeResult::Fail(k) if k.is_transient() => {
                self.consecutive_transient += 1;
                if self.successes == 0 && self.consecutive_transient >= GIVE_UP_AFTER {
                    self.dead = Some(*k);
                }
            }
            ProbeResult::Fail(_) => self.consecutive_transient = 0,
        }
    }
}

struct EndpointRun<'a> {
    id: usize,
    cfg: &'a BenchConfig,
    tx: &'a mpsc::UnboundedSender<BenchEvent>,
    session: Session,
    health: Health,
    backoff: Backoff,
    rng: u64,
}

impl EndpointRun<'_> {
    async fn pause(&mut self) {
        if !self.cfg.inter_query.is_zero() {
            let base = self.backoff.apply(self.cfg.inter_query);
            sleep(jitter(base, &mut self.rng, self.cfg.jitter_pct)).await;
        }
    }

    /// Fresh connection + one query, timed together. Tried twice before the
    /// endpoint is declared unreachable.
    async fn measure_setup(&mut self) -> Option<Duration> {
        let host = self.cfg.domains.first()?.clone();
        let mut last_fail = FailKind::Network;
        for _ in 0..2 {
            self.session.reset();
            let start = Instant::now();
            let attempt = async {
                self.session.connect(self.cfg.timeout).await?;
                self.session.query(&host, RecordType::A, self.cfg.timeout).await
            };
            match attempt.await {
                Ok(_) => return Some(start.elapsed()),
                Err(e) => last_fail = fail_kind(&e),
            }
        }
        self.health.dead = Some(last_fail);
        None
    }

    async fn check_dnssec(&mut self) -> Option<bool> {
        // First-time validation of a broken zone can be slow; be generous.
        let timeout = self.cfg.timeout.max(Duration::from_secs(3));
        let outcome = self.session.query(DNSSEC_TEST_DOMAIN, RecordType::A, timeout).await.ok()?;
        match outcome.rcode {
            ResponseCode::ServFail => Some(true),
            ResponseCode::NoError if outcome.answer_count > 0 => Some(false),
            _ => None,
        }
    }

    async fn warm_up(&mut self) {
        for i in 0..self.cfg.domains.len() {
            if self.health.dead.is_some() {
                return;
            }
            let host = self.cfg.domains[i].clone();
            let result = match self.session.query(&host, RecordType::A, self.cfg.timeout).await {
                Ok(o) => ProbeResult::Ok(o.rtt),
                Err(e) => ProbeResult::Fail(fail_kind(&e)),
            };
            self.health.record(&result);
            self.pause().await;
        }
    }

    async fn run_class(&mut self, class: Class) {
        let cfg = self.cfg;
        let wildcard = cfg.wildcard_domain.as_deref().filter(|_| class == Class::Uncached);
        let mut order: Vec<usize> = (0..cfg.domains.len()).collect();

        for _ in 0..cfg.iterations {
            shuffle(&mut order, &mut self.rng);
            for &idx in &order {
                let result = if let Some(kind) = self.health.dead {
                    // Unreachable endpoint: account for the probe without waiting.
                    ProbeResult::Fail(kind)
                } else {
                    let host = match (class, wildcard) {
                        (Class::Cached, _) => cfg.domains[idx].clone(),
                        (Class::Uncached, Some(w)) => format!("{}.{}", random_label(), w),
                        (Class::Uncached, None) => format!("{}.{}", random_label(), cfg.domains[idx]),
                    };
                    let result = match self.session.query(&host, RecordType::A, cfg.timeout).await {
                        Ok(o) => classify(class, wildcard.is_some(), &o),
                        Err(e) => ProbeResult::Fail(fail_kind(&e)),
                    };
                    match result {
                        ProbeResult::Ok(_) => self.backoff.on_success(),
                        ProbeResult::Fail(k) => self.backoff.on_failure(k.is_transient()),
                    }
                    self.health.record(&result);
                    result
                };
                let _ = self.tx.send(BenchEvent::Probe {
                    id: self.id,
                    class,
                    domain_idx: idx as u16,
                    result,
                });
                if self.health.dead.is_none() {
                    self.pause().await;
                }
            }
        }
    }
}

async fn run_endpoint(
    id: usize,
    transport: Transport,
    cfg: Arc<BenchConfig>,
    tx: mpsc::UnboundedSender<BenchEvent>,
    slots: Arc<Semaphore>,
    asn_cache: AsnCache,
) {
    let _slot = slots.acquire().await;
    let _ = tx.send(BenchEvent::Running { id });

    let connection_oriented = transport.kind().is_connection_oriented();
    let mut run = EndpointRun {
        id,
        cfg: &cfg,
        tx: &tx,
        session: Session::new(transport),
        health: Health::new(),
        backoff: Backoff::new(),
        rng: rng_seed(),
    };

    if connection_oriented {
        let result = run.measure_setup().await;
        let _ = tx.send(BenchEvent::Setup { id, result });
    }
    if cfg.dnssec_check && run.health.dead.is_none() {
        let validates = run.check_dnssec().await;
        let _ = tx.send(BenchEvent::Dnssec { id, validates });
    }
    if cfg.privacy_check && run.health.dead.is_none() {
        let timeout = cfg.timeout.max(Duration::from_secs(3));
        let info = privacy::check(&mut run.session, timeout, &asn_cache).await;
        let _ = tx.send(BenchEvent::Privacy { id, info });
    }
    if cfg.cached {
        if cfg.warmup {
            run.warm_up().await;
        }
        run.run_class(Class::Cached).await;
    }
    if cfg.cached && cfg.uncached && !cfg.inter_class_pause.is_zero() && run.health.dead.is_none() {
        sleep(cfg.inter_class_pause).await;
    }
    if cfg.uncached {
        run.run_class(Class::Uncached).await;
    }
    let _ = tx.send(BenchEvent::Done { id });
}

/// Run the benchmark and emit `BenchEvent`s over `tx` as probes finish.
pub async fn run_bench_streaming(
    resolvers: Vec<Resolver>,
    cfg: BenchConfig,
    tx: mpsc::UnboundedSender<BenchEvent>,
) {
    let endpoints = build_endpoints(&resolvers, &cfg);
    let total_per_class = cfg.domains.len() * cfg.iterations;

    for (id, ep) in endpoints.iter().enumerate() {
        let _ = tx.send(BenchEvent::Start {
            id,
            resolver: ep.resolver.clone(),
            provider: ep.provider.clone(),
            filtering: ep.filtering.clone(),
            transport_kind: ep.transport.kind(),
            addr_display: ep.transport.display_addr(),
            total_per_class,
        });
    }

    let permits = match cfg.max_concurrent {
        0 => Semaphore::MAX_PERMITS,
        n => n,
    };
    let slots = Arc::new(Semaphore::new(permits));
    let cfg = Arc::new(cfg);
    let asn_cache = privacy::new_asn_cache();

    let handles: Vec<_> = endpoints
        .into_iter()
        .enumerate()
        .map(|(id, ep)| {
            tokio::spawn(run_endpoint(
                id,
                ep.transport,
                cfg.clone(),
                tx.clone(),
                slots.clone(),
                asn_cache.clone(),
            ))
        })
        .collect();

    for h in handles {
        let _ = h.await;
    }
    let _ = tx.send(BenchEvent::AllDone);
}

/// Folds a stream of [`BenchEvent`]s into per-endpoint reports.
#[derive(Default)]
struct Collector {
    rows: Vec<CollectorRow>,
}

#[derive(Default)]
struct CollectorRow {
    report: Option<EndpointReport>,
    cached: (Vec<Duration>, usize),
    uncached: (Vec<Duration>, usize),
}

impl Collector {
    fn row(&mut self, id: usize) -> &mut CollectorRow {
        if self.rows.len() <= id {
            self.rows.resize_with(id + 1, CollectorRow::default);
        }
        &mut self.rows[id]
    }

    fn apply(&mut self, ev: BenchEvent) {
        match ev {
            BenchEvent::Start { id, resolver, provider, filtering, transport_kind, addr_display, .. } => {
                self.row(id).report = Some(EndpointReport {
                    resolver,
                    provider,
                    filtering,
                    transport_kind,
                    addr_display,
                    setup: None,
                    dnssec: None,
                    privacy: None,
                    cached: None,
                    uncached: None,
                });
            }
            BenchEvent::Setup { id, result } => {
                if let Some(r) = self.row(id).report.as_mut() { r.setup = result; }
            }
            BenchEvent::Dnssec { id, validates } => {
                if let Some(r) = self.row(id).report.as_mut() { r.dnssec = validates; }
            }
            BenchEvent::Privacy { id, info } => {
                if let Some(r) = self.row(id).report.as_mut() { r.privacy = Some(info); }
            }
            BenchEvent::Probe { id, class, result, .. } => {
                let row = self.row(id);
                let bucket = match class {
                    Class::Cached => &mut row.cached,
                    Class::Uncached => &mut row.uncached,
                };
                bucket.1 += 1;
                if let Some(rtt) = result.rtt() {
                    bucket.0.push(rtt);
                }
            }
            BenchEvent::Running { .. } | BenchEvent::Done { .. } | BenchEvent::AllDone => {}
        }
    }

    fn finish(self) -> Vec<EndpointReport> {
        let mut out: Vec<EndpointReport> = self
            .rows
            .into_iter()
            .filter_map(|row| {
                let mut report = row.report?;
                report.cached = summarize(row.cached.0, row.cached.1);
                report.uncached = summarize(row.uncached.0, row.uncached.1);
                Some(report)
            })
            .collect();
        out.sort_by_key(EndpointReport::score);
        out
    }
}

/// Headless benchmark: runs the streaming benchmark to completion and returns
/// one report per endpoint, fastest first.
pub async fn run_bench(resolvers: &[Resolver], cfg: &BenchConfig) -> Vec<EndpointReport> {
    run_bench_with_progress(resolvers, cfg, |_, _| {}).await
}

/// Like [`run_bench`], calling `progress(done, total)` after every probe.
pub async fn run_bench_with_progress(
    resolvers: &[Resolver],
    cfg: &BenchConfig,
    mut progress: impl FnMut(usize, usize),
) -> Vec<EndpointReport> {
    let classes = cfg.cached as usize + cfg.uncached as usize;
    let total = build_endpoints(resolvers, cfg).len() * cfg.domains.len() * cfg.iterations * classes;

    let (tx, mut rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run_bench_streaming(resolvers.to_vec(), cfg.clone(), tx));

    let mut collector = Collector::default();
    let mut done = 0usize;
    while let Some(ev) = rx.recv().await {
        if matches!(ev, BenchEvent::Probe { .. }) {
            done += 1;
            progress(done, total);
        }
        collector.apply(ev);
    }
    let _ = task.await;
    collector.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, OpCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::UdpSocket;

    #[derive(Clone, Copy)]
    enum Behaviour {
        Answer,
        Rcode(ResponseCode),
        Silent,
    }

    /// Minimal UDP DNS server on localhost. Returns its address and a counter
    /// of the queries it has seen.
    async fn mock_server(behaviour: Behaviour) -> (SocketAddr, Arc<AtomicUsize>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else { return };
                counter.fetch_add(1, Ordering::SeqCst);
                let Ok(query) = Message::from_vec(&buf[..n]) else { continue };
                let mut resp = Message::response(query.metadata.id, OpCode::Query);
                for q in &query.queries {
                    resp.add_query(q.clone());
                }
                match behaviour {
                    Behaviour::Silent => continue,
                    Behaviour::Rcode(rc) => {
                        resp.metadata.response_code = rc;
                    }
                    Behaviour::Answer => {
                        let name = query.queries[0].name().clone();
                        resp.add_answer(Record::from_rdata(name, 60, RData::A(A::new(192, 0, 2, 1))));
                    }
                }
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        (addr, seen)
    }

    fn resolver_at(addr: SocketAddr) -> Resolver {
        Resolver {
            name: "mock".into(),
            ipv4: vec![addr.ip()],
            port: Some(addr.port()),
            ..Resolver::default()
        }
    }

    fn test_cfg() -> BenchConfig {
        BenchConfig {
            domains: vec!["a.test".into(), "b.test".into()],
            iterations: 3,
            timeout: Duration::from_millis(60),
            inter_query: Duration::ZERO,
            inter_class_pause: Duration::ZERO,
            dnssec_check: false,
            privacy_check: false,
            ..BenchConfig::default()
        }
    }

    #[tokio::test]
    async fn healthy_resolver_and_warmup_is_not_counted() {
        let (addr, seen) = mock_server(Behaviour::Answer).await;
        let reports = run_bench(&[resolver_at(addr)], &test_cfg()).await;
        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert!(r.setup.is_none(), "UDP has no connection setup");

        let cached = r.cached.as_ref().unwrap();
        assert_eq!((cached.successes, cached.total), (6, 6));
        let uncached = r.uncached.as_ref().unwrap();
        assert_eq!((uncached.successes, uncached.total), (6, 6));
        // 2 warm-up queries on top of the 12 timed ones.
        assert_eq!(seen.load(Ordering::SeqCst), 14);
    }

    #[tokio::test]
    async fn progress_counts_every_probe() {
        let (addr, _) = mock_server(Behaviour::Answer).await;
        let mut calls = Vec::new();
        run_bench_with_progress(&[resolver_at(addr)], &test_cfg(), |done, total| calls.push((done, total))).await;
        assert_eq!(calls.len(), 12);
        assert_eq!(calls.last(), Some(&(12, 12)));
    }

    #[tokio::test]
    async fn warmup_can_be_disabled() {
        let (addr, seen) = mock_server(Behaviour::Answer).await;
        let cfg = BenchConfig { warmup: false, uncached: false, ..test_cfg() };
        run_bench(&[resolver_at(addr)], &cfg).await;
        assert_eq!(seen.load(Ordering::SeqCst), 6);
    }

    #[tokio::test]
    async fn servfail_is_a_failure_not_a_fast_answer() {
        let (addr, _) = mock_server(Behaviour::Rcode(ResponseCode::ServFail)).await;
        let reports = run_bench(&[resolver_at(addr)], &test_cfg()).await;
        let r = &reports[0];
        for class in [&r.cached, &r.uncached] {
            let s = class.as_ref().unwrap();
            assert_eq!((s.successes, s.total), (0, 6));
            assert_eq!(s.reliability(), 0.0);
        }
        assert_eq!(r.score(), Duration::MAX);
    }

    #[tokio::test]
    async fn nxdomain_is_fine_for_uncached_only() {
        let (addr, _) = mock_server(Behaviour::Rcode(ResponseCode::NXDomain)).await;
        let reports = run_bench(&[resolver_at(addr)], &test_cfg()).await;
        let r = &reports[0];
        assert_eq!(r.cached.as_ref().unwrap().successes, 0);
        assert_eq!(r.uncached.as_ref().unwrap().successes, 6);
    }

    #[tokio::test]
    async fn wildcard_mode_expects_an_address() {
        let (addr, _) = mock_server(Behaviour::Rcode(ResponseCode::NXDomain)).await;
        let cfg = BenchConfig { cached: false, wildcard_domain: Some("wild.test".into()), ..test_cfg() };
        let reports = run_bench(&[resolver_at(addr)], &cfg).await;
        assert_eq!(reports[0].uncached.as_ref().unwrap().successes, 0);
    }

    #[tokio::test]
    async fn dead_resolver_is_abandoned_but_fully_accounted() {
        let (addr, seen) = mock_server(Behaviour::Silent).await;
        let cfg = BenchConfig { iterations: 20, ..test_cfg() };
        let started = Instant::now();
        let reports = run_bench(&[resolver_at(addr)], &cfg).await;

        let r = &reports[0];
        assert_eq!(r.cached.as_ref().unwrap().total, 40);
        assert_eq!(r.uncached.as_ref().unwrap().total, 40);
        assert_eq!(r.cached.as_ref().unwrap().successes, 0);
        // Gave up after a handful of timeouts rather than waiting out all 80.
        assert_eq!(seen.load(Ordering::SeqCst), GIVE_UP_AFTER);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn dnssec_check_reports_validation() {
        let (validating, _) = mock_server(Behaviour::Rcode(ResponseCode::ServFail)).await;
        let (plain, _) = mock_server(Behaviour::Answer).await;
        let cfg = BenchConfig { dnssec_check: true, iterations: 1, ..test_cfg() };
        let mut a = resolver_at(validating);
        a.name = "validating".into();
        let reports = run_bench(&[a, resolver_at(plain)], &cfg).await;
        let by_name = |n: &str| reports.iter().find(|r| r.resolver == n).unwrap().dnssec;
        assert_eq!(by_name("validating"), Some(true));
        assert_eq!(by_name("mock"), Some(false));
    }

    #[tokio::test]
    async fn concurrency_limit_is_respected() {
        let (addr, _) = mock_server(Behaviour::Answer).await;
        let resolvers: Vec<Resolver> = (0..6)
            .map(|i| {
                let mut r = resolver_at(addr);
                r.name = format!("mock{}", i);
                r
            })
            .collect();
        let cfg = BenchConfig { max_concurrent: 2, iterations: 1, ..test_cfg() };

        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(run_bench_streaming(resolvers, cfg, tx));
        let (mut running, mut peak) = (0usize, 0usize);
        while let Some(ev) = rx.recv().await {
            match ev {
                BenchEvent::Running { .. } => {
                    running += 1;
                    peak = peak.max(running);
                }
                BenchEvent::Done { .. } => running -= 1,
                _ => {}
            }
        }
        assert_eq!(peak, 2);
    }
}
