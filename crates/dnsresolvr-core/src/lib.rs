//! Core benchmarking engine for `dnsresolvr`.

pub mod bench;
pub mod domains;
pub mod export;
pub mod privacy;
pub mod probe;
pub mod resolver;
pub mod stats;
pub mod system;
pub mod transport;
pub mod verdict;

pub use bench::{
    build_endpoints, run_bench, run_bench_streaming, run_bench_with_progress, BenchConfig, BenchEvent, Class, Endpoint,
    EndpointReport, FailKind, ProbeResult,
};
pub use domains::{default_domains, dedup_preserve, load_domains_file, DEFAULT_DOMAINS};
pub use export::{export, ExportFormat};
pub use privacy::PrivacyInfo;
pub use probe::{probe_udp, probe_udp_at, ProbeError, ProbeOutcome};
pub use resolver::{
    add_system_resolvers, bundled_resolvers, load_resolvers_file, merge_resolvers, Resolver,
};
pub use stats::{summarize, Summary, P99_MIN_SAMPLES};
pub use system::system_resolvers;
pub use transport::{probe, Session, Transport, TransportKind};
pub use verdict::{verdict, Verdict};

pub use hickory_proto::rr::RecordType;
