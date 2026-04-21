//! Core benchmarking engine for `dnsresolvr`.

pub mod bench;
pub mod domains;
pub mod export;
pub mod probe;
pub mod resolver;
pub mod stats;

pub use bench::{
    build_endpoints, run_bench, run_bench_streaming, BenchConfig, BenchEvent, Class,
    EndpointReport, FailKind, ProbeResult,
};
pub use domains::{default_domains, dedup_preserve, load_domains_file, DEFAULT_DOMAINS};
pub use export::{export, ExportFormat};
pub use probe::{probe_udp, ProbeError, ProbeOutcome};
pub use resolver::{bundled_resolvers, Resolver};
pub use stats::{summarize, Summary};

pub use hickory_proto::rr::RecordType;
