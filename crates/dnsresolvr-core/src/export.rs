//! Serialize benchmark results to CSV or JSON.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::bench::{BenchConfig, EndpointReport};
use crate::stats::Summary;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Json,
}

impl ExportFormat {
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension().and_then(|s| s.to_str()).map(str::to_ascii_lowercase).as_deref() {
            Some("csv") => Some(ExportFormat::Csv),
            Some("json") => Some(ExportFormat::Json),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize)]
struct ExportedSummary {
    count: usize,
    total: usize,
    reliability: f64,
    min_ms: f64,
    p50_ms: f64,
    p90_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    mean_ms: f64,
    stddev_ms: f64,
}

impl From<&Summary> for ExportedSummary {
    fn from(s: &Summary) -> Self {
        Self {
            count: s.successes,
            total: s.total,
            reliability: s.reliability(),
            min_ms: ms(s.min),
            p50_ms: ms(s.p50),
            p90_ms: ms(s.p90),
            p95_ms: ms(s.p95),
            p99_ms: ms(s.p99),
            max_ms: ms(s.max),
            mean_ms: ms(s.mean),
            stddev_ms: ms(s.stddev),
        }
    }
}

#[derive(Debug, Serialize)]
struct ExportedEndpoint {
    resolver: String,
    provider: String,
    transport: &'static str,
    addr: String,
    filtering: Option<String>,
    /// Fresh connection + first answer, encrypted transports only.
    setup_ms: Option<f64>,
    dnssec_validating: Option<bool>,
    /// Address the resolver uses towards authoritative servers, and its operator.
    exit_ip: Option<String>,
    exit_as: Option<String>,
    /// Whether the resolver forwards your subnet (EDNS Client Subnet).
    ecs_sent: Option<bool>,
    ecs_subnet: Option<String>,
    cached: Option<ExportedSummary>,
    uncached: Option<ExportedSummary>,
}

impl From<&EndpointReport> for ExportedEndpoint {
    fn from(e: &EndpointReport) -> Self {
        Self {
            resolver: e.resolver.clone(),
            provider: e.provider.clone(),
            transport: e.transport_kind.label(),
            addr: e.addr_display.clone(),
            filtering: e.filtering.clone(),
            setup_ms: e.setup.map(ms),
            dnssec_validating: e.dnssec,
            exit_ip: e.privacy.as_ref().and_then(|p| p.exit_ip).map(|ip| ip.to_string()),
            exit_as: e.privacy.as_ref().and_then(|p| p.exit_as.clone()),
            ecs_sent: e.privacy.as_ref().and_then(|p| p.ecs_sent),
            ecs_subnet: e.privacy.as_ref().and_then(|p| p.ecs_subnet.clone()),
            cached: e.cached.as_ref().map(ExportedSummary::from),
            uncached: e.uncached.as_ref().map(ExportedSummary::from),
        }
    }
}

/// The settings a run was made with, so two exports can be compared.
#[derive(Debug, Serialize)]
struct ExportedConfig {
    domains: Vec<String>,
    iterations: usize,
    timeout_ms: u64,
    spacing_ms: u64,
    cached: bool,
    uncached: bool,
    warmup: bool,
    ipv6: bool,
    all_addrs: bool,
    transports: Vec<&'static str>,
    max_concurrent: usize,
    wildcard_domain: Option<String>,
}

impl From<&BenchConfig> for ExportedConfig {
    fn from(c: &BenchConfig) -> Self {
        Self {
            domains: c.domains.clone(),
            iterations: c.iterations,
            timeout_ms: c.timeout.as_millis() as u64,
            spacing_ms: c.inter_query.as_millis() as u64,
            cached: c.cached,
            uncached: c.uncached,
            warmup: c.warmup,
            ipv6: c.include_ipv6,
            all_addrs: c.all_addrs,
            transports: c.transports.iter().map(|k| k.label()).collect(),
            max_concurrent: c.max_concurrent,
            wildcard_domain: c.wildcard_domain.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ExportedReport<'a> {
    generated_at: String,
    tool: &'a str,
    version: &'a str,
    config: ExportedConfig,
    endpoints: Vec<ExportedEndpoint>,
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Current time as an ISO 8601 UTC timestamp, e.g. `2026-10-05T17:23:42Z`.
fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso8601_utc(now)
}

fn iso8601_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    // Civil-from-days (Howard Hinnant), valid for the whole Unix era.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, rem / 3600, rem % 3600 / 60, rem % 60
    )
}

/// Write `reports` to `path`. `cfg` is the configuration the run was made
/// with; it is stored alongside the results.
pub fn export(
    reports: &[EndpointReport],
    cfg: &BenchConfig,
    path: &Path,
    format: ExportFormat,
) -> io::Result<()> {
    match format {
        ExportFormat::Json => write_json(reports, cfg, path),
        ExportFormat::Csv => write_csv(reports, cfg, path),
    }
}

fn write_json(reports: &[EndpointReport], cfg: &BenchConfig, path: &Path) -> io::Result<()> {
    let exported = ExportedReport {
        generated_at: timestamp(),
        tool: "dnsresolvr",
        version: env!("CARGO_PKG_VERSION"),
        config: ExportedConfig::from(cfg),
        endpoints: reports.iter().map(ExportedEndpoint::from).collect(),
    };
    let mut f = File::create(path)?;
    serde_json::to_writer_pretty(&mut f, &exported).map_err(io::Error::other)?;
    f.write_all(b"\n")?;
    Ok(())
}

fn write_csv(reports: &[EndpointReport], cfg: &BenchConfig, path: &Path) -> io::Result<()> {
    let mut f = File::create(path)?;
    // Run settings repeat on every row so the file stays a plain table.
    writeln!(
        f,
        "resolver,provider,transport,addr,filtering,dnssec_validating,ecs_sent,exit_ip,exit_as,setup_ms,\
         c_count,c_total,c_rel,c_min_ms,c_p50_ms,c_p90_ms,c_p95_ms,c_p99_ms,c_max_ms,c_mean_ms,c_stddev_ms,\
         u_count,u_total,u_rel,u_min_ms,u_p50_ms,u_p90_ms,u_p95_ms,u_p99_ms,u_max_ms,u_mean_ms,u_stddev_ms,\
         generated_at,iterations,domains,timeout_ms,spacing_ms,max_concurrent"
    )?;
    let generated_at = timestamp();
    let domains = csv_escape(&cfg.domains.join(" "));
    for e in reports {
        let privacy = e.privacy.as_ref();
        write!(
            f,
            "{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&e.resolver),
            csv_escape(&e.provider),
            e.transport_kind.label(),
            csv_escape(&e.addr_display),
            csv_escape(e.filtering.as_deref().unwrap_or("")),
            e.dnssec.map(|v| v.to_string()).unwrap_or_default(),
            privacy.and_then(|p| p.ecs_sent).map(|v| v.to_string()).unwrap_or_default(),
            privacy.and_then(|p| p.exit_ip).map(|ip| ip.to_string()).unwrap_or_default(),
            csv_escape(privacy.and_then(|p| p.exit_as.as_deref()).unwrap_or("")),
            e.setup.map(|d| format!("{:.3}", ms(d))).unwrap_or_default(),
        )?;
        write_class(&mut f, e.cached.as_ref())?;
        write_class(&mut f, e.uncached.as_ref())?;
        writeln!(
            f,
            ",{},{},{},{},{},{}",
            generated_at,
            cfg.iterations,
            domains,
            cfg.timeout.as_millis(),
            cfg.inter_query.as_millis(),
            cfg.max_concurrent,
        )?;
    }
    Ok(())
}

fn write_class(f: &mut File, s: Option<&Summary>) -> io::Result<()> {
    match s {
        // Latencies are left empty when every query failed.
        Some(s) if s.has_samples() => write!(
            f,
            ",{},{},{:.4},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
            s.successes,
            s.total,
            s.reliability(),
            ms(s.min),
            ms(s.p50),
            ms(s.p90),
            ms(s.p95),
            ms(s.p99),
            ms(s.max),
            ms(s.mean),
            ms(s.stddev)
        ),
        Some(s) => write!(f, ",0,{},0.0000,,,,,,,,", s.total),
        None => write!(f, ",,,,,,,,,,,"),
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        let quoted = s.replace('"', "\"\"");
        format!("\"{}\"", quoted)
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_timestamps() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601_utc(1_791_220_999), "2026-10-05T17:23:19Z");
    }

    #[test]
    fn csv_escaping() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
