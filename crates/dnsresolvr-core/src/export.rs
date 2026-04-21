//! Serialize benchmark results to CSV or JSON.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use crate::bench::EndpointReport;
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
    addr: String,
    cached: Option<ExportedSummary>,
    uncached: Option<ExportedSummary>,
}

impl From<&EndpointReport> for ExportedEndpoint {
    fn from(e: &EndpointReport) -> Self {
        Self {
            resolver: e.resolver.clone(),
            provider: e.provider.clone(),
            addr: e.addr.to_string(),
            cached: e.cached.as_ref().map(ExportedSummary::from),
            uncached: e.uncached.as_ref().map(ExportedSummary::from),
        }
    }
}

#[derive(Debug, Serialize)]
struct ExportedReport<'a> {
    generated_at: String,
    tool: &'a str,
    version: &'a str,
    endpoints: Vec<ExportedEndpoint>,
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{}", now)
}

pub fn export(reports: &[EndpointReport], path: &Path, format: ExportFormat) -> io::Result<()> {
    match format {
        ExportFormat::Json => write_json(reports, path),
        ExportFormat::Csv => write_csv(reports, path),
    }
}

fn write_json(reports: &[EndpointReport], path: &Path) -> io::Result<()> {
    let exported = ExportedReport {
        generated_at: timestamp(),
        tool: "dnsresolvr",
        version: env!("CARGO_PKG_VERSION"),
        endpoints: reports.iter().map(ExportedEndpoint::from).collect(),
    };
    let mut f = File::create(path)?;
    serde_json::to_writer_pretty(&mut f, &exported).map_err(io::Error::other)?;
    f.write_all(b"\n")?;
    Ok(())
}

fn write_csv(reports: &[EndpointReport], path: &Path) -> io::Result<()> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "resolver,provider,addr,\
         c_count,c_total,c_rel,c_min_ms,c_p50_ms,c_p95_ms,c_p99_ms,c_max_ms,c_mean_ms,c_stddev_ms,\
         u_count,u_total,u_rel,u_min_ms,u_p50_ms,u_p95_ms,u_p99_ms,u_max_ms,u_mean_ms,u_stddev_ms"
    )?;
    for e in reports {
        write!(
            f,
            "{},{},{}",
            csv_escape(&e.resolver),
            csv_escape(&e.provider),
            e.addr
        )?;
        write_class(&mut f, e.cached.as_ref())?;
        write_class(&mut f, e.uncached.as_ref())?;
        writeln!(f)?;
    }
    Ok(())
}

fn write_class(f: &mut File, s: Option<&Summary>) -> io::Result<()> {
    match s {
        Some(s) => write!(
            f,
            ",{},{},{:.4},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}",
            s.successes,
            s.total,
            s.reliability(),
            ms(s.min),
            ms(s.p50),
            ms(s.p95),
            ms(s.p99),
            ms(s.max),
            ms(s.mean),
            ms(s.stddev)
        ),
        None => write!(f, ",,,,,,,,,,"),
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
