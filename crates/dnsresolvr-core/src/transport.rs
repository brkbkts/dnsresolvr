//! Transport abstractions and probes for UDP, DoT, and DoH.
//!
//! All three probes share the same DNS wire format; only the transport differs.
//! Each probe builds its own request and times the full request/response cycle,
//! so results are directly comparable across transports. DoT/DoH pay an extra
//! TCP+TLS setup on each probe (no connection pooling yet); see M4.5.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::probe::{next_id, ProbeError, ProbeOutcome};

/// The transport + address of a single benchmarkable endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Transport {
    /// Classic UDP/53.
    Udp { addr: IpAddr },
    /// DNS-over-TLS (RFC 7858) on port 853. `tls_name` is the SNI / cert name.
    Dot { addr: IpAddr, tls_name: String },
    /// DNS-over-HTTPS (RFC 8484). URL includes scheme, host, and path.
    Doh { url: String },
}

impl Transport {
    pub fn kind(&self) -> TransportKind {
        match self {
            Transport::Udp { .. } => TransportKind::Udp,
            Transport::Dot { .. } => TransportKind::Dot,
            Transport::Doh { .. } => TransportKind::Doh,
        }
    }

    /// Short human-readable address: `1.1.1.1`, `1.1.1.1 (cloudflare-dns.com)`,
    /// or `https://cloudflare-dns.com/dns-query`.
    pub fn display_addr(&self) -> String {
        match self {
            Transport::Udp { addr } => addr.to_string(),
            Transport::Dot { addr, tls_name } => format!("{} ({})", addr, tls_name),
            Transport::Doh { url } => url.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Udp,
    Dot,
    Doh,
}

impl TransportKind {
    pub fn label(self) -> &'static str {
        match self {
            TransportKind::Udp => "UDP",
            TransportKind::Dot => "DoT",
            TransportKind::Doh => "DoH",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Some(TransportKind::Udp),
            "dot" | "tls" => Some(TransportKind::Dot),
            "doh" | "https" => Some(TransportKind::Doh),
            _ => None,
        }
    }
}

/// Dispatch a single probe to the right transport handler.
pub async fn probe(
    transport: &Transport,
    hostname: &str,
    qtype: RecordType,
    timeout: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    match transport {
        Transport::Udp { addr } => crate::probe::probe_udp(*addr, hostname, qtype, timeout).await,
        Transport::Dot { addr, tls_name } => probe_dot(*addr, tls_name, hostname, qtype, timeout).await,
        Transport::Doh { url } => probe_doh(url, hostname, qtype, timeout).await,
    }
}

// --- shared helpers ---

fn build_query(hostname: &str, qtype: RecordType) -> Result<(u16, Vec<u8>), ProbeError> {
    let name = Name::from_str(hostname).map_err(|e| ProbeError::BadName(e.to_string()))?;
    let id = next_id();
    let mut msg = Message::new();
    msg.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(name, qtype));
    let bytes = msg.to_bytes().map_err(|e| ProbeError::Encode(e.to_string()))?;
    Ok((id, bytes))
}

fn decode_response(bytes: &[u8], expected_id: u16) -> Result<ProbeOutcome, ProbeError> {
    // RTT is filled in by the caller — we only parse here.
    let resp = Message::from_bytes(bytes).map_err(|e| ProbeError::Decode(e.to_string()))?;
    if resp.id() != expected_id {
        return Err(ProbeError::IdMismatch { sent: expected_id, got: resp.id() });
    }
    let first_answer = resp.answers().first().map(|r| r.to_string());
    Ok(ProbeOutcome {
        rtt: Duration::ZERO,
        rcode: resp.response_code(),
        answer_count: resp.answers().len(),
        first_answer,
    })
}

// --- DoT ---

fn tls_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            // Install ring as the process-wide default crypto provider exactly once.
            // Safe to call multiple times; subsequent calls are no-ops.
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

async fn probe_dot(
    addr: IpAddr,
    tls_name: &str,
    hostname: &str,
    qtype: RecordType,
    rtt_timeout: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    let (id, query) = build_query(hostname, qtype)?;

    let server_name = ServerName::try_from(tls_name.to_owned())
        .map_err(|e| ProbeError::BadName(format!("invalid TLS name {}: {}", tls_name, e)))?;
    let connector = TlsConnector::from(tls_client_config());

    let start = Instant::now();
    let work = async move {
        let tcp = TcpStream::connect((addr, 853)).await?;
        tcp.set_nodelay(true)?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(std::io::Error::other)?;

        let len = (query.len() as u16).to_be_bytes();
        tls.write_all(&len).await?;
        tls.write_all(&query).await?;
        tls.flush().await?;

        let mut len_buf = [0u8; 2];
        tls.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        tls.read_exact(&mut resp_buf).await?;

        Ok::<Vec<u8>, std::io::Error>(resp_buf)
    };

    let resp_buf = tokio::time::timeout(rtt_timeout, work)
        .await
        .map_err(|_| ProbeError::Timeout(rtt_timeout))??;
    let rtt = start.elapsed();

    let mut outcome = decode_response(&resp_buf, id)?;
    outcome.rtt = rtt;
    Ok(outcome)
}

// --- DoH ---

fn doh_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        // Share the same ring provider as DoT.
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder()
            .pool_max_idle_per_host(4)
            .http2_prior_knowledge()
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

async fn probe_doh(
    url: &str,
    hostname: &str,
    qtype: RecordType,
    rtt_timeout: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    let (id, query) = build_query(hostname, qtype)?;
    let client = doh_client();

    let start = Instant::now();
    let work = async {
        let resp = client
            .post(url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query)
            .send()
            .await
            .map_err(std::io::Error::other)?;

        if !resp.status().is_success() {
            return Err(std::io::Error::other(format!("HTTP {}", resp.status())));
        }
        resp.bytes().await.map_err(std::io::Error::other)
    };

    let body = tokio::time::timeout(rtt_timeout, work)
        .await
        .map_err(|_| ProbeError::Timeout(rtt_timeout))??;
    let rtt = start.elapsed();

    let mut outcome = decode_response(&body, id)?;
    outcome.rtt = rtt;
    Ok(outcome)
}
