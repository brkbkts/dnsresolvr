use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("invalid domain name: {0}")]
    BadName(String),
    #[error("encode failed: {0}")]
    Encode(String),
    #[error("decode failed: {0}")]
    Decode(String),
    #[error("socket error: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out after {0:?}")]
    Timeout(Duration),
    #[error("transaction id mismatch (sent {sent}, got {got})")]
    IdMismatch { sent: u16, got: u16 },
}

#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub rtt: Duration,
    pub rcode: ResponseCode,
    pub answer_count: usize,
    pub first_answer: Option<String>,
    /// Record data of every answer, as text (TXT strings are unquoted).
    pub answers: Vec<String>,
}

static ID_COUNTER: AtomicU16 = AtomicU16::new(1);

pub(crate) fn next_id() -> u16 {
    // wrap around at 0 to avoid a 0 id which some resolvers treat oddly
    let v = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    if v == 0 {
        ID_COUNTER.fetch_add(1, Ordering::Relaxed)
    } else {
        v
    }
}

/// Encode a recursive query for `hostname` with the given transaction id.
pub(crate) fn build_query(hostname: &str, qtype: RecordType, id: u16) -> Result<Vec<u8>, ProbeError> {
    let name = Name::from_str(hostname).map_err(|e| ProbeError::BadName(e.to_string()))?;
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, qtype));
    msg.to_vec().map_err(|e| ProbeError::Encode(e.to_string()))
}

/// Parse a wire-format response and check it answers the query we sent.
pub(crate) fn decode_response(
    bytes: &[u8],
    expected_id: u16,
    rtt: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    let resp = Message::from_vec(bytes).map_err(|e| ProbeError::Decode(e.to_string()))?;
    if resp.metadata.id != expected_id {
        return Err(ProbeError::IdMismatch { sent: expected_id, got: resp.metadata.id });
    }
    let first_answer = resp.answers.first().map(|r| r.to_string());
    let answers = resp
        .answers
        .iter()
        .map(|r| match &r.data {
            RData::TXT(txt) => txt.txt_data.iter().map(|part| String::from_utf8_lossy(part)).collect(),
            other => other.to_string(),
        })
        .collect();
    Ok(ProbeOutcome {
        rtt,
        rcode: resp.metadata.response_code,
        answer_count: resp.answers.len(),
        first_answer,
        answers,
    })
}

/// Send one UDP/53 DNS query to `resolver` for `hostname` and time the round trip.
///
/// No retries, no caching, no fallback. Higher layers build policy on top
/// of single-shot measurements.
pub async fn probe_udp(
    resolver: IpAddr,
    hostname: &str,
    qtype: RecordType,
    rtt_timeout: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    probe_udp_at(SocketAddr::new(resolver, 53), hostname, qtype, rtt_timeout).await
}

/// Same as [`probe_udp`] but for a resolver on a non-standard port.
pub async fn probe_udp_at(
    resolver: SocketAddr,
    hostname: &str,
    qtype: RecordType,
    rtt_timeout: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    let id = next_id();
    let bytes = build_query(hostname, qtype, id)?;

    let bind_addr: SocketAddr = if resolver.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(resolver).await?;

    let start = Instant::now();
    sock.send(&bytes).await?;

    let mut buf = [0u8; 4096];
    let recv = timeout(rtt_timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| ProbeError::Timeout(rtt_timeout))??;
    let rtt = start.elapsed();

    decode_response(&buf[..recv], id, rtt)
}
