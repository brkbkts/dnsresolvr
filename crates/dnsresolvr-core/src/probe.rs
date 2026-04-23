use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
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
    let name = Name::from_str(hostname).map_err(|e| ProbeError::BadName(e.to_string()))?;

    let id = next_id();
    let mut msg = Message::new();
    msg.set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(name, qtype));

    let bytes = msg.to_bytes().map_err(|e| ProbeError::Encode(e.to_string()))?;

    let bind_addr: SocketAddr = if resolver.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(SocketAddr::new(resolver, 53)).await?;

    let start = Instant::now();
    sock.send(&bytes).await?;

    let mut buf = [0u8; 4096];
    let recv = timeout(rtt_timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| ProbeError::Timeout(rtt_timeout))??;
    let rtt = start.elapsed();

    let resp = Message::from_bytes(&buf[..recv]).map_err(|e| ProbeError::Decode(e.to_string()))?;
    if resp.id() != id {
        return Err(ProbeError::IdMismatch { sent: id, got: resp.id() });
    }

    let first_answer = resp.answers().first().map(|r| r.to_string());
    Ok(ProbeOutcome {
        rtt,
        rcode: resp.response_code(),
        answer_count: resp.answers().len(),
        first_answer,
    })
}
