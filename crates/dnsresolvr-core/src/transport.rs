//! Transport abstractions and probes for UDP, DoT, DoH, DoH3 and DoQ.
//!
//! All transports share the same DNS wire format; only the carrier differs.
//! Encrypted transports are driven through a [`Session`], which keeps one
//! connection open per endpoint so that the timed section of a probe covers
//! the query/response exchange only. Connection setup is measured separately
//! by the benchmark (see `bench.rs`), which makes rows comparable across
//! transports. UDP has no connection and uses a fresh socket per query.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use hickory_proto::rr::RecordType;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::probe::{build_query, decode_response, next_id, probe_udp_at, ProbeError, ProbeOutcome};

const DNS_MESSAGE: &str = "application/dns-message";

/// The transport + address of a single benchmarkable endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Transport {
    /// Classic DNS over UDP (port 53 unless the resolver says otherwise).
    Udp { addr: IpAddr, port: u16 },
    /// DNS-over-TLS (RFC 7858). `tls_name` is the SNI / cert name.
    Dot { addr: IpAddr, port: u16, tls_name: String },
    /// DNS-over-HTTPS (RFC 8484) over HTTP/2.
    Doh { url: String },
    /// DNS-over-HTTPS over HTTP/3 (QUIC). Same URL as `Doh`, no fallback.
    Doh3 { url: String },
    /// DNS-over-QUIC (RFC 9250).
    Doq { addr: IpAddr, port: u16, tls_name: String },
}

impl Transport {
    pub fn kind(&self) -> TransportKind {
        match self {
            Transport::Udp { .. } => TransportKind::Udp,
            Transport::Dot { .. } => TransportKind::Dot,
            Transport::Doh { .. } => TransportKind::Doh,
            Transport::Doh3 { .. } => TransportKind::Doh3,
            Transport::Doq { .. } => TransportKind::Doq,
        }
    }

    /// Short human-readable address: `1.1.1.1`, `1.1.1.1 (cloudflare-dns.com)`,
    /// or `https://cloudflare-dns.com/dns-query`. Non-default ports are shown.
    pub fn display_addr(&self) -> String {
        let with_port = |addr: &IpAddr, port: u16, default: u16| {
            if port == default {
                addr.to_string()
            } else {
                SocketAddr::new(*addr, port).to_string()
            }
        };
        match self {
            Transport::Udp { addr, port } => with_port(addr, *port, 53),
            Transport::Dot { addr, port, tls_name } | Transport::Doq { addr, port, tls_name } => {
                format!("{} ({})", with_port(addr, *port, 853), tls_name)
            }
            Transport::Doh { url } | Transport::Doh3 { url } => url.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Udp,
    Dot,
    Doh,
    Doh3,
    Doq,
}

impl TransportKind {
    pub const ALL: [TransportKind; 5] = [
        TransportKind::Udp,
        TransportKind::Dot,
        TransportKind::Doh,
        TransportKind::Doh3,
        TransportKind::Doq,
    ];

    pub fn label(self) -> &'static str {
        match self {
            TransportKind::Udp => "UDP",
            TransportKind::Dot => "DoT",
            TransportKind::Doh => "DoH",
            TransportKind::Doh3 => "DoH3",
            TransportKind::Doq => "DoQ",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "udp" => Some(TransportKind::Udp),
            "dot" | "tls" => Some(TransportKind::Dot),
            "doh" | "https" => Some(TransportKind::Doh),
            "doh3" | "h3" => Some(TransportKind::Doh3),
            "doq" | "quic" => Some(TransportKind::Doq),
            _ => None,
        }
    }

    /// True for transports that keep a connection open between queries.
    pub fn is_connection_oriented(self) -> bool {
        !matches!(self, TransportKind::Udp)
    }
}

/// One-shot probe: opens a fresh session, sends a single query and drops it.
/// For encrypted transports the returned RTT covers the exchange only, not
/// the handshake. Use a [`Session`] directly to send several queries.
pub async fn probe(
    transport: &Transport,
    hostname: &str,
    qtype: RecordType,
    timeout: Duration,
) -> Result<ProbeOutcome, ProbeError> {
    let mut session = Session::new(transport.clone());
    session.prepare().await?;
    session.query(hostname, qtype, timeout).await
}

// --- TLS configuration ---

fn ensure_crypto_provider() {
    // Install ring as the process-wide default crypto provider exactly once.
    // Safe to call multiple times; subsequent calls are no-ops.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn build_tls_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    ensure_crypto_provider();
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

fn dot_tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| build_tls_config(&[])).clone()
}

fn h2_tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| build_tls_config(&[b"h2"])).clone()
}

fn quic_client_config(alpn: &'static [u8]) -> io::Result<quinn::ClientConfig> {
    static DOQ: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static H3: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    let tls = if alpn == b"doq" {
        DOQ.get_or_init(|| build_tls_config(&[b"doq"])).clone()
    } else {
        H3.get_or_init(|| build_tls_config(&[b"h3"])).clone()
    };
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(to_io)?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

// --- session ---

struct QuicLink {
    // The endpoint owns the UDP socket; it must outlive the connection.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
}

impl Drop for QuicLink {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"");
    }
}

struct H2Link {
    sender: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<()>,
}

impl Drop for H2Link {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

struct H3Link {
    quic: QuicLink,
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: JoinHandle<()>,
}

impl Drop for H3Link {
    fn drop(&mut self) {
        self.driver.abort();
        let _ = &self.quic;
    }
}

/// Host + pre-resolved socket address of a DoH endpoint. Resolving the host
/// once up front keeps the system resolver out of the timed section.
#[derive(Clone)]
struct Pinned {
    host: String,
    addr: SocketAddr,
}

enum State {
    Udp,
    Dot { stream: Option<Box<TlsStream<TcpStream>>> },
    Doh { pinned: Option<Pinned>, link: Option<H2Link> },
    Doh3 { pinned: Option<Pinned>, link: Option<H3Link> },
    Doq { link: Option<QuicLink> },
}

/// A reusable connection to one endpoint.
pub struct Session {
    transport: Transport,
    state: State,
    /// True once a query has succeeded on the current connection.
    warm: bool,
}

impl Session {
    pub fn new(transport: Transport) -> Self {
        let state = match &transport {
            Transport::Udp { .. } => State::Udp,
            Transport::Dot { .. } => State::Dot { stream: None },
            Transport::Doh { .. } => State::Doh { pinned: None, link: None },
            Transport::Doh3 { .. } => State::Doh3 { pinned: None, link: None },
            Transport::Doq { .. } => State::Doq { link: None },
        };
        Self { transport, state, warm: false }
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Untimed bootstrap work: resolves the DoH hostname once so later
    /// connects go straight to a fixed address.
    pub async fn prepare(&mut self) -> Result<(), ProbeError> {
        let url = match &self.transport {
            Transport::Doh { url } | Transport::Doh3 { url } => url.clone(),
            _ => return Ok(()),
        };
        let resolved = resolve_url_host(&url).await?;
        match &mut self.state {
            State::Doh { pinned, .. } | State::Doh3 { pinned, .. } => *pinned = Some(resolved),
            _ => {}
        }
        Ok(())
    }

    /// Drop the current connection. The next query opens a new one.
    pub fn reset(&mut self) {
        self.warm = false;
        match &mut self.state {
            State::Udp => {}
            State::Dot { stream } => *stream = None,
            State::Doh { link, .. } => *link = None,
            State::Doh3 { link, .. } => *link = None,
            State::Doq { link } => *link = None,
        }
    }

    /// Make sure a connection is open; a no-op if one already is.
    pub async fn connect(&mut self, timeout: Duration) -> Result<(), ProbeError> {
        let needs_pin = matches!(
            &self.state,
            State::Doh { pinned: None, .. } | State::Doh3 { pinned: None, .. }
        );
        if needs_pin {
            self.prepare().await?;
        }
        let work = async {
            match (&self.transport, &mut self.state) {
                (Transport::Dot { addr, port, tls_name }, State::Dot { stream }) if stream.is_none() => {
                    *stream = Some(Box::new(connect_dot(*addr, *port, tls_name).await?));
                }
                (Transport::Doh { .. }, State::Doh { pinned, link }) if link.is_none() => {
                    let pinned = pinned.as_ref().ok_or_else(|| to_io("DoH host not resolved"))?;
                    *link = Some(connect_h2(pinned).await?);
                }
                (Transport::Doh3 { .. }, State::Doh3 { pinned, link }) if link.is_none() => {
                    let pinned = pinned.as_ref().ok_or_else(|| to_io("DoH3 host not resolved"))?;
                    *link = Some(connect_h3(pinned).await?);
                }
                (Transport::Doq { addr, port, tls_name }, State::Doq { link }) if link.is_none() => {
                    let target = SocketAddr::new(*addr, *port);
                    *link = Some(connect_quic(target, tls_name, b"doq").await?);
                }
                _ => {}
            }
            Ok::<(), io::Error>(())
        };
        tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| ProbeError::Timeout(timeout))?
            .map_err(ProbeError::Io)
    }

    /// Send one query and time the exchange. The handshake is not part of the
    /// returned RTT.
    pub async fn query(
        &mut self,
        hostname: &str,
        qtype: RecordType,
        rtt_timeout: Duration,
    ) -> Result<ProbeOutcome, ProbeError> {
        if let Transport::Udp { addr, port } = &self.transport {
            return probe_udp_at(SocketAddr::new(*addr, *port), hostname, qtype, rtt_timeout).await;
        }

        // RFC 8484 and RFC 9250 ask for transaction id 0 on DoH and DoQ.
        let id = match self.transport.kind() {
            TransportKind::Dot => next_id(),
            _ => 0,
        };
        let wire = build_query(hostname, qtype, id)?;

        let mut retried = false;
        loop {
            let was_warm = self.warm;
            self.connect(rtt_timeout).await?;

            let start = Instant::now();
            match tokio::time::timeout(rtt_timeout, self.exchange(&wire)).await {
                Ok(Ok(bytes)) => {
                    let rtt = start.elapsed();
                    self.warm = true;
                    return decode_response(&bytes, id, rtt);
                }
                Ok(Err(e)) => {
                    self.reset();
                    // A server may close an idle connection between queries.
                    // Reconnect once and repeat so that does not count as a failure.
                    if was_warm && !retried {
                        retried = true;
                        continue;
                    }
                    return Err(ProbeError::Io(e));
                }
                Err(_) => {
                    // A late reply would be mistaken for the next answer.
                    self.reset();
                    return Err(ProbeError::Timeout(rtt_timeout));
                }
            }
        }
    }

    async fn exchange(&mut self, wire: &[u8]) -> io::Result<Vec<u8>> {
        match (&self.transport, &mut self.state) {
            (Transport::Dot { .. }, State::Dot { stream: Some(tls) }) => {
                let mut framed = Vec::with_capacity(wire.len() + 2);
                framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
                framed.extend_from_slice(wire);
                tls.write_all(&framed).await?;
                tls.flush().await?;

                let mut len_buf = [0u8; 2];
                tls.read_exact(&mut len_buf).await?;
                let mut resp = vec![0u8; u16::from_be_bytes(len_buf) as usize];
                tls.read_exact(&mut resp).await?;
                Ok(resp)
            }
            (Transport::Doh { url }, State::Doh { link: Some(link), .. }) => {
                let req = doh_request(url, wire.len())?;
                let mut sender = link.sender.clone().ready().await.map_err(to_io)?;
                let (response, mut stream) = sender.send_request(req, false).map_err(to_io)?;
                stream.send_data(Bytes::copy_from_slice(wire), true).map_err(to_io)?;

                let resp = response.await.map_err(to_io)?;
                if !resp.status().is_success() {
                    return Err(to_io(format!("HTTP {}", resp.status())));
                }
                let mut body = resp.into_body();
                let mut out = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.map_err(to_io)?;
                    out.extend_from_slice(&chunk);
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
                Ok(out)
            }
            (Transport::Doh3 { url }, State::Doh3 { link: Some(link), .. }) => {
                let req = doh_request(url, wire.len())?;
                let mut stream = link.sender.send_request(req).await.map_err(to_io)?;
                stream.send_data(Bytes::copy_from_slice(wire)).await.map_err(to_io)?;
                stream.finish().await.map_err(to_io)?;

                let resp = stream.recv_response().await.map_err(to_io)?;
                if !resp.status().is_success() {
                    return Err(to_io(format!("HTTP {}", resp.status())));
                }
                let mut body = Vec::new();
                while let Some(mut chunk) = stream.recv_data().await.map_err(to_io)? {
                    while chunk.has_remaining() {
                        let part = chunk.chunk();
                        let n = part.len();
                        body.extend_from_slice(part);
                        chunk.advance(n);
                    }
                }
                Ok(body)
            }
            (Transport::Doq { .. }, State::Doq { link: Some(link) }) => {
                // One bidirectional stream per query, 2-byte length prefix.
                let (mut send, mut recv) = link.conn.open_bi().await.map_err(to_io)?;
                let mut framed = Vec::with_capacity(wire.len() + 2);
                framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
                framed.extend_from_slice(wire);
                send.write_all(&framed).await.map_err(to_io)?;
                send.finish().map_err(to_io)?;

                let data = recv.read_to_end(u16::MAX as usize + 2).await.map_err(to_io)?;
                if data.len() < 2 {
                    return Err(to_io("short DoQ response"));
                }
                let len = u16::from_be_bytes([data[0], data[1]]) as usize;
                data.get(2..2 + len)
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| to_io("truncated DoQ response"))
            }
            _ => Err(to_io("not connected")),
        }
    }
}

// --- connection setup helpers ---

/// RFC 8484 POST request head; the DNS message goes in the body.
fn doh_request(url: &str, body_len: usize) -> io::Result<http::Request<()>> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header("content-type", DNS_MESSAGE)
        .header("accept", DNS_MESSAGE)
        .header("content-length", body_len)
        .body(())
        .map_err(to_io)
}

async fn resolve_url_host(raw: &str) -> Result<Pinned, ProbeError> {
    let uri: http::Uri = raw.parse().map_err(|e| ProbeError::BadName(format!("{}: {}", raw, e)))?;
    if uri.scheme_str() != Some("https") {
        return Err(ProbeError::BadName(format!("{}: DoH needs an https:// URL", raw)));
    }
    let host = uri
        .host()
        .ok_or_else(|| ProbeError::BadName(format!("{}: no host", raw)))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let port = uri.port_u16().unwrap_or(443);

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port)).await?.collect();
    // Prefer IPv4 so results line up with the default (v4) endpoint set.
    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| ProbeError::Io(to_io(format!("{} did not resolve", host))))?;
    Ok(Pinned { host, addr })
}

async fn connect_dot(addr: IpAddr, port: u16, tls_name: &str) -> io::Result<TlsStream<TcpStream>> {
    let server_name = ServerName::try_from(tls_name.to_owned())
        .map_err(|e| to_io(format!("invalid TLS name {}: {}", tls_name, e)))?;
    let tcp = TcpStream::connect((addr, port)).await?;
    tcp.set_nodelay(true)?;
    TlsConnector::from(dot_tls_config()).connect(server_name, tcp).await
}

async fn connect_h2(pinned: &Pinned) -> io::Result<H2Link> {
    let server_name = ServerName::try_from(pinned.host.clone())
        .map_err(|e| to_io(format!("invalid TLS name {}: {}", pinned.host, e)))?;
    let tcp = TcpStream::connect(pinned.addr).await?;
    tcp.set_nodelay(true)?;
    let tls = TlsConnector::from(h2_tls_config()).connect(server_name, tcp).await?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err(to_io("server does not offer HTTP/2"));
    }
    let (sender, connection) = h2::client::handshake(tls).await.map_err(to_io)?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(H2Link { sender, driver })
}

async fn connect_quic(target: SocketAddr, tls_name: &str, alpn: &'static [u8]) -> io::Result<QuicLink> {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(quic_client_config(alpn)?);
    let conn = endpoint.connect(target, tls_name).map_err(to_io)?.await.map_err(to_io)?;
    Ok(QuicLink { _endpoint: endpoint, conn })
}

async fn connect_h3(pinned: &Pinned) -> io::Result<H3Link> {
    let quic = connect_quic(pinned.addr, &pinned.host, b"h3").await?;
    let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(quic.conn.clone()))
        .await
        .map_err(to_io)?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    Ok(H3Link { quic, sender, driver })
}
