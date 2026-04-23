use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::transport::Transport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolver {
    pub name: String,
    pub provider: String,
    #[serde(default)]
    pub ipv4: Vec<IpAddr>,
    #[serde(default)]
    pub ipv6: Vec<IpAddr>,
    /// TLS SNI / certificate hostname. Present if the operator publishes a DoT
    /// endpoint on the standard port (853) at the addresses above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dot_hostname: Option<String>,
    /// DoH endpoint URL (e.g. `https://cloudflare-dns.com/dns-query`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_url: Option<String>,
}

impl Resolver {
    /// Primary address, IPv4 preferred, IPv6 fallback.
    pub fn primary_addr(&self) -> Option<IpAddr> {
        self.ipv4.first().copied().or_else(|| self.ipv6.first().copied())
    }

    pub fn all_addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.ipv4.iter().chain(self.ipv6.iter()).copied()
    }

    /// Enumerate the transport endpoints this resolver exposes. IPv4 first,
    /// then IPv6 (if enabled), with UDP / DoT / DoH variants per address.
    pub fn transports(&self, include_ipv6: bool) -> Vec<Transport> {
        let mut out = Vec::new();
        let ipv4 = self.ipv4.first().copied();
        let ipv6 = if include_ipv6 { self.ipv6.first().copied() } else { None };

        for addr in ipv4.into_iter().chain(ipv6) {
            out.push(Transport::Udp { addr });
            if let Some(name) = &self.dot_hostname {
                out.push(Transport::Dot { addr, tls_name: name.clone() });
            }
        }
        if let Some(url) = &self.doh_url {
            out.push(Transport::Doh { url: url.clone() });
        }
        out
    }
}

const BUNDLED_JSON: &str = include_str!("resolvers.json");

/// Returns the bundled list of well-known public resolvers.
///
/// Panics only if the embedded JSON is malformed — caught at build time by tests.
pub fn bundled_resolvers() -> Vec<Resolver> {
    serde_json::from_str(BUNDLED_JSON).expect("bundled resolvers.json is malformed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_list_parses() {
        let list = bundled_resolvers();
        assert!(list.len() >= 10);
        assert!(list.iter().any(|r| r.name == "Cloudflare"));
        for r in &list {
            assert!(r.primary_addr().is_some(), "{} has no address", r.name);
        }
    }
}
