use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

use crate::transport::Transport;

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolver {
    pub name: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub ipv4: Vec<IpAddr>,
    #[serde(default)]
    pub ipv6: Vec<IpAddr>,
    /// False for services that only offer encrypted transports.
    #[serde(default = "yes", skip_serializing_if = "Clone::clone")]
    pub plain: bool,
    /// Addresses of the DoT / DoQ endpoint, if they differ from `ipv4`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dot_ipv4: Vec<IpAddr>,
    /// Plain DNS port, if not 53 (handy for LAN resolvers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// TLS SNI / certificate hostname. Present if the operator publishes a DoT
    /// endpoint at the addresses above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dot_hostname: Option<String>,
    /// DoT port, if not 853.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dot_port: Option<u16>,
    /// DoH endpoint URL (e.g. `https://cloudflare-dns.com/dns-query`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_url: Option<String>,
    /// True if `doh_url` is also served over HTTP/3.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub doh3: bool,
    /// Certificate hostname of the DoQ endpoint at the addresses above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doq_hostname: Option<String>,
    /// DoQ port, if not 853.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doq_port: Option<u16>,
    /// What the resolver blocks, if anything: `malware`, `family`, `ads`, ...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filtering: Option<String>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self {
            name: String::new(),
            provider: String::new(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            plain: true,
            dot_ipv4: Vec::new(),
            port: None,
            dot_hostname: None,
            dot_port: None,
            doh_url: None,
            doh3: false,
            doq_hostname: None,
            doq_port: None,
            filtering: None,
        }
    }
}

impl Resolver {
    /// Primary address, IPv4 preferred, IPv6 fallback.
    pub fn primary_addr(&self) -> Option<IpAddr> {
        self.ipv4.first().copied().or_else(|| self.ipv6.first().copied())
    }

    pub fn all_addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.ipv4.iter().chain(self.ipv6.iter()).copied()
    }

    /// Enumerate the transport endpoints this resolver exposes: UDP per
    /// address (IPv4 first, then IPv6 if enabled), then DoT / DoQ per address,
    /// followed by the URL-based DoH / DoH3 endpoints. By default only the
    /// first address of each family is used; `all_addrs` includes the rest.
    pub fn transports(&self, include_ipv6: bool, all_addrs: bool) -> Vec<Transport> {
        let take = if all_addrs { usize::MAX } else { 1 };
        let v6_take = if include_ipv6 { take } else { 0 };
        let mut out = Vec::new();

        if self.plain {
            for &addr in self.ipv4.iter().take(take).chain(self.ipv6.iter().take(v6_take)) {
                out.push(Transport::Udp { addr, port: self.port.unwrap_or(53) });
            }
        }
        let secure_v4 = if self.dot_ipv4.is_empty() { &self.ipv4 } else { &self.dot_ipv4 };
        for &addr in secure_v4.iter().take(take).chain(self.ipv6.iter().take(v6_take)) {
            if let Some(name) = &self.dot_hostname {
                out.push(Transport::Dot {
                    addr,
                    port: self.dot_port.unwrap_or(853),
                    tls_name: name.clone(),
                });
            }
            if let Some(name) = &self.doq_hostname {
                out.push(Transport::Doq {
                    addr,
                    port: self.doq_port.unwrap_or(853),
                    tls_name: name.clone(),
                });
            }
        }
        if let Some(url) = &self.doh_url {
            out.push(Transport::Doh { url: url.clone() });
            if self.doh3 {
                out.push(Transport::Doh3 { url: url.clone() });
            }
        }
        out
    }

    /// Parse a command-line resolver spec:
    /// `NAME=ADDR[,ADDR...][,dot=HOST][,doq=HOST][,doh=URL][,doh3][,port=N][,filtering=TAG]`
    ///
    /// Example: `Home=192.168.1.2,doh=https://dns.example.net/dns-query`
    pub fn parse_spec(spec: &str) -> Result<Resolver, String> {
        let (name, rest) = spec
            .split_once('=')
            .ok_or_else(|| format!("{}: expected NAME=ADDR[,option...]", spec))?;
        let name = name.trim();
        if name.is_empty() {
            return Err(format!("{}: empty resolver name", spec));
        }
        let mut r = Resolver {
            name: name.to_string(),
            provider: "custom".to_string(),
            ..Resolver::default()
        };
        for tok in rest.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if let Ok(addr) = tok.parse::<IpAddr>() {
                if addr.is_ipv4() { r.ipv4.push(addr) } else { r.ipv6.push(addr) }
                continue;
            }
            if tok.eq_ignore_ascii_case("doh3") {
                r.doh3 = true;
                continue;
            }
            let (key, val) = tok
                .split_once('=')
                .ok_or_else(|| format!("{}: not an IP address or option: {}", spec, tok))?;
            let port = |v: &str| v.parse::<u16>().map_err(|_| format!("{}: bad port: {}", spec, v));
            match key.to_ascii_lowercase().as_str() {
                "dot" => r.dot_hostname = Some(val.to_string()),
                "doq" => r.doq_hostname = Some(val.to_string()),
                "doh" => r.doh_url = Some(val.to_string()),
                "port" => r.port = Some(port(val)?),
                "dot_port" => r.dot_port = Some(port(val)?),
                "doq_port" => r.doq_port = Some(port(val)?),
                "filtering" => r.filtering = Some(val.to_string()),
                "provider" => r.provider = val.to_string(),
                other => return Err(format!("{}: unknown option: {}", spec, other)),
            }
        }
        if r.primary_addr().is_none() && r.doh_url.is_none() {
            return Err(format!("{}: needs at least one IP address or doh=URL", spec));
        }
        Ok(r)
    }
}

const BUNDLED_JSON: &str = include_str!("resolvers.json");

/// Returns the bundled list of well-known public resolvers.
///
/// Panics only if the embedded JSON is malformed — caught at build time by tests.
pub fn bundled_resolvers() -> Vec<Resolver> {
    serde_json::from_str(BUNDLED_JSON).expect("bundled resolvers.json is malformed")
}

/// Load a resolver list from a JSON file in the same format as the bundled one.
pub fn load_resolvers_file(path: impl AsRef<Path>) -> std::io::Result<Vec<Resolver>> {
    let raw = std::fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(std::io::Error::other)
}

/// Append `extra` to `base`. An entry whose name is already present replaces
/// the existing one, so a user file can override bundled resolvers.
pub fn merge_resolvers(mut base: Vec<Resolver>, extra: Vec<Resolver>) -> Vec<Resolver> {
    for r in extra {
        match base.iter_mut().find(|b| b.name.eq_ignore_ascii_case(&r.name)) {
            Some(slot) => *slot = r,
            None => base.push(r),
        }
    }
    base
}

/// Add the operating system's configured DNS servers as `System (<ip>)`
/// entries, skipping addresses that are already in the list.
pub fn add_system_resolvers(mut list: Vec<Resolver>, system: &[IpAddr]) -> Vec<Resolver> {
    for &addr in system {
        if list.iter().any(|r| r.all_addrs().any(|a| a == addr)) {
            continue;
        }
        let mut r = Resolver {
            name: format!("System ({})", addr),
            provider: "system".to_string(),
            ..Resolver::default()
        };
        if addr.is_ipv4() { r.ipv4.push(addr) } else { r.ipv6.push(addr) }
        list.push(r);
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportKind;

    #[test]
    fn bundled_list_parses() {
        let list = bundled_resolvers();
        assert!(list.len() >= 10);
        assert!(list.iter().any(|r| r.name == "Cloudflare"));
        for r in &list {
            assert!(r.primary_addr().is_some(), "{} has no address", r.name);
        }
    }

    #[test]
    fn bundled_names_are_unique() {
        let list = bundled_resolvers();
        for (i, r) in list.iter().enumerate() {
            assert!(
                !list[..i].iter().any(|o| o.name.eq_ignore_ascii_case(&r.name)),
                "duplicate resolver name {}",
                r.name
            );
        }
    }

    #[test]
    fn spec_with_options() {
        let r = Resolver::parse_spec(
            "Home=192.168.1.2,fd00::2,dot=dns.example.net,doh=https://dns.example.net/dns-query,doh3,port=5353",
        )
        .unwrap();
        assert_eq!(r.name, "Home");
        assert_eq!(r.ipv4.len(), 1);
        assert_eq!(r.ipv6.len(), 1);
        assert_eq!(r.port, Some(5353));
        assert!(r.doh3);
        let kinds: Vec<_> = r.transports(false, false).iter().map(|t| t.kind()).collect();
        assert_eq!(
            kinds,
            [TransportKind::Udp, TransportKind::Dot, TransportKind::Doh, TransportKind::Doh3]
        );
    }

    #[test]
    fn encrypted_only_and_separate_dot_address() {
        let r: Resolver = serde_json::from_str(
            r#"{ "name": "X", "ipv4": ["192.0.2.1"], "plain": false,
                 "dot_ipv4": ["192.0.2.9"], "dot_hostname": "dot.example" }"#,
        )
        .unwrap();
        let t = r.transports(false, false);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].display_addr(), "192.0.2.9 (dot.example)");

        let plain: Resolver = serde_json::from_str(r#"{ "name": "Y", "ipv4": ["192.0.2.1"] }"#).unwrap();
        assert!(plain.plain);
    }

    #[test]
    fn spec_rejects_garbage() {
        assert!(Resolver::parse_spec("no-equals").is_err());
        assert!(Resolver::parse_spec("Home=").is_err());
        assert!(Resolver::parse_spec("Home=10.0.0.1,bogus=1").is_err());
        assert!(Resolver::parse_spec("Home=10.0.0.1,port=99999").is_err());
    }

    #[test]
    fn all_addrs_expands_secondaries() {
        let r = Resolver::parse_spec("X=1.1.1.1,1.0.0.1").unwrap();
        assert_eq!(r.transports(false, false).len(), 1);
        assert_eq!(r.transports(false, true).len(), 2);
    }

    #[test]
    fn merge_overrides_by_name_and_system_dedups() {
        let base = vec![Resolver::parse_spec("A=1.1.1.1").unwrap()];
        let merged = merge_resolvers(
            base,
            vec![Resolver::parse_spec("a=9.9.9.9").unwrap(), Resolver::parse_spec("B=8.8.8.8").unwrap()],
        );
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].ipv4[0].to_string(), "9.9.9.9");

        let with_sys = add_system_resolvers(merged, &["8.8.8.8".parse().unwrap(), "10.0.0.1".parse().unwrap()]);
        assert_eq!(with_sys.len(), 3);
        assert_eq!(with_sys[2].name, "System (10.0.0.1)");
    }
}
