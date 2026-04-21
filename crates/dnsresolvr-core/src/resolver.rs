use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolver {
    pub name: String,
    pub provider: String,
    #[serde(default)]
    pub ipv4: Vec<IpAddr>,
    #[serde(default)]
    pub ipv6: Vec<IpAddr>,
}

impl Resolver {
    /// Primary address, IPv4 preferred, IPv6 fallback.
    pub fn primary_addr(&self) -> Option<IpAddr> {
        self.ipv4.first().copied().or_else(|| self.ipv6.first().copied())
    }

    pub fn all_addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.ipv4.iter().chain(self.ipv6.iter()).copied()
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
