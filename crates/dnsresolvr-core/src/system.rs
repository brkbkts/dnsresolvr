//! Discover the DNS servers the operating system is configured to use.

use std::net::IpAddr;

/// Returns the system's DNS servers in configuration order, without
/// duplicates. Loopback stubs (e.g. systemd-resolved's 127.0.0.53) and
/// link-local addresses are skipped. Empty if detection fails.
pub fn system_resolvers() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for addr in detect() {
        let link_local = match addr {
            IpAddr::V4(a) => a.is_link_local(),
            IpAddr::V6(a) => (a.segments()[0] & 0xffc0) == 0xfe80 || (a.segments()[0] & 0xffc0) == 0xfec0,
        };
        if addr.is_loopback() || addr.is_unspecified() || link_local || out.contains(&addr) {
            continue;
        }
        out.push(addr);
    }
    out
}

#[cfg(windows)]
fn detect() -> Vec<IpAddr> {
    // PowerShell output is locale-independent, unlike `ipconfig /all`.
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses }).ServerAddresses",
        ])
        .output();
    match output {
        Ok(o) => parse_lines(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Vec::new(),
    }
}

#[cfg(not(windows))]
fn detect() -> Vec<IpAddr> {
    match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(raw) => parse_resolv_conf(&raw),
        Err(_) => Vec::new(),
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn parse_lines(raw: &str) -> Vec<IpAddr> {
    raw.lines().filter_map(|l| l.trim().parse().ok()).collect()
}

#[cfg_attr(windows, allow(dead_code))]
fn parse_resolv_conf(raw: &str) -> Vec<IpAddr> {
    raw.lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            match (parts.next(), parts.next()) {
                // Strip an IPv6 zone id such as `fe80::1%eth0`.
                (Some("nameserver"), Some(addr)) => addr.split('%').next()?.parse().ok(),
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_nameservers() {
        let raw = "# comment\nsearch lan\nnameserver 192.168.1.2\nnameserver 2606:4700:4700::1111\noptions edns0\n";
        let got = parse_resolv_conf(raw);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].to_string(), "192.168.1.2");
    }

    #[test]
    fn plain_lines() {
        let got = parse_lines("192.168.1.2\r\n\r\nnot-an-ip\r\n1.1.1.1\r\n");
        assert_eq!(got.len(), 2);
    }
}
