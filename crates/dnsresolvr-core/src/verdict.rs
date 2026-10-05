//! Turns a table of endpoint reports into a short recommendation.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::bench::EndpointReport;
use crate::stats::Summary;
use crate::transport::TransportKind;

/// Share of the cached median in the blended score. A resolver mostly answers
/// from cache, so cached latency dominates; the rest is the uncached median.
pub const CACHED_WEIGHT: f64 = 0.75;

/// Endpoints below this reliability in any class are not recommended.
pub const MIN_RELIABILITY: f64 = 0.97;

/// One recommendation, e.g. "Fastest unfiltered" -> Cloudflare over DoT.
#[derive(Debug, Clone, PartialEq)]
pub struct Pick {
    pub label: String,
    pub resolver: String,
    pub transport: TransportKind,
    pub addr: String,
    pub cached_p50: Option<Duration>,
    pub uncached_p50: Option<Duration>,
    /// Position among all recommendable endpoints (1 = fastest). `None` if
    /// the endpoint itself is not recommendable.
    pub rank: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub picks: Vec<Pick>,
    /// Number of endpoints that were ranked.
    pub ranked: usize,
    pub notes: Vec<String>,
}

fn median(s: &Option<Summary>) -> Option<Duration> {
    s.as_ref().filter(|s| s.has_samples()).map(|s| s.p50)
}

/// Blended latency used for ranking, or `None` if the endpoint should not be
/// recommended: no successful samples, or too unreliable.
pub fn blended_score(r: &EndpointReport) -> Option<Duration> {
    let classes = [&r.cached, &r.uncached];
    if classes.iter().flat_map(|c| c.iter()).any(|s| s.reliability() < MIN_RELIABILITY) {
        return None;
    }
    match (median(&r.cached), median(&r.uncached)) {
        (Some(c), Some(u)) => Some(c.mul_f64(CACHED_WEIGHT) + u.mul_f64(1.0 - CACHED_WEIGHT)),
        (Some(c), None) if r.uncached.is_none() => Some(c),
        (None, Some(u)) if r.cached.is_none() => Some(u),
        _ => None,
    }
}

/// The IP an endpoint talks to, when its address is IP-based (UDP, DoT, DoQ).
fn endpoint_ip(r: &EndpointReport) -> Option<IpAddr> {
    let first = r.addr_display.split_whitespace().next()?;
    first
        .parse::<IpAddr>()
        .ok()
        .or_else(|| first.parse::<SocketAddr>().ok().map(|s| s.ip()))
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        // fc00::/7 unique local, fe80::/10 link local
        IpAddr::V6(a) => {
            a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Build the recommendation. `system` is the list of DNS servers this machine
/// is configured to use; endpoints at those addresses, and any on a private
/// network, are reported as "your resolver" and kept out of the public picks.
pub fn verdict(reports: &[EndpointReport], system: &[IpAddr]) -> Verdict {
    let is_own = |r: &EndpointReport| endpoint_ip(r).is_some_and(|ip| is_private(ip) || system.contains(&ip));

    let mut ranked: Vec<(Duration, &EndpointReport)> =
        reports.iter().filter_map(|r| blended_score(r).map(|s| (s, r))).collect();
    ranked.sort_by_key(|(s, _)| *s);
    let rank_of = |r: &EndpointReport| ranked.iter().position(|(_, x)| std::ptr::eq(*x, r)).map(|i| i + 1);

    let pick = |label: &str, r: &EndpointReport| Pick {
        label: label.to_string(),
        resolver: r.resolver.clone(),
        transport: r.transport_kind,
        addr: r.addr_display.clone(),
        cached_p50: median(&r.cached),
        uncached_p50: median(&r.uncached),
        rank: rank_of(r),
    };
    let best = |label: &str, keep: &dyn Fn(&EndpointReport) -> bool| {
        ranked
            .iter()
            .map(|(_, r)| *r)
            .find(|r| !is_own(r) && keep(r))
            .map(|r| pick(label, r))
    };
    let blocks = |r: &EndpointReport, what: &str| {
        r.filtering.as_deref().is_some_and(|f| f.split('+').any(|t| t.eq_ignore_ascii_case(what)))
    };
    let encrypted = |r: &EndpointReport| r.transport_kind != TransportKind::Udp;

    let mut picks = Vec::new();
    picks.extend(best("Fastest unfiltered", &|r| r.filtering.is_none()));
    picks.extend(best("Fastest unfiltered, encrypted", &|r| r.filtering.is_none() && encrypted(r)));
    picks.extend(best("Fastest with malware blocking", &|r| blocks(r, "malware")));
    picks.extend(best("Fastest with ad blocking", &|r| blocks(r, "ads")));
    picks.extend(best("Fastest family filter", &|r| blocks(r, "adult")));
    for r in reports.iter().filter(|r| is_own(r)) {
        picks.push(pick("Your resolver", r));
    }

    let mut notes = Vec::new();
    let unreachable = reports
        .iter()
        .filter(|r| {
            let dead = |s: &Option<Summary>| s.as_ref().is_some_and(|s| !s.has_samples());
            (r.cached.is_some() || r.uncached.is_some())
                && (r.cached.is_none() || dead(&r.cached))
                && (r.uncached.is_none() || dead(&r.uncached))
        })
        .count();
    if unreachable > 0 {
        notes.push(format!("{} endpoint(s) did not answer at all", unreachable));
    }
    let unreliable = reports.len() - ranked.len() - unreachable;
    if unreliable > 0 {
        notes.push(format!(
            "{} endpoint(s) left out for reliability below {:.0}%",
            unreliable,
            MIN_RELIABILITY * 100.0
        ));
    }
    let mut no_dnssec: Vec<&str> = reports
        .iter()
        .filter(|r| r.dnssec == Some(false))
        .map(|r| r.resolver.as_str())
        .collect();
    no_dnssec.dedup();
    if !no_dnssec.is_empty() {
        notes.push(format!("no DNSSEC validation: {}", no_dnssec.join(", ")));
    }
    // Some resolvers send a substitute subnet instead of yours, so show which.
    let mut ecs: Vec<String> = Vec::new();
    for r in reports {
        let Some(p) = r.privacy.as_ref().filter(|p| p.ecs_sent == Some(true)) else { continue };
        let entry = match &p.ecs_subnet {
            Some(subnet) => format!("{} ({})", r.resolver, subnet),
            None => r.resolver.clone(),
        };
        if !ecs.contains(&entry) {
            ecs.push(entry);
        }
    }
    if !ecs.is_empty() {
        notes.push(format!("sends a client subnet with lookups (ECS): {}", ecs.join(", ")));
    }
    // For the user's own resolver, say who actually does the resolving.
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for r in reports.iter().filter(|r| is_own(r)) {
        let Some(exit) = r.privacy.as_ref().and_then(|p| p.exit_as.as_deref()) else { continue };
        if !seen.contains(&(r.resolver.as_str(), exit)) {
            seen.push((r.resolver.as_str(), exit));
            notes.push(format!("{} resolves through {}", r.resolver, exit));
        }
    }

    Verdict { picks, ranked: ranked.len(), notes }
}

impl Verdict {
    /// Plain-text rendering, one line per pick followed by the notes.
    pub fn lines(&self) -> Vec<String> {
        let ms = |d: Option<Duration>| match d {
            Some(d) => format!("{:.1}", d.as_secs_f64() * 1000.0),
            None => "—".to_string(),
        };
        let mut out = Vec::new();
        for p in &self.picks {
            let rank = match p.rank {
                Some(n) => format!("rank {} of {}", n, self.ranked),
                None => "not ranked (unreliable or unreachable)".to_string(),
            };
            out.push(format!(
                "{:<30} {:<22} {:<4}  cached {:>5} ms · uncached {:>5} ms · {}",
                p.label,
                p.resolver,
                p.transport.label(),
                ms(p.cached_p50),
                ms(p.uncached_p50),
                rank,
            ));
        }
        if self.picks.is_empty() {
            out.push("no endpoint was reliable enough to recommend".to_string());
        }
        for n in &self.notes {
            out.push(format!("note: {}", n));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::summarize;

    fn class(ms: u64, ok: usize, total: usize) -> Option<Summary> {
        summarize(vec![Duration::from_millis(ms); ok], total)
    }

    fn ep(name: &str, kind: TransportKind, addr: &str, filtering: Option<&str>, c: u64, u: u64) -> EndpointReport {
        EndpointReport {
            resolver: name.into(),
            provider: String::new(),
            filtering: filtering.map(String::from),
            transport_kind: kind,
            addr_display: addr.into(),
            setup: None,
            dnssec: Some(true),
            privacy: None,
            cached: class(c, 10, 10),
            uncached: class(u, 10, 10),
        }
    }

    fn find<'a>(v: &'a Verdict, label: &str) -> &'a Pick {
        v.picks.iter().find(|p| p.label == label).unwrap_or_else(|| panic!("no pick {}", label))
    }

    #[test]
    fn picks_per_category() {
        let reports = vec![
            ep("Plain", TransportKind::Udp, "1.1.1.1", None, 4, 10),
            ep("PlainTls", TransportKind::Dot, "1.1.1.1 (x)", None, 5, 10),
            ep("Guard", TransportKind::Udp, "9.9.9.9", Some("malware"), 12, 15),
            ep("Family", TransportKind::Doh, "https://f/dns-query", Some("malware+adult"), 20, 30),
            ep("Ads", TransportKind::Udp, "94.140.14.14", Some("ads"), 6, 9),
            ep("Home", TransportKind::Udp, "192.168.1.2", Some("ads"), 1, 13),
        ];
        let v = verdict(&reports, &[]);
        assert_eq!(v.ranked, 6);
        assert_eq!(find(&v, "Fastest unfiltered").resolver, "Plain");
        assert_eq!(find(&v, "Fastest unfiltered, encrypted").resolver, "PlainTls");
        assert_eq!(find(&v, "Fastest with malware blocking").resolver, "Guard");
        assert_eq!(find(&v, "Fastest family filter").resolver, "Family");
        // The LAN resolver is faster but must not win a public category.
        assert_eq!(find(&v, "Fastest with ad blocking").resolver, "Ads");
        let home = find(&v, "Your resolver");
        assert_eq!((home.resolver.as_str(), home.rank), ("Home", Some(1)));
    }

    #[test]
    fn blend_weights_cached_higher() {
        // 0.75*4 + 0.25*40 = 13ms beats 0.75*14 + 0.25*14 = 14ms
        let a = ep("A", TransportKind::Udp, "1.1.1.1", None, 4, 40);
        let b = ep("B", TransportKind::Udp, "8.8.8.8", None, 14, 14);
        assert_eq!(blended_score(&a), Some(Duration::from_millis(13)));
        let v = verdict(&[b, a], &[]);
        assert_eq!(find(&v, "Fastest unfiltered").resolver, "A");
    }

    #[test]
    fn unreliable_and_dead_endpoints_are_not_recommended() {
        let mut flaky = ep("Flaky", TransportKind::Udp, "1.1.1.1", None, 1, 1);
        flaky.uncached = class(1, 9, 10);
        let mut dead = ep("Dead", TransportKind::Udp, "2.2.2.2", None, 1, 1);
        dead.cached = class(1, 0, 10);
        dead.uncached = class(1, 0, 10);
        let mut lax = ep("Solid", TransportKind::Udp, "8.8.8.8", None, 30, 30);
        lax.dnssec = Some(false);

        let v = verdict(&[flaky, dead, lax], &[]);
        assert_eq!(v.ranked, 1);
        assert_eq!(find(&v, "Fastest unfiltered").resolver, "Solid");
        assert!(v.notes.iter().any(|n| n.starts_with("1 endpoint(s) did not answer")));
        assert!(v.notes.iter().any(|n| n.starts_with("1 endpoint(s) left out")));
        assert!(v.notes.iter().any(|n| n == "no DNSSEC validation: Solid"));
    }

    #[test]
    fn system_resolver_on_public_ip_counts_as_own() {
        let reports = vec![
            ep("ISP", TransportKind::Udp, "194.25.0.60", None, 3, 9),
            ep("Other", TransportKind::Udp, "1.1.1.1", None, 5, 9),
        ];
        let v = verdict(&reports, &["194.25.0.60".parse().unwrap()]);
        assert_eq!(find(&v, "Fastest unfiltered").resolver, "Other");
        assert_eq!(find(&v, "Your resolver").resolver, "ISP");
    }

    #[test]
    fn privacy_notes() {
        use crate::privacy::PrivacyInfo;
        let mut leaky = ep("Leaky", TransportKind::Udp, "8.8.8.8", None, 5, 9);
        leaky.privacy = Some(PrivacyInfo {
            ecs_sent: Some(true),
            ecs_subnet: Some("192.0.2.0/24".into()),
            ..PrivacyInfo::default()
        });
        let mut home = ep("Home", TransportKind::Udp, "192.168.1.2", None, 1, 12);
        home.privacy = Some(PrivacyInfo {
            exit_as: Some("AS13335 CLOUDFLARENET".into()),
            ecs_sent: Some(false),
            ..PrivacyInfo::default()
        });
        let v = verdict(&[leaky, home], &[]);
        assert!(v.notes.iter().any(|n| n.ends_with("(ECS): Leaky (192.0.2.0/24)")));
        assert!(v.notes.iter().any(|n| n == "Home resolves through AS13335 CLOUDFLARENET"));
    }

    #[test]
    fn single_class_runs_still_rank() {
        let mut r = ep("A", TransportKind::Udp, "1.1.1.1", None, 7, 0);
        r.uncached = None;
        assert_eq!(blended_score(&r), Some(Duration::from_millis(7)));
    }
}
