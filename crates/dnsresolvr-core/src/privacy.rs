//! Privacy checks: where a resolver's queries come out, and whether it tells
//! authoritative servers which network you are on.
//!
//! Both answers come from one TXT query for a name whose authoritative server
//! echoes what it saw: the address that contacted it (the resolver's *exit
//! server*) and, if present, the EDNS Client Subnet option (your /24 or /56).
//! The exit address is then mapped to its network operator through Team
//! Cymru's IP-to-ASN service, also over DNS.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::rr::RecordType;

use crate::transport::Session;

/// Google's authoritative servers answer this with the querying resolver's
/// address and any client subnet it passed along.
const ECHO_DOMAIN: &str = "o-o.myaddr.l.google.com";
/// Fallback that returns the resolver's address as an A record (IPv4 only).
const WHOAMI_DOMAIN: &str = "whoami.akamai.net";
const ECS_PREFIX: &str = "edns0-client-subnet ";

/// Note that `ecs_subnet` is whatever the resolver chose to send: usually the
/// client's own /24 or /56, but some resolvers substitute an unrelated subnet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivacyInfo {
    /// Address the resolver used to reach the authoritative server.
    pub exit_ip: Option<IpAddr>,
    /// Operator of that address, e.g. `AS13335 CLOUDFLARENET - Cloudflare, Inc., US`.
    pub exit_as: Option<String>,
    /// Whether the resolver forwarded a client subnet. `None` if unknown.
    pub ecs_sent: Option<bool>,
    /// The subnet it forwarded, e.g. `203.0.113.0/24`.
    pub ecs_subnet: Option<String>,
}

/// Operator names by exit address, shared across endpoints of one run so
/// each address is looked up once.
pub type AsnCache = Arc<Mutex<HashMap<IpAddr, Option<String>>>>;

pub fn new_asn_cache() -> AsnCache {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Pull the exit address and client subnet out of the echo answer.
/// Returns `None` if the answer contains no address at all.
fn parse_echo(answers: &[String]) -> Option<PrivacyInfo> {
    let mut info = PrivacyInfo::default();
    for a in answers {
        let a = a.trim().trim_matches('"');
        if let Some(subnet) = a.strip_prefix(ECS_PREFIX) {
            info.ecs_subnet = Some(subnet.trim().to_string());
        } else if let Ok(ip) = a.parse::<IpAddr>() {
            info.exit_ip = Some(ip);
        }
    }
    info.exit_ip?;
    info.ecs_sent = Some(info.ecs_subnet.is_some());
    Some(info)
}

/// The Team Cymru query name that maps `ip` to its origin AS.
fn origin_query(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", d, c, b, a)
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<String> = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|byte| [byte & 0x0f, byte >> 4])
                .map(|n| format!("{:x}", n))
                .collect();
            format!("{}.origin6.asn.cymru.com", nibbles.join("."))
        }
    }
}

/// First AS number of an origin answer like `13335 | 172.70.120.0/24 | US | arin | 2015-02-25`.
fn parse_origin(answer: &str) -> Option<u32> {
    answer.trim_matches('"').split('|').next()?.split_whitespace().next()?.parse().ok()
}

/// Operator name of an AS answer like `13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US`.
fn parse_as_name(answer: &str) -> Option<String> {
    let name = answer.trim_matches('"').rsplit('|').next()?.trim();
    (!name.is_empty()).then(|| name.to_string())
}

async fn txt(session: &mut Session, name: &str, timeout: Duration) -> Option<Vec<String>> {
    let outcome = session.query(name, RecordType::TXT, timeout).await.ok()?;
    (!outcome.answers.is_empty()).then_some(outcome.answers)
}

async fn lookup_as(session: &mut Session, ip: IpAddr, timeout: Duration) -> Option<String> {
    let origin = txt(session, &origin_query(ip), timeout).await?;
    let asn = origin.iter().find_map(|a| parse_origin(a))?;
    let name = txt(session, &format!("AS{}.asn.cymru.com", asn), timeout)
        .await
        .and_then(|answers| answers.iter().find_map(|a| parse_as_name(a)));
    Some(match name {
        Some(name) => format!("AS{} {}", asn, name),
        None => format!("AS{}", asn),
    })
}

/// Run the privacy checks through `session`. Best effort: any part that
/// cannot be determined is left as `None`.
pub(crate) async fn check(session: &mut Session, timeout: Duration, cache: &AsnCache) -> PrivacyInfo {
    let mut info = match txt(session, ECHO_DOMAIN, timeout).await.and_then(|a| parse_echo(&a)) {
        Some(info) => info,
        None => {
            // Echo name blocked or unanswered: at least find the exit address.
            let exit_ip = session
                .query(WHOAMI_DOMAIN, RecordType::A, timeout)
                .await
                .ok()
                .and_then(|o| o.answers.iter().find_map(|a| a.parse().ok()));
            PrivacyInfo { exit_ip, ..PrivacyInfo::default() }
        }
    };

    if let Some(ip) = info.exit_ip {
        let cached = cache.lock().ok().and_then(|c| c.get(&ip).cloned());
        info.exit_as = match cached {
            Some(known) => known,
            None => {
                let found = lookup_as(session, ip, timeout).await;
                if let Ok(mut c) = cache.lock() {
                    c.insert(ip, found.clone());
                }
                found
            }
        };
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn echo_with_client_subnet() {
        let info = parse_echo(&strings(&["edns0-client-subnet 203.0.113.0/24", "172.217.34.25"])).unwrap();
        assert_eq!(info.exit_ip, Some("172.217.34.25".parse().unwrap()));
        assert_eq!(info.ecs_sent, Some(true));
        assert_eq!(info.ecs_subnet.as_deref(), Some("203.0.113.0/24"));
    }

    #[test]
    fn echo_without_client_subnet() {
        let info = parse_echo(&strings(&["\"2400:cb00:48:1024::c629:f1a7\""])).unwrap();
        assert!(info.exit_ip.unwrap().is_ipv6());
        assert_eq!(info.ecs_sent, Some(false));
    }

    #[test]
    fn echo_without_address_is_inconclusive() {
        assert!(parse_echo(&strings(&["something else"])).is_none());
        assert!(parse_echo(&[]).is_none());
    }

    #[test]
    fn origin_query_names() {
        assert_eq!(origin_query("172.70.120.139".parse().unwrap()), "139.120.70.172.origin.asn.cymru.com");
        let v6 = origin_query("2001:db8::1".parse().unwrap());
        assert!(v6.starts_with("1.0.0.0."));
        assert!(v6.ends_with(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com"));
        assert_eq!(v6.split('.').count(), 32 + 4);
    }

    #[test]
    fn cymru_answers() {
        assert_eq!(parse_origin("\"13335 | 172.70.120.0/24 | US | arin | 2015-02-25\""), Some(13335));
        assert_eq!(parse_origin("13335 36408 | 1.1.1.0/24 | AU | apnic | 2011-08-11"), Some(13335));
        assert_eq!(parse_origin("NA"), None);
        assert_eq!(
            parse_as_name("13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US").as_deref(),
            Some("CLOUDFLARENET - Cloudflare, Inc., US")
        );
    }
}
