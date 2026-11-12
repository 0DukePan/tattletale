//! Attribution health: how much of the traffic this tool can actually explain.
//!
//! The standard-mode design reads names from the Windows resolver cache. An
//! application that resolves names itself — most browsers, via DNS over HTTPS —
//! never puts those names in that cache, so its connections arrive as bare
//! addresses.
//!
//! This module measures that gap and produces the caveats shown in the receipt.
//! The tool does not hide the gap and does not paper over it with a guess: an
//! unnamed connection is reported as unnamed, and the receipt says why.
//!
//! The honest framing matters more than the number. A privacy tool that quietly
//! under-reports is worse than one that says "I cannot see this".

use std::collections::BTreeSet;

use crate::report::build::Event;

/// Coverage below this fraction is worth disclosing once there is a sample
/// large enough for the number to mean something.
pub const LOW_COVERAGE: f64 = 0.5;

/// Below this many connections, a coverage percentage is noise and is not
/// shown. A two-connection recording is always 0% or 100%.
pub const MIN_SAMPLE: u64 = 10;

/// Resolver endpoints commonly used over HTTPS. A connection to one of these on
/// port 443 means that application's name lookups bypassed the system resolver.
const DOH_ENDPOINTS: &[(&str, &str)] = &[
    ("1.1.1.1", "Cloudflare"),
    ("1.0.0.1", "Cloudflare"),
    ("8.8.8.8", "Google"),
    ("8.8.4.4", "Google"),
    ("9.9.9.9", "Quad9"),
    ("149.112.112.112", "Quad9"),
    ("94.140.14.14", "AdGuard"),
    ("94.140.15.15", "AdGuard"),
    ("76.76.2.2", "NextDNS"),
    ("45.90.28.0", "NextDNS"),
    ("45.90.30.0", "NextDNS"),
    ("208.67.222.222", "OpenDNS"),
    ("208.67.220.220", "OpenDNS"),
    ("185.228.168.9", "CleanBrowsing"),
];

/// Resolver hostnames. A connection whose name resolved to one of these is a
/// DoH endpoint even when the address is not in the table above.
const DOH_HOSTS: &[&str] = &[
    "dns.google",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "dns.adguard.com",
];

/// What attribution health looks like for a window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Health {
    pub total: u64,
    pub named: u64,
    /// Applications observed talking to a DoH resolver on port 443.
    pub doh_apps: BTreeSet<String>,
    /// Human-readable disclosures for the receipt footer.
    pub caveats: Vec<String>,
}

impl Health {
    /// Fraction of connections that carry a domain name, 0.0 to 1.0.
    pub fn coverage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.named as f64 / self.total as f64
        }
    }

    /// Whether the sample is big enough for coverage to be meaningful.
    pub fn has_sample(&self) -> bool {
        self.total >= MIN_SAMPLE
    }
}

/// Measure how well this window could be explained.
pub fn assess(events: &[Event]) -> Health {
    let mut health = Health {
        total: events.len() as u64,
        ..Health::default()
    };

    for event in events {
        if event.site.is_some() {
            health.named += 1;
        }
        if is_doh_endpoint(&event.ip, event.port, event.site.as_deref()) {
            health.doh_apps.insert(event.app.clone());
        }
    }

    health.caveats = caveats(&health);
    health
}

/// Whether a connection is to a resolver used over HTTPS.
pub fn is_doh_endpoint(ip: &str, port: u16, host: Option<&str>) -> bool {
    if port != 443 {
        // Plain DNS on port 53 is already visible to the system resolver, so it
        // is not a blind spot.
        return false;
    }
    if DOH_ENDPOINTS.iter().any(|(endpoint, _)| *endpoint == ip) {
        return true;
    }
    host.map(|host| {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        DOH_HOSTS
            .iter()
            .any(|known| host == *known || host.ends_with(&format!(".{known}")))
    })
    .unwrap_or(false)
}

/// The disclosures a receipt should carry, most important first.
fn caveats(health: &Health) -> Vec<String> {
    let mut out = Vec::new();

    if !health.doh_apps.is_empty() {
        let apps: Vec<&str> = health.doh_apps.iter().map(String::as_str).take(3).collect();
        out.push(format!(
            "{} {} its own DNS over HTTPS, so those domain names never reach the system resolver and cannot appear here. Their connections are counted, but shown by address.",
            apps.join(", "),
            if apps.len() == 1 { "uses" } else { "use" },
        ));
    }

    if health.has_sample() && health.coverage() < LOW_COVERAGE {
        out.push(format!(
            "Only {:.0}% of connections could be named. This is expected when applications resolve names themselves; it is not a missing connection count.",
            health.coverage() * 100.0
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Tier;

    fn event(app: &str, ip: &str, port: u16, site: Option<&str>) -> Event {
        Event {
            app: app.into(),
            site: site.map(str::to_string),
            at: 0,
            tier: if site.is_some() {
                Tier::High
            } else {
                Tier::Unknown
            },
            ip: ip.into(),
            port,
        }
    }

    #[test]
    fn a_resolver_on_443_is_a_doh_endpoint() {
        assert!(is_doh_endpoint("1.1.1.1", 443, None));
        assert!(is_doh_endpoint("8.8.8.8", 443, None));
        assert!(is_doh_endpoint("9.9.9.9", 443, None));
    }

    #[test]
    fn plain_dns_on_53_is_not_a_blind_spot() {
        // Port 53 is visible to the system resolver; only HTTPS is a gap.
        assert!(!is_doh_endpoint("8.8.8.8", 53, None));
        assert!(!is_doh_endpoint("1.1.1.1", 53, None));
    }

    #[test]
    fn a_resolver_hostname_counts_even_on_an_unknown_address() {
        assert!(is_doh_endpoint(
            "104.16.248.249",
            443,
            Some("mozilla.cloudflare-dns.com")
        ));
        assert!(is_doh_endpoint("1.2.3.4", 443, Some("dns.google")));
        assert!(!is_doh_endpoint("1.2.3.4", 443, Some("example.com")));
    }

    #[test]
    fn ordinary_traffic_is_not_mistaken_for_doh() {
        assert!(!is_doh_endpoint(
            "142.250.75.238",
            443,
            Some("www.google.com")
        ));
        assert!(!is_doh_endpoint("140.82.114.25", 443, Some("github.com")));
    }

    #[test]
    fn coverage_counts_only_named_connections() {
        let events = vec![
            event("chrome.exe", "1.2.3.4", 443, Some("example.com")),
            event("brave.exe", "5.6.7.8", 443, None),
            event("brave.exe", "9.9.9.9", 443, None),
            event("slack.exe", "4.3.2.1", 443, Some("slack.com")),
        ];
        let health = assess(&events);
        assert_eq!(health.total, 4);
        assert_eq!(health.named, 2);
        assert!((health.coverage() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn a_doh_user_is_named_in_the_caveat() {
        let events = vec![event("brave.exe", "1.1.1.1", 443, None)];
        let health = assess(&events);
        assert!(health.doh_apps.contains("brave.exe"));
        assert!(
            health
                .caveats
                .iter()
                .any(|c| c.contains("brave.exe") && c.contains("HTTPS")),
            "the receipt must say which app hides its names: {:?}",
            health.caveats
        );
    }

    #[test]
    fn low_coverage_is_disclosed_only_with_enough_data() {
        // Two connections: too small a sample to draw a conclusion.
        let few = vec![
            event("a.exe", "1.2.3.4", 443, None),
            event("a.exe", "1.2.3.5", 443, None),
        ];
        let health = assess(&few);
        assert!(!health.has_sample());
        assert!(
            !health.caveats.iter().any(|c| c.contains('%')),
            "a two-connection sample must not produce a percentage: {:?}",
            health.caveats
        );

        // Twelve unnamed connections: the percentage is meaningful.
        let many: Vec<Event> = (0..12)
            .map(|i| event("brave.exe", &format!("1.2.3.{i}"), 443, None))
            .collect();
        let health = assess(&many);
        assert!(health.has_sample());
        assert!(
            health.caveats.iter().any(|c| c.contains('%')),
            "a large unnamed sample must be disclosed: {:?}",
            health.caveats
        );
    }

    #[test]
    fn a_well_named_window_has_no_caveats() {
        let events: Vec<Event> = (0..12)
            .map(|i| event("slack.exe", &format!("1.2.3.{i}"), 443, Some("slack.com")))
            .collect();
        let health = assess(&events);
        assert!((health.coverage() - 1.0).abs() < f64::EPSILON);
        assert!(
            health.caveats.is_empty(),
            "nothing to disclose: {:?}",
            health.caveats
        );
    }

    #[test]
    fn empty_input_is_handled() {
        let health = assess(&[]);
        assert_eq!(health.total, 0);
        assert_eq!(health.coverage(), 0.0, "no division by zero");
        assert!(health.caveats.is_empty());
    }
}
