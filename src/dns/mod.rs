//! DNS observation parsing and correlation support.
//!
//! Attribution starts with names. The system resolver cache is the only
//! name-to-address source available to a standard user, so this module turns
//! `ipconfig /displaydns` output into [`DnsRecord`]s and tracks when each pair
//! was first seen. That timestamp is what the attribution engine scores
//! against a connection, so getting it wrong quietly degrades every verdict.

pub mod cache;
pub mod ipconfig;

/// Record types we keep. CNAME (5) and MX (15) describe the query, not an
/// address, and are dropped after they have been used to follow the chain.
pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_AAAA: u16 = 28;

/// Names that resolve to this machine or its immediate neighbours. They are
/// not "apps phoning home" and would only add noise to the receipt.
pub fn is_local_name(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return true;
    }
    // Reverse lookups are never a website name, and the bare namespace counts.
    for suffix in ["in-addr.arpa", "ip6.arpa"] {
        if host == suffix || host.ends_with(&format!(".{suffix}")) {
            return true;
        }
    }
    // Single-label names are NetBIOS/mDNS neighbours, not remote services.
    if !host.contains('.') {
        return true;
    }
    const LOCAL_SUFFIXES: [&str; 5] = [".local", ".lan", ".internal", ".home.arpa", ".localdomain"];
    LOCAL_SUFFIXES.iter().any(|suffix| host.ends_with(suffix))
}

/// Reduce a host to the registrable site used for grouping in reports.
///
/// This is a heuristic on purpose: a real public-suffix list would add a data
/// file and a dependency, and the receipt only needs to say "google.com", not
/// to be authoritative. The cases that matter (`co.uk`, `com.br`, â€¦) are
/// handled because they are the ones where a naive last-two-labels guess is
/// visibly wrong on a screenshot.
pub fn site_of(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return host;
    }
    // Two-level public suffixes that are common enough to appear in a demo.
    const SECOND_LEVEL: [&str; 14] = [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "or.jp", "ne.jp", "com.au", "net.au",
        "co.nz", "com.br", "com.mx", "co.za", "co.in",
    ];
    let tail2 = labels[labels.len() - 2..].join(".");
    if SECOND_LEVEL.contains(&tail2.as_str()) && labels.len() >= 3 {
        return labels[labels.len() - 3..].join(".");
    }
    tail2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_names_are_recognised() {
        for local in [
            "localhost",
            "printer",
            "my-nas.local",
            "router.lan",
            "box.internal",
            "202.43.168.192.in-addr.arpa.",
            "ip6.arpa",
        ] {
            assert!(is_local_name(local), "{local} must be treated as local");
        }
    }

    #[test]
    fn public_names_are_not_local() {
        for public in [
            "example.com",
            "a.b.googlevideo.com",
            "s3.amazonaws.com",
            "x.io",
        ] {
            assert!(
                !is_local_name(public),
                "{public} must not be treated as local"
            );
        }
    }

    #[test]
    fn site_reduces_to_registrable_domain() {
        assert_eq!(site_of("a.b.example.com"), "example.com");
        assert_eq!(site_of("example.com"), "example.com");
        assert_eq!(site_of("www.example.co.uk"), "example.co.uk");
        assert_eq!(
            site_of("rr1.sn-5abxgpxuxaxjvh-5aby.googlevideo.com"),
            "googlevideo.com"
        );
        assert_eq!(site_of("EXAMPLE.COM."), "example.com");
    }

    #[test]
    fn site_keeps_short_hosts_intact() {
        assert_eq!(site_of("x.io"), "x.io");
        // A bare suffix is not a site, but returning it beats panicking.
        assert_eq!(site_of("co.uk"), "co.uk");
    }
}
