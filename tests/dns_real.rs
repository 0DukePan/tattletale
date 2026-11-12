//! The parser against a real `ipconfig /displaydns` capture.
//!
//! The capture is a real Windows 10 dump, **sanitised**: every hostname, machine
//! name and address was replaced with a documentation-range equivalent while
//! preserving the exact formatting, record types, TTLs, section values and
//! CNAME chains. Line count, record count and every structural field are
//! identical to the original.
//!
//! It was sanitised for a specific reason: a privacy tool publishing the
//! author's own DNS cache would be an embarrassing way to make this point.

use tattletale::dns::ipconfig;

#[test]
fn parses_a_real_capture_after_sanitising() {
    let text = std::fs::read_to_string("fixtures/displaydns-windows.txt").expect("fixture");

    let entries = ipconfig::parse_entries(&text);
    let records = ipconfig::parse_at(&text, 1_700_000_000);

    // These numbers pin the structure of the capture. If the parser regresses
    // and drops a record type, they change.
    assert_eq!(entries.len(), 38, "the capture contains 38 complete blocks");
    assert!(!records.is_empty(), "the capture contains A records");

    for record in &records {
        assert!(
            record.rtype == 1 || record.rtype == 28,
            "only address records survive, got type {}",
            record.rtype
        );
        assert!(
            record.ip.parse::<std::net::IpAddr>().is_ok(),
            "{} is not an address",
            record.ip
        );
        assert!(
            !tattletale::dns::is_local_name(&record.host),
            "{} is local and should have been filtered",
            record.host
        );
        assert!(record.ttl > 0, "ttl must be captured for refresh detection");
        assert_eq!(
            record.first_seen, 1_700_000_000,
            "injection time must be honoured"
        );
    }
}

#[test]
fn the_capture_contains_no_identifying_data() {
    // The fixture is published. It must not contain a machine name or an
    // address outside the ranges reserved for documentation.
    let text = std::fs::read_to_string("fixtures/displaydns-windows.txt").expect("fixture");

    assert!(
        !text.to_ascii_uppercase().contains("DESKTOP-"),
        "the fixture leaks a machine name"
    );

    // RFC 5737 / RFC 1918 / loopback are the only address families allowed.
    let allowed = |ip: &str| {
        ip.starts_with("203.0.113.")
            || ip.starts_with("198.51.100.")
            || ip.starts_with("192.168.1.")
            || ip == "127.0.0.1"
    };

    for line in text.lines() {
        let Some((_, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.matches('.').count() == 3 && value.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            assert!(
                allowed(value),
                "{value} is not in a documentation or private range; the fixture is leaking a real address"
            );
        }
    }
}
