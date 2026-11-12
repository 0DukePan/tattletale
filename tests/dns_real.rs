use tattletale::dns::ipconfig;

#[test]
fn parses_the_real_dump_from_this_machine() {
    let text = std::fs::read_to_string("fixtures/displaydns-win10-en.txt").expect("fixture");
    let entries = ipconfig::parse_entries(&text);
    println!("entries parsed: {}", entries.len());
    let records = ipconfig::parse_at(&text, 1_700_000_000);
    println!("address records: {}", records.len());

    for r in records.iter().take(12) {
        println!(
            "  {:<52} {:<40} type {} ttl {}",
            r.host, r.ip, r.rtype, r.ttl
        );
    }

    assert!(
        !records.is_empty(),
        "the fixture has A records and must yield some"
    );
    for r in &records {
        assert!(
            r.rtype == 1 || r.rtype == 28,
            "only address records survive"
        );
        assert!(
            r.ip.parse::<std::net::IpAddr>().is_ok(),
            "{} is not an address",
            r.ip
        );
        assert!(
            !tattletale::dns::is_local_name(&r.host),
            "{} is local",
            r.host
        );
        assert!(r.ttl > 0, "ttl must be captured for refresh detection");
    }
}
