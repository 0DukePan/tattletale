//! End-to-end attribution against the live operating system.
//!
//! This is the test that proves the product actually works, not just that its
//! parts do. It performs a controlled experiment:
//!
//! 1. resolve a name through the OS resolver, so the cache holds it
//! 2. open a TCP connection to the address it resolved to
//! 3. read both the connection table and the resolver cache
//! 4. assert the engine names the connection with `High` confidence
//!
//! It is `#[ignore]`d by default because it needs the network and takes a few
//! seconds. Run it with `cargo test -- --ignored live_`.

#![cfg(windows)]

use std::io::Write as _;
use std::net::TcpStream;
use std::time::Duration;

use tattletale::dns::{cache::CacheTracker, ipconfig};
use tattletale::model::Tier;
use tattletale::platform::windows::Collector;
use tattletale::resolve::{self, Pending};

/// Read the resolver cache the same way the watcher does.
fn dns_dump() -> String {
    let out = std::process::Command::new("ipconfig")
        .arg("/displaydns")
        .output()
        .expect("ipconfig must run");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
#[ignore = "needs the network and a few seconds of wall clock"]
fn live_resolve_then_connect_is_attributed_with_high_confidence() {
    // An address that is stable, reachable, and not behind a browser CDN.
    let probe_host = "example.com";

    // Step 1: resolve through the OS resolver, so the cache is populated.
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = format!("{probe_host}:80")
        .to_socket_addrs()
        .expect("resolution must work")
        .collect();
    let target = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .copied()
        .expect("an IPv4 address is required for this test");

    let resolved_at = now();

    // Step 2: hold a real connection open to it.
    let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(5))
        .expect("the connection must succeed");
    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n");
    let opened_at = now();

    // Step 3: read both sides.
    let mut collector = Collector::new();
    let samples = collector.tick(opened_at).expect("connection table");

    let dump = dns_dump();
    let mut tracker = CacheTracker::new();
    let records = ipconfig::parse_at(&dump, resolved_at);
    tracker.update(&records, resolved_at);
    let observations = tracker.snapshot();

    let ip = target.ip().to_string();
    let pending = vec![Pending {
        conn_id: 1,
        app_id: 1,
        ip: ip.clone(),
        at: opened_at,
    }];
    let decisions = resolve::resolve(&pending, &observations);

    let live = samples.iter().any(|s| s.ip == ip);
    println!("target       {ip}:{}", target.port());
    println!("connection   present in table: {live}");
    println!(
        "observations {} records, {} for this address",
        observations.len(),
        observations.iter().filter(|r| r.ip == ip).count()
    );
    println!(
        "decision     {:?} ({})",
        decisions[0].tier, decisions[0].method
    );
    for a in &decisions[0].attributions {
        println!("  candidate  {} ({})", a.host, a.site);
    }

    drop(stream);

    assert!(live, "the connection should be visible in the table");
    assert_eq!(
        decisions[0].tier,
        Tier::High,
        "a name resolved just before a connection must be attributed with high confidence"
    );
    assert!(
        decisions[0]
            .attributions
            .iter()
            .any(|a| a.host == probe_host),
        "the engine must name {probe_host}"
    );
}

#[test]
#[ignore = "needs the network"]
fn every_visible_connection_gets_a_decision() {
    // Not every connection can be named — browsers with their own resolver
    // produce connections the Windows cache never saw. What must hold is that
    // every connection gets an *answer*, and that unanswered ones are Unknown
    // rather than a guess.
    let mut collector = Collector::new();
    let at = now();
    let samples = collector.tick(at).expect("connection table");

    let mut tracker = CacheTracker::new();
    tracker.update(&ipconfig::parse_at(&dns_dump(), at), at);
    let observations = tracker.snapshot();

    let pending: Vec<Pending> = samples
        .iter()
        .enumerate()
        .map(|(i, s)| Pending {
            conn_id: i as i64,
            app_id: 1,
            ip: s.ip.clone(),
            at,
        })
        .collect();

    let decisions = resolve::resolve(&pending, &observations);
    assert_eq!(
        decisions.len(),
        pending.len(),
        "every connection must get a decision"
    );

    let named = decisions
        .iter()
        .filter(|d| !d.attributions.is_empty())
        .count();
    println!(
        "{} connections, {} named, {} unknown",
        decisions.len(),
        named,
        decisions.len() - named
    );

    for decision in &decisions {
        if decision.tier == Tier::Unknown {
            assert!(
                decision.attributions.is_empty(),
                "an unknown answer must not carry a guess"
            );
        }
    }
}
