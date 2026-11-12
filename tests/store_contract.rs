//! Both store implementations must behave identically.
//!
//! The in-memory store exists for tests and replay; the SQLite store is what
//! ships. If they diverge, tests pass and the product is wrong. Every assertion
//! here runs twice, once against each backend.

use tattletale::model::{Category, DnsRecord, DnsSection, DnsSource, Proto, Sample};
use tattletale::resolve;
use tattletale::store::{memory::MemoryStore, sqlite::SqliteStore, Store};

fn sample(at: i64, app: &str, ip: &str, port: u16) -> Sample {
    Sample {
        at,
        app_path: format!("C:\\apps\\{app}.exe"),
        app_name: format!("{app}.exe"),
        ip: ip.into(),
        port,
        proto: Proto::Tcp,
    }
}

fn dns(host: &str, ip: &str, first_seen: i64) -> DnsRecord {
    DnsRecord {
        host: host.into(),
        ip: ip.into(),
        rtype: 1,
        section: DnsSection::Answer,
        ttl: 60,
        first_seen,
        last_seen: first_seen,
        source: DnsSource::Ipconfig,
    }
}

/// Every contract test is written once and run against both backends.
fn check_with<S: Store>(mut store: S) {
    // --- repeated polls of the same tuple are one connection ---
    store
        .record(&[sample(100, "chrome", "1.2.3.4", 443)])
        .unwrap();
    store
        .record(&[sample(101, "chrome", "1.2.3.4", 443)])
        .unwrap();
    store
        .record(&[sample(102, "chrome", "1.2.3.4", 443)])
        .unwrap();
    let totals = store.totals(0).unwrap();
    assert_eq!(
        totals.connections, 1,
        "three polls of one socket is one connection"
    );
    assert_eq!(totals.apps, 1);

    // --- a tuple that disappears and returns is a new connection ---
    store.record(&[]).unwrap();
    store
        .record(&[sample(110, "chrome", "1.2.3.4", 443)])
        .unwrap();
    let totals = store.totals(0).unwrap();
    assert_eq!(totals.connections, 2, "reconnecting counts again");

    // --- separate ports and protocols are separate connections ---
    store
        .record(&[sample(120, "chrome", "1.2.3.4", 8443)])
        .unwrap();
    let totals = store.totals(0).unwrap();
    assert_eq!(totals.connections, 3);

    // --- the address is resolved just before the app dials it ---
    store
        .record_dns(&[dns("api.example.com", "1.2.3.4", 200)])
        .unwrap();
    store.record(&[]).unwrap();
    store
        .record(&[sample(205, "chrome", "1.2.3.4", 443)])
        .unwrap();

    // --- DNS merge keeps the earliest sighting ---
    store
        .record_dns(&[dns("api.example.com", "1.2.3.4", 199)])
        .unwrap();
    let obs = store.observations(210, 90).unwrap();
    assert_eq!(obs.len(), 1);
    assert_eq!(
        obs[0].first_seen, 199,
        "the earliest resolution is the true one"
    );

    // --- observations are windowed ---
    assert!(
        store.observations(1000, 90).unwrap().is_empty(),
        "stale resolutions are excluded"
    );

    // --- attribution round-trips and removes the row from pending ---
    let pending = store.pending(10).unwrap();
    assert!(!pending.is_empty());
    let decisions = resolve::resolve(&pending, &obs);
    assert!(
        decisions
            .iter()
            .any(|d| d.tier == tattletale::model::Tier::High),
        "a connection that reopened 5 s after its name resolved must be confidently attributed"
    );
    store.save_attributions(&decisions).unwrap();
    let remaining = store.pending(10).unwrap();
    assert!(
        remaining
            .iter()
            .all(|p| !pending.iter().any(|q| q.conn_id == p.conn_id)),
        "attributed connections must not be returned again"
    );

    // --- categories drive the tracked count ---
    store
        .set_category("api.example.com", Category::Tracker)
        .unwrap();
    let rows = store.site_rows(0, 10).unwrap();
    let example = rows
        .iter()
        .find(|r| r.site == "example.com")
        .expect("site row");
    assert_eq!(example.category, Category::Tracker);
    assert_eq!(example.host, "api.example.com");

    let totals = store.totals(0).unwrap();
    assert!(totals.sites >= 1);
    assert!(totals.tracked >= 1, "a flagged site must count as tracked");

    // --- app rows carry their top sites ---
    let apps = store.app_rows(0, 10).unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].app.name, "chrome.exe");
    assert!(apps[0].top_sites.iter().any(|s| s.site == "example.com"));

    // --- pruning respects retention ---
    let week = 7 * 24 * 60 * 60;
    store.prune(1_000_000 + week).unwrap();
    assert_eq!(
        store.totals(0).unwrap().connections,
        0,
        "rows past retention are dropped"
    );
}

/// The two stores must agree on the numbers, not just pass the same assertions.
#[test]
fn backends_agree_on_the_same_input() {
    fn run<S: Store>(mut store: S) -> (u64, u64, u64) {
        store
            .record(&[sample(100, "chrome", "1.2.3.4", 443)])
            .unwrap();
        store
            .record(&[sample(101, "chrome", "1.2.3.4", 443)])
            .unwrap();
        store
            .record(&[sample(102, "slack", "5.6.7.8", 443)])
            .unwrap();
        store.record(&[]).unwrap();
        store
            .record(&[sample(110, "chrome", "1.2.3.4", 443)])
            .unwrap();
        let t = store.totals(0).unwrap();
        (t.connections, t.apps, t.sites)
    }

    let memory = run(MemoryStore::new());
    let sqlite = run(SqliteStore::open_in_memory().unwrap());
    assert_eq!(
        memory, sqlite,
        "the two backends disagree on the same traffic"
    );
    assert_eq!(memory.0, 3, "two chrome opens plus one slack open");
    assert_eq!(memory.1, 2, "two applications");
}

#[test]
fn memory_store_honours_the_contract() {
    check_with(MemoryStore::new());
}

#[test]
fn sqlite_store_honours_the_contract() {
    check_with(SqliteStore::open_in_memory().expect("in-memory sqlite"));
}

#[test]
fn sqlite_persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tattle.db");
    {
        let mut store = SqliteStore::open(&path).unwrap();
        store
            .record(&[sample(100, "slack", "5.6.7.8", 443)])
            .unwrap();
    }
    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(
        store.totals(0).unwrap().connections,
        1,
        "a receipt must survive a restart"
    );
}

#[test]
fn sqlite_survives_a_concurrent_second_handle() {
    // The writer thread owns the database, but `tattle report` opens the same
    // file from another process. WAL mode must allow that read.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tattle.db");
    let mut writer = SqliteStore::open(&path).unwrap();
    writer
        .record(&[sample(100, "chrome", "1.2.3.4", 443)])
        .unwrap();

    let reader = SqliteStore::open(&path).unwrap();
    assert_eq!(reader.totals(0).unwrap().connections, 1);
}
