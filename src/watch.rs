//! Record live traffic into a database, so the receipt can be built from
//! something real.
//!
//! This is the loop that runs continuously, so it is written against two traits
//! rather than against the operating system directly: one for connections, one
//! for the resolver cache. That is what makes it testable — the tests drive it
//! with a scripted sequence of readings and a store that counts what it was
//! asked to do.
//!
//! `tattle watch --duration 10m` is how a first-time user fills a receipt.

use std::time::{Duration, Instant};

use crate::dns::cache::CacheTracker;
use crate::model::{DnsRecord, Sample, Tier};
use crate::resolve;
use crate::store::Store;

/// How many seconds between resolver-cache polls.
///
/// The cache changes slowly and reading it spawns a process, so it is polled far
/// less often than the connection table.
pub const DNS_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Ticks between retention sweeps. Roughly ten minutes at the one-second
/// cadence. Pruning runs inside the loop rather than only at shutdown: an
/// interrupted session would otherwise never prune at all.
pub const PRUNE_EVERY: u64 = 600;

/// Outcome of one collection cycle, for the progress line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickStats {
    pub connections: usize,
    pub names: usize,
    pub resolved: usize,
}

/// Where connections come from. Implemented by the Windows collector and, in
/// tests, by a scripted source.
pub trait ConnectionSource {
    /// Connections visible right now, with the application each belongs to.
    fn connections(&mut self, at: i64) -> anyhow::Result<Vec<Sample>>;
}

/// Where name/address pairs come from.
pub trait NameSource {
    /// The names the resolver currently holds. An empty result is normal: the
    /// cache may be empty, or the source may be unavailable.
    fn names(&mut self, at: i64) -> Vec<DnsRecord>;
}

/// Paces the recording loop so real runs tick once per second.
pub trait Pacer {
    fn wait_before_next_tick(&mut self);
}

/// One tick per second, the real cadence.
pub struct OncePerSecond;

impl Pacer for OncePerSecond {
    fn wait_before_next_tick(&mut self) {
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Drives a connection source, a name source and a store in a loop.
pub struct Watcher<S: Store, C: ConnectionSource, N: NameSource> {
    store: S,
    connections: C,
    names: N,
    dns: CacheTracker,
    last_dns_poll: Option<Instant>,
    ticks_since_prune: u64,
    /// The reverse-DNS worker, when enrichment is enabled. Off by default: see
    /// `dns::reverse`.
    reverse: Option<ReverseWorker>,
}

/// A PTR observation for `ip`, tagged with the fact that this tool asked.
fn ptr_record(name: &str, ip: &str, now: i64) -> DnsRecord {
    DnsRecord {
        host: name.to_string(),
        ip: ip.to_string(),
        rtype: crate::dns::TYPE_PTR,
        section: crate::model::DnsSection::Ptr,
        ttl: 0,
        first_seen: now,
        last_seen: now,
        source: crate::model::DnsSource::ReverseDns,
    }
}

/// Performs reverse lookups without blocking the collection loop.
///
/// One request gets one short-lived thread rather than a shared queue. A single
/// worker was tried first and it was worse than useless: one address whose
/// reverse lookup timed out blocked every diagnosis queued behind it, so the
/// feature appeared to do nothing at all.
struct ReverseWorker {
    outgoing: std::sync::mpsc::Sender<(String, Option<String>)>,
    answers: std::sync::mpsc::Receiver<(String, Option<String>)>,
    in_flight: std::collections::HashSet<String>,
    answered: std::collections::HashSet<String>,
}

/// Ceiling on concurrent lookups, so a screen full of unknown addresses cannot
/// spawn a thread per connection.
const MAX_LOOKUPS_IN_FLIGHT: usize = 64;

impl ReverseWorker {
    fn spawn() -> Self {
        let (outgoing, answers) = std::sync::mpsc::channel();
        Self {
            outgoing,
            answers,
            in_flight: std::collections::HashSet::new(),
            answered: std::collections::HashSet::new(),
        }
    }

    /// Ask for a lookup, at most once per address per session.
    fn request(&mut self, ip: &str) {
        if self.answered.contains(ip) || self.in_flight.contains(ip) {
            return;
        }
        if self.in_flight.len() >= MAX_LOOKUPS_IN_FLIGHT {
            return;
        }

        self.in_flight.insert(ip.to_string());
        let ip = ip.to_string();
        let outgoing = self.outgoing.clone();
        std::thread::spawn(move || {
            let name = crate::dns::reverse::lookup(&ip);
            let _ = outgoing.send((ip, name));
        });
    }

    /// Answers that arrived since the last call.
    fn drain(&mut self) -> Vec<(String, Option<String>)> {
        let ready: Vec<(String, Option<String>)> = self.answers.try_iter().collect();
        for (ip, _) in &ready {
            self.in_flight.remove(ip);
            // An address with no name is answered too: retrying it every second
            // would build a queue that never drains.
            self.answered.insert(ip.clone());
        }
        ready
    }

    fn is_answered(&self, ip: &str) -> bool {
        self.answered.contains(ip)
    }
}
#[cfg(windows)]
impl<S: Store> Watcher<S, crate::platform::windows::Collector, IpconfigNames> {
    /// The real watcher, reading this machine.
    pub fn new(store: S) -> Self {
        Self::with_sources(
            store,
            crate::platform::windows::Collector::new(),
            IpconfigNames,
        )
    }
}

#[cfg(windows)]
impl ConnectionSource for crate::platform::windows::Collector {
    fn connections(&mut self, at: i64) -> anyhow::Result<Vec<Sample>> {
        self.tick(at)
    }
}

impl<S: Store, C: ConnectionSource, N: NameSource> Watcher<S, C, N> {
    /// Build a watcher over arbitrary sources. Used by the tests.
    pub fn with_sources(store: S, connections: C, names: N) -> Self {
        Self {
            store,
            connections,
            names,
            dns: CacheTracker::new(),
            last_dns_poll: None,
            ticks_since_prune: 0,
            reverse: None,
        }
    }

    /// Enable or disable reverse-DNS enrichment.
    ///
    /// Off by default: a reverse lookup tells the local resolver which address
    /// this machine is talking to, which is the fact DNS over HTTPS was hiding.
    pub fn with_reverse_dns(mut self, enabled: bool) -> Self {
        self.reverse = if enabled {
            Some(ReverseWorker::spawn())
        } else {
            None
        };
        self
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// One cycle: read connections, maybe read the resolver cache, resolve names.
    pub fn tick(&mut self, now: i64) -> anyhow::Result<TickStats> {
        let mut stats = TickStats::default();

        let samples = self.connections.connections(now)?;
        stats.connections = samples.len();
        self.store.record(&samples)?;

        let due = self
            .last_dns_poll
            .map(|last| last.elapsed() >= DNS_POLL_INTERVAL)
            .unwrap_or(true);
        if due {
            self.last_dns_poll = Some(Instant::now());
            let dump = self.names.names(now);
            stats.names = self.dns.update(&dump, now).len();
            self.store.record_dns(&self.dns.snapshot())?;
        }

        // Collect any reverse lookups that finished since the last tick.
        //
        // These run on a worker thread, not here. Doing them inline stalled the
        // one-second poll: a resolver that takes a second to answer made the
        // loop miss connections entirely, which is worse than not knowing the
        // name.
        if let Some(worker) = self.reverse.as_mut() {
            for (ip, answer) in worker.drain() {
                if let Some(name) = answer {
                    self.store.record_dns(&[ptr_record(&name, &ip, now)])?;
                }
            }
        }

        let mut pending = self.store.pending(256)?;
        if !pending.is_empty() {
            if let Some(worker) = self.reverse.as_mut() {
                // A connection whose owner is still being looked up waits a tick
                // rather than being resolved as unknown and never revisited.
                for connection in &pending {
                    worker.request(&connection.ip);
                }
                pending.retain(|connection| worker.is_answered(&connection.ip));
            }
        }

        if !pending.is_empty() {
            let observations = self.observations_for(&pending, now)?;
            let decisions = resolve::resolve(&pending, &observations);
            stats.resolved = decisions
                .iter()
                .filter(|decision| decision.tier > Tier::Unknown)
                .count();
            self.store.save_attributions(&decisions)?;
        }

        self.ticks_since_prune += 1;
        if self.ticks_since_prune >= PRUNE_EVERY {
            self.ticks_since_prune = 0;
            self.store.prune(now)?;
        }

        Ok(stats)
    }

    /// Observations covering the widest window any pending connection needs.
    ///
    /// The upper bound is the later of the newest connection and *now*. A
    /// reverse lookup answers a tick or two after the connection opened, and
    /// anchoring the window to the connection alone filtered the answer out —
    /// so enrichment only appeared to work when the resolver cache happened to
    /// already hold the name.
    fn observations_for(
        &self,
        pending: &[resolve::Pending],
        now: i64,
    ) -> anyhow::Result<Vec<DnsRecord>> {
        let Some(first) = pending.iter().map(|p| p.at).min() else {
            return Ok(Vec::new());
        };
        let Some(last) = pending.iter().map(|p| p.at).max() else {
            return Ok(Vec::new());
        };
        let from = first - resolve::WINDOW_SECONDS;
        let to = last.max(now) + resolve::FORWARD_SLACK_SECONDS;
        self.store.observations(to, (to - from).max(1))
    }

    /// Run until `duration` has elapsed, calling `on_tick` after each cycle.
    ///
    /// The pacer is a parameter so a test can run the loop without waiting a
    /// second per iteration, which is the only way this function gets exercised
    /// at all.
    pub fn run(
        &mut self,
        duration: Duration,
        pacer: &mut dyn Pacer,
        mut on_tick: impl FnMut(TickStats),
    ) -> anyhow::Result<()> {
        let started = Instant::now();
        let base = crate::now_unix();

        while started.elapsed() < duration {
            let now = base + started.elapsed().as_secs() as i64;
            let stats = self.tick(now)?;
            on_tick(stats);
            pacer.wait_before_next_tick();
        }
        Ok(())
    }

    /// Prune old rows. Called once at the end of a session.
    pub fn finish(&mut self, now: i64) -> anyhow::Result<()> {
        self.store.prune(now)
    }
}

/// The resolver cache of this machine, read through `ipconfig /displaydns`.
pub struct IpconfigNames;

impl NameSource for IpconfigNames {
    fn names(&mut self, at: i64) -> Vec<DnsRecord> {
        // A failure here degrades attribution but must not stop collection: the
        // addresses are still worth showing.
        match windows_dns_dump() {
            Some(text) => crate::dns::ipconfig::parse_at(&text, at),
            None => Vec::new(),
        }
    }
}

fn windows_dns_dump() -> Option<String> {
    let output = std::process::Command::new("ipconfig")
        .args(["/displaydns"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    // `ipconfig` writes the console code page, not UTF-8. Losing a non-ASCII
    // character in a hostname is acceptable; failing the whole poll is not.
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsSection, DnsSource, Proto};
    use crate::store::{memory::MemoryStore, Store};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// What the loop asked the store to do, in order.
    #[derive(Debug, Default, Clone)]
    struct Calls {
        record: usize,
        record_dns: usize,
        save: usize,
        prune: usize,
        samples_seen: usize,
    }

    /// A store that behaves like the real one and records what was asked of it.
    ///
    /// The counters are the point: the loop's contract is not just "it does not
    /// panic", it is "it records every tick, polls names on a cadence, and
    /// prunes on a schedule".
    struct SpyStore {
        inner: MemoryStore,
        calls: Rc<RefCell<Calls>>,
    }

    impl SpyStore {
        fn new() -> (Self, Rc<RefCell<Calls>>) {
            let calls = Rc::new(RefCell::new(Calls::default()));
            (
                Self {
                    inner: MemoryStore::new(),
                    calls: Rc::clone(&calls),
                },
                calls,
            )
        }
    }

    impl Store for SpyStore {
        fn record(&mut self, samples: &[Sample]) -> anyhow::Result<Vec<crate::model::Connection>> {
            let mut calls = self.calls.borrow_mut();
            calls.record += 1;
            calls.samples_seen += samples.len();
            drop(calls);
            self.inner.record(samples)
        }

        fn record_dns(&mut self, records: &[DnsRecord]) -> anyhow::Result<()> {
            self.calls.borrow_mut().record_dns += 1;
            self.inner.record_dns(records)
        }

        fn observations(&self, at: i64, window: i64) -> anyhow::Result<Vec<DnsRecord>> {
            self.inner.observations(at, window)
        }

        fn save_attributions(
            &mut self,
            decisions: &[crate::resolve::Decision],
        ) -> anyhow::Result<()> {
            self.calls.borrow_mut().save += 1;
            self.inner.save_attributions(decisions)
        }

        fn set_category(
            &mut self,
            host: &str,
            category: crate::model::Category,
        ) -> anyhow::Result<()> {
            self.inner.set_category(host, category)
        }

        fn prune(&mut self, now: i64) -> anyhow::Result<()> {
            self.calls.borrow_mut().prune += 1;
            self.inner.prune(now)
        }

        fn pending(&self, limit: usize) -> anyhow::Result<Vec<resolve::Pending>> {
            self.inner.pending(limit)
        }

        fn apps(&self) -> anyhow::Result<Vec<crate::model::App>> {
            self.inner.apps()
        }

        fn totals(&self, since: i64) -> anyhow::Result<crate::store::Totals> {
            self.inner.totals(since)
        }

        fn app_rows(&self, since: i64, limit: usize) -> anyhow::Result<Vec<crate::store::AppRow>> {
            self.inner.app_rows(since, limit)
        }

        fn site_rows(
            &self,
            since: i64,
            limit: usize,
        ) -> anyhow::Result<Vec<crate::store::SiteRow>> {
            self.inner.site_rows(since, limit)
        }

        fn events(
            &self,
            since: i64,
            limit: usize,
        ) -> anyhow::Result<Vec<crate::report::build::Event>> {
            self.inner.events(since, limit)
        }
    }

    /// A scripted connection source: returns the same socket every tick.
    struct FixedConnections {
        samples: Vec<Sample>,
    }

    impl ConnectionSource for FixedConnections {
        fn connections(&mut self, at: i64) -> anyhow::Result<Vec<Sample>> {
            Ok(self
                .samples
                .iter()
                .map(|s| Sample { at, ..s.clone() })
                .collect())
        }
    }

    /// A source that fails, to prove one bad read does not end the session.
    struct BrokenConnections;

    impl ConnectionSource for BrokenConnections {
        fn connections(&mut self, _at: i64) -> anyhow::Result<Vec<Sample>> {
            anyhow::bail!("the connection table could not be read")
        }
    }

    /// A source that answers once, then reports an empty cache.
    struct OnceNames {
        answered: bool,
        records: Vec<DnsRecord>,
    }

    impl NameSource for OnceNames {
        fn names(&mut self, _at: i64) -> Vec<DnsRecord> {
            if self.answered {
                return Vec::new();
            }
            self.answered = true;
            self.records.clone()
        }
    }

    fn sample(app: &str, ip: &str) -> Sample {
        Sample {
            at: 0,
            app_path: format!("C:\\apps\\{app}.exe"),
            app_name: format!("{app}.exe"),
            ip: ip.into(),
            port: 443,
            proto: Proto::Tcp,
        }
    }

    fn name(host: &str, ip: &str) -> DnsRecord {
        DnsRecord {
            host: host.into(),
            ip: ip.into(),
            rtype: 1,
            section: DnsSection::Answer,
            ttl: 300,
            first_seen: 0,
            last_seen: 0,
            source: DnsSource::Replay,
        }
    }

    /// A pacer that does not sleep.
    struct Immediately;

    impl Pacer for Immediately {
        fn wait_before_next_tick(&mut self) {}
    }

    #[test]
    fn a_tick_records_every_connection_it_sees() {
        let (store, calls) = SpyStore::new();
        let source = FixedConnections {
            samples: vec![sample("chrome", "203.0.113.1")],
        };
        let mut watcher = Watcher::with_sources(
            store,
            source,
            OnceNames {
                answered: true,
                records: vec![],
            },
        );

        let stats = watcher.tick(1_000).expect("tick");

        assert_eq!(stats.connections, 1);
        assert_eq!(calls.borrow().record, 1);
        assert_eq!(calls.borrow().samples_seen, 1);
    }

    #[test]
    fn names_are_polled_on_a_cadence_not_every_tick() {
        // Reading the resolver cache spawns a process. Doing it every second
        // would be wasteful, and the loop claims to poll it every three.
        let (store, calls) = SpyStore::new();
        let source = FixedConnections {
            samples: vec![sample("chrome", "203.0.113.1")],
        };
        let names = OnceNames {
            answered: false,
            records: vec![name("example.com", "203.0.113.1")],
        };
        let mut watcher = Watcher::with_sources(store, source, names);

        watcher.tick(1_000).expect("first tick");
        watcher.tick(1_001).expect("second tick");
        watcher.tick(1_002).expect("third tick");

        assert_eq!(calls.borrow().record, 3, "connections are read every tick");
        assert_eq!(
            calls.borrow().record_dns,
            1,
            "the cache is read once, not on all three ticks"
        );
    }

    #[test]
    fn a_resolved_name_becomes_an_attribution_in_the_same_tick() {
        let (store, calls) = SpyStore::new();
        let source = FixedConnections {
            samples: vec![sample("chrome", "203.0.113.7")],
        };
        let names = OnceNames {
            answered: false,
            records: vec![name("example.com", "203.0.113.7")],
        };
        let mut watcher = Watcher::with_sources(store, source, names);

        let stats = watcher.tick(1_000).expect("tick");

        assert_eq!(stats.resolved, 1, "one connection should have been named");
        assert_eq!(calls.borrow().save, 1);
        assert!(
            watcher.store().app_rows(0, 10).expect("rows")[0].top_sites[0].site == "example.com"
        );
    }

    #[test]
    fn an_unresolvable_connection_is_recorded_but_not_counted_as_resolved() {
        let (store, _calls) = SpyStore::new();
        let source = FixedConnections {
            samples: vec![sample("chrome", "203.0.113.99")],
        };
        let mut watcher = Watcher::with_sources(
            store,
            source,
            OnceNames {
                answered: true,
                records: vec![],
            },
        );

        let stats = watcher.tick(1_000).expect("tick");
        assert_eq!(stats.connections, 1);
        assert_eq!(stats.resolved, 0, "nothing was named, so nothing resolved");
    }

    #[test]
    fn a_failing_source_stops_the_tick_with_an_error_rather_than_panicking() {
        let (store, _calls) = SpyStore::new();
        let mut watcher = Watcher::with_sources(
            store,
            BrokenConnections,
            OnceNames {
                answered: true,
                records: vec![],
            },
        );

        let err = watcher.tick(1_000).unwrap_err();
        assert!(err.to_string().contains("could not be read"), "got: {err}");
    }

    #[test]
    fn retention_runs_inside_the_loop_on_a_schedule() {
        let (store, calls) = SpyStore::new();
        let source = FixedConnections { samples: vec![] };
        let mut watcher = Watcher::with_sources(
            store,
            source,
            OnceNames {
                answered: true,
                records: vec![],
            },
        );

        for tick in 0..PRUNE_EVERY {
            watcher.tick(1_000 + tick as i64).expect("tick");
        }
        assert_eq!(
            calls.borrow().prune,
            1,
            "one sweep after {PRUNE_EVERY} ticks"
        );

        for tick in 0..PRUNE_EVERY {
            watcher.tick(2_000 + tick as i64).expect("tick");
        }
        assert_eq!(calls.borrow().prune, 2, "and another after the next");
    }

    #[test]
    fn finish_prunes_once_more() {
        let (store, calls) = SpyStore::new();
        let mut watcher = Watcher::with_sources(
            store,
            FixedConnections { samples: vec![] },
            OnceNames {
                answered: true,
                records: vec![],
            },
        );
        watcher.finish(5_000).expect("finish");
        assert_eq!(calls.borrow().prune, 1);
    }

    #[test]
    fn run_ticks_repeatedly_and_reports_every_cycle() {
        // The paced loop is the part that runs for minutes on a user's machine.
        // A no-op pacer lets it be exercised in milliseconds.
        let (store, calls) = SpyStore::new();
        let source = FixedConnections {
            samples: vec![sample("chrome", "203.0.113.1")],
        };
        let mut watcher = Watcher::with_sources(
            store,
            source,
            OnceNames {
                answered: true,
                records: vec![],
            },
        );

        let mut seen = 0usize;
        watcher
            .run(Duration::from_millis(30), &mut Immediately, |stats| {
                assert_eq!(stats.connections, 1);
                seen += 1;
            })
            .expect("run");

        assert!(seen > 1, "the loop must tick more than once");
        assert_eq!(
            calls.borrow().record,
            seen,
            "every reported tick was recorded"
        );
    }

    #[test]
    fn an_empty_source_is_not_an_error() {
        // A machine with no connections is normal, not a failure.
        let (store, calls) = SpyStore::new();
        let mut watcher = Watcher::with_sources(
            store,
            FixedConnections { samples: vec![] },
            OnceNames {
                answered: true,
                records: vec![],
            },
        );
        let stats = watcher.tick(1_000).expect("tick");
        assert_eq!(stats, TickStats::default());
        assert_eq!(calls.borrow().record, 1);
    }
}
