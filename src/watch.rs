//! Record live traffic into a database, so the receipt can be built from
//! something real. Part of the shipped binary, not a test helper: `tattle
//! watch --for 60s` is how a first-time user fills the receipt before running
//! `tattle report`.

use std::time::{Duration, Instant};

use crate::dns::{cache::CacheTracker, ipconfig};
use crate::model::Sample;
use crate::resolve::{self, Pending};
use crate::store::Store;

/// Outcome of one collection cycle, for the progress line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickStats {
    pub connections: usize,
    pub names: usize,
    pub resolved: usize,
}

/// Drives the collectors and the store in a loop.
pub struct Watcher<S: Store> {
    store: S,
    collector: crate::platform::windows::Collector,
    dns: CacheTracker,
    last_dns_poll: Option<Instant>,
    /// Ticks since the last retention sweep. Pruning runs on a timer inside the
    /// loop, not only at shutdown: a session that is interrupted or that runs
    /// for hours would otherwise never prune at all.
    ticks_since_prune: u64,
}

impl<S: Store> Watcher<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            collector: crate::platform::windows::Collector::new(),
            dns: CacheTracker::new(),
            last_dns_poll: None,
            ticks_since_prune: 0,
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// One cycle: read connections, read the resolver cache, resolve names.
    pub fn tick(&mut self, now: i64) -> anyhow::Result<TickStats> {
        let mut stats = TickStats::default();

        // Connections every tick: the table is cheap (about 1 ms).
        let samples = self.collector.tick(now)?;
        stats.connections = samples.len();
        self.store.record(&samples)?;

        // The DNS cache changes slowly and `ipconfig` is a process spawn, so it
        // is polled far less often than the connection table.
        let due = self
            .last_dns_poll
            .map(|t| t.elapsed() >= Duration::from_secs(3))
            .unwrap_or(true);
        if due {
            self.last_dns_poll = Some(Instant::now());
            let dump = self.read_dns_cache(now);
            stats.names = self.dns.update(&dump, now).len();
            self.store.record_dns(&self.dns.snapshot())?;
        }

        // Resolve anything new since the last cycle.
        let pending = self.store.pending(256)?;
        if !pending.is_empty() {
            let observations = self.observations_for(&pending)?;
            let decisions = resolve::resolve(&pending, &observations);
            stats.resolved = decisions
                .iter()
                .filter(|d| d.tier > crate::model::Tier::Unknown)
                .count();
            self.store.save_attributions(&decisions)?;
        }

        // Roughly every ten minutes at the one-second poll cadence.
        self.ticks_since_prune += 1;
        if self.ticks_since_prune >= 600 {
            self.ticks_since_prune = 0;
            self.store.prune(now)?;
        }

        Ok(stats)
    }

    /// Observations covering the widest window any pending connection needs.
    fn observations_for(
        &self,
        pending: &[Pending],
    ) -> anyhow::Result<Vec<crate::model::DnsRecord>> {
        let Some(first) = pending.iter().map(|p| p.at).min() else {
            return Ok(Vec::new());
        };
        let Some(last) = pending.iter().map(|p| p.at).max() else {
            return Ok(Vec::new());
        };
        let from = first - resolve::WINDOW_SECONDS;
        let to = last + resolve::FORWARD_SLACK_SECONDS;
        self.store.observations(to, (to - from).max(1))
    }

    /// Run until `duration` has elapsed, calling `on_tick` after each cycle.
    pub fn run(
        &mut self,
        duration: Duration,
        mut on_tick: impl FnMut(TickStats),
    ) -> anyhow::Result<()> {
        let started = Instant::now();
        let base = now_unix();
        let mut tick = 0i64;

        while started.elapsed() < duration {
            let now = base + started.elapsed().as_secs() as i64;
            let stats = self.tick(now)?;
            on_tick(stats);
            tick += 1;

            // Sleep the remainder of the second, so the cadence is even.
            let next = Duration::from_secs(tick as u64);
            if let Some(remaining) = next.checked_sub(started.elapsed()) {
                std::thread::sleep(remaining);
            }
        }
        Ok(())
    }

    /// Prune old rows. Called once at the end of a session.
    pub fn finish(&mut self, now: i64) -> anyhow::Result<()> {
        self.store.prune(now)
    }
}

impl<S: Store> Watcher<S> {
    /// Read and parse the resolver cache. A failure here degrades attribution
    /// but must not stop collection: the addresses are still worth showing.
    fn read_dns_cache(&self, now: i64) -> Vec<crate::model::DnsRecord> {
        match windows_dns_dump() {
            Some(text) => ipconfig::parse_at(&text, now),
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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A sample-only view, used by tests that do not want a live collector.
pub fn record_samples<S: Store>(
    store: &mut S,
    samples: &[Sample],
) -> anyhow::Result<Vec<crate::model::Connection>> {
    store.record(samples)
}
