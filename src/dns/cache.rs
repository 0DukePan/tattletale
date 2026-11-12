//! Tracks when each name/address pair was first observed.
//!
//! The resolver cache does not say *when* it resolved a name, only that it
//! currently holds it. Attribution needs the moment of resolution, because a
//! connection is matched against names resolved shortly before it opened. So
//! this module remembers the earliest dump in which a pair appeared, and
//! forgets it when the cache drops the pair (the entry expired).
//!
//! A TTL that goes *up* between dumps is the signal that the resolver refreshed
//! the entry: the name was resolved again, so its first-seen time must move
//! forward. Without that rule a stale address would look freshly resolved
//! forever and every long-lived connection would match it.

use std::collections::HashMap;

use crate::model::DnsRecord;

#[derive(Debug, Clone)]
struct Tracked {
    /// When this incarnation of the entry was first seen.
    first_seen: i64,
    ttl: u32,
    last_seen: i64,
}

/// In-memory index of the resolver cache, refreshed from each dump.
#[derive(Debug, Default)]
pub struct CacheTracker {
    tracked: HashMap<(String, String), (Tracked, DnsRecord)>,
    last_poll_at: i64,
}

impl CacheTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge a fresh dump into the index.
    ///
    /// Returns every record currently held, with `first_seen` corrected to the
    /// time of the resolution that produced it. Records missing from `dump`
    /// are forgotten: the resolver dropped them, so they must not keep matching
    /// new connections.
    pub fn update(&mut self, dump: &[DnsRecord], now: i64) -> Vec<DnsRecord> {
        let mut present: HashMap<(String, String), ()> = HashMap::with_capacity(dump.len());

        for record in dump {
            let key = (record.host.clone(), record.ip.clone());
            present.insert(key.clone(), ());

            match self.tracked.get_mut(&key) {
                Some((tracked, stored)) => {
                    if record.ttl > tracked.ttl {
                        // The resolver refreshed the entry: a new resolution.
                        tracked.first_seen = now;
                    }
                    tracked.ttl = record.ttl;
                    tracked.last_seen = now;
                    *stored = record.clone();
                }
                None => {
                    let tracked = Tracked {
                        first_seen: now,
                        ttl: record.ttl,
                        last_seen: now,
                    };
                    self.tracked.insert(key, (tracked, record.clone()));
                }
            }
        }

        self.tracked.retain(|key, _| present.contains_key(key));
        self.last_poll_at = now;
        self.snapshot()
    }

    /// Everything currently remembered, with accurate first-seen times.
    pub fn snapshot(&self) -> Vec<DnsRecord> {
        self.tracked
            .values()
            .map(|(tracked, record)| DnsRecord {
                first_seen: tracked.first_seen,
                last_seen: tracked.last_seen,
                ..record.clone()
            })
            .collect()
    }

    /// Pairs for `ip` that were resolved recently enough to explain a
    /// connection opening at `at`. This is the query the engine runs per
    /// connection, so it must be cheap and deterministic.
    pub fn candidates(&self, ip: &str, at: i64, window: i64, limit: usize) -> Vec<DnsRecord> {
        let mut hits: Vec<DnsRecord> = self
            .tracked
            .values()
            .filter(|(_, record)| record.ip == ip && matches!(record.rtype, 1 | 28))
            .filter(|(tracked, _)| {
                tracked.first_seen <= at + 3 && tracked.first_seen >= at - window
            })
            .map(|(tracked, record)| DnsRecord {
                first_seen: tracked.first_seen,
                last_seen: tracked.last_seen,
                ..record.clone()
            })
            .collect();

        // Most recent resolution first; on a tie the answer section outranks
        // an additional-section guess.
        hits.sort_by(|a, b| {
            b.first_seen
                .cmp(&a.first_seen)
                .then(b.section.cmp(&a.section))
        });
        hits.truncate(limit);
        hits
    }

    pub fn len(&self) -> usize {
        self.tracked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tracked.is_empty()
    }

    pub fn last_poll_at(&self) -> i64 {
        self.last_poll_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsSection, DnsSource};

    fn record(host: &str, ip: &str, ttl: u32) -> DnsRecord {
        DnsRecord {
            host: host.into(),
            ip: ip.into(),
            rtype: 1,
            section: DnsSection::Answer,
            ttl,
            first_seen: 0,
            last_seen: 0,
            source: DnsSource::Ipconfig,
        }
    }

    #[test]
    fn first_sighting_is_remembered_across_dumps() {
        let mut tracker = CacheTracker::new();
        tracker.update(&[record("example.com", "1.2.3.4", 300)], 100);
        let out = tracker.update(&[record("example.com", "1.2.3.4", 290)], 130);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].first_seen, 100,
            "a decrementing TTL is the same resolution"
        );
    }

    #[test]
    fn an_increasing_ttl_means_the_name_was_resolved_again() {
        let mut tracker = CacheTracker::new();
        tracker.update(&[record("example.com", "1.2.3.4", 60)], 100);
        let out = tracker.update(&[record("example.com", "1.2.3.4", 300)], 200);
        assert_eq!(out[0].first_seen, 200, "the resolver refreshed the entry");
    }

    #[test]
    fn expired_entries_stop_matching() {
        let mut tracker = CacheTracker::new();
        tracker.update(&[record("example.com", "1.2.3.4", 60)], 100);
        assert_eq!(tracker.len(), 1);
        tracker.update(&[], 200);
        assert!(
            tracker.is_empty(),
            "a pair the resolver dropped must not linger"
        );
        assert!(tracker.candidates("1.2.3.4", 200, 90, 8).is_empty());
    }

    #[test]
    fn candidates_are_ordered_by_resolution_time() {
        let mut tracker = CacheTracker::new();
        tracker.update(&[record("old.example", "1.2.3.4", 300)], 100);
        tracker.update(
            &[
                record("old.example", "1.2.3.4", 290),
                record("newer.example", "1.2.3.4", 300),
            ],
            150,
        );

        let hits = tracker.candidates("1.2.3.4", 160, 90, 8);
        assert_eq!(
            hits[0].host, "newer.example",
            "the most recent resolution wins"
        );
        assert!(
            hits.iter().any(|h| h.host == "old.example"),
            "an older entry still inside the window stays a candidate"
        );
    }

    #[test]
    fn candidates_outside_the_window_are_excluded() {
        let mut tracker = CacheTracker::new();
        tracker.update(&[record("example.com", "1.2.3.4", 8000)], 100);
        assert!(
            tracker.candidates("1.2.3.4", 500, 90, 8).is_empty(),
            "resolved 400s ago"
        );
        assert_eq!(
            tracker.candidates("1.2.3.4", 150, 90, 8).len(),
            1,
            "resolved 50s ago"
        );
    }

    #[test]
    fn a_connection_can_be_attributed_before_the_cache_is_polled() {
        let mut tracker = CacheTracker::new();
        tracker.update(&[record("example.com", "1.2.3.4", 300)], 100);
        // The connection opened 2 s after the resolver answered, but the next
        // poll has not happened yet. The record is still there, so this works.
        assert_eq!(tracker.candidates("1.2.3.4", 102, 90, 8).len(), 1);
        // A connection that opened *before* the resolution is not explained by it.
        assert!(tracker.candidates("1.2.3.4", 90, 90, 8).is_empty());
    }

    #[test]
    fn candidates_for_other_addresses_are_not_returned() {
        let mut tracker = CacheTracker::new();
        tracker.update(&[record("example.com", "1.2.3.4", 300)], 100);
        assert!(tracker.candidates("5.6.7.8", 110, 90, 8).is_empty());
    }

    #[test]
    fn limit_is_respected_and_the_best_come_first() {
        let mut tracker = CacheTracker::new();
        // A real `ipconfig` dump is the whole cache, so every poll carries
        // every still-live pair; a name added later appears alongside the rest.
        let mut dump: Vec<DnsRecord> = (0..10)
            .map(|i| record(&format!("h{i}.example"), "1.2.3.4", 300))
            .collect();
        tracker.update(&dump, 100);

        dump.push(record("newest.example", "1.2.3.4", 10));
        tracker.update(&dump, 170);

        let hits = tracker.candidates("1.2.3.4", 175, 90, 3);
        assert_eq!(hits.len(), 3, "the limit must bound the candidate list");
        assert_eq!(hits[0].host, "newest.example");
    }
}
