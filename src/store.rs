//! Persistence. SQLite in production, in-memory in tests.
//!
//! The trait exists so the attribution engine and the report renderer can be
//! tested against a fake store without creating files or depending on timing.

use crate::model::{Attribution, Category, Connection, DnsRecord, Sample};

/// Everything the rest of the program needs from storage.
pub trait Store {
    /// Merge a batch of polled connections and return the affected rows with
    /// their updated counters. Must be idempotent for repeated samples.
    fn record(&mut self, samples: &[Sample]) -> anyhow::Result<Vec<Connection>>;

    /// Merge observed DNS answers, preferring the answer section over additional.
    fn record_dns(&mut self, records: &[DnsRecord]) -> anyhow::Result<()>;

    /// Candidate domains for an address, best first, filtered to the time window.
    fn candidates(
        &self,
        ip: &str,
        from: i64,
        to: i64,
        limit: usize,
    ) -> anyhow::Result<Vec<DnsRecord>>;

    /// Persist the attribution decision for a connection.
    fn save_attribution(&mut self, attribution: &[Attribution]) -> anyhow::Result<()>;

    /// Attach a category to a host and its site, so later reports need no list.
    fn set_category(&mut self, host: &str, site: &str, category: Category) -> anyhow::Result<()>;

    /// Drop rows past the retention window and refresh the daily rollups.
    fn prune(&mut self, now: i64) -> anyhow::Result<()>;
}

/// Summaries the receipt and the TUI ask for.
#[derive(Debug, Clone, Default)]
pub struct Totals {
    pub connections: u64,
    pub apps: u64,
    pub sites: u64,
    pub tracker_hits: u64,
}
