//! Persistence. SQLite in production, in-memory in tests.
//!
//! The trait exists so the attribution engine and the report renderer can be
//! tested against a fake store without creating files or depending on timing.
//! The SQLite implementation is the only one that ships.

pub mod memory;
pub mod sqlite;

use crate::model::{App, Category, Connection, DnsRecord, Sample, Tier};

/// Everything the rest of the program needs from storage.
pub trait Store {
    /// Merge a batch of polled connections.
    ///
    /// A connection is identified by `(app, address, port, protocol)`; seeing
    /// the same tuple again updates `last_at`, and seeing it again *after* it
    /// disappeared increments `opens`. That counter is what the receipt calls
    /// "connections", so it must not be inflated by the poll rate.
    fn record(&mut self, samples: &[Sample]) -> anyhow::Result<Vec<Connection>>;

    /// Merge observed DNS answers.
    fn record_dns(&mut self, records: &[DnsRecord]) -> anyhow::Result<()>;

    /// Records resolved recently enough to explain a connection opening at
    /// `at`. This is the engine's candidate query.
    fn observations(&self, at: i64, window: i64) -> anyhow::Result<Vec<DnsRecord>>;

    /// Persist the attribution decisions for a batch of connections.
    fn save_attributions(&mut self, decisions: &[crate::resolve::Decision]) -> anyhow::Result<()>;

    /// Attach a category to a host, so later reports need no list.
    fn set_category(&mut self, host: &str, category: Category) -> anyhow::Result<()>;

    /// Drop rows past the retention window.
    fn prune(&mut self, now: i64) -> anyhow::Result<()>;

    /// Connections that have no attribution yet, for the next resolve pass.
    fn pending(&self, limit: usize) -> anyhow::Result<Vec<crate::resolve::Pending>>;

    /// All applications seen, for the TUI and the receipt.
    fn apps(&self) -> anyhow::Result<Vec<App>>;

    /// Totals for a time window, for the receipt headline.
    fn totals(&self, since: i64) -> anyhow::Result<Totals>;

    /// Per-application rows for a time window, best first.
    fn app_rows(&self, since: i64, limit: usize) -> anyhow::Result<Vec<AppRow>>;

    /// Per-site rows for a time window, best first.
    fn site_rows(&self, since: i64, limit: usize) -> anyhow::Result<Vec<SiteRow>>;

    /// Individual connections in a window, oldest first, for time-based
    /// aggregation (the hourly chart, the night summary).
    fn events(&self, since: i64, limit: usize) -> anyhow::Result<Vec<crate::report::build::Event>>;
}

/// Headline numbers for a time window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Totals {
    pub connections: u64,
    pub apps: u64,
    pub sites: u64,
    /// Connections whose best candidate is on a tracker list.
    pub tracked: u64,
}

/// One application's traffic in a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRow {
    pub app: App,
    pub connections: u64,
    pub sites: u64,
    pub tracked: u64,
    /// Best tier seen for this app, for the confidence badge.
    pub tier: Tier,
    /// Top sites, best first.
    pub top_sites: Vec<SiteRow>,
}

/// One site's traffic in a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteRow {
    pub host: String,
    pub site: String,
    pub category: Category,
    pub connections: u64,
    pub tier: Tier,
}

/// Retention defaults: detailed rows are cheap but not free.
pub const CONNECTION_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const DNS_RETENTION_SECONDS: i64 = 24 * 60 * 60;
