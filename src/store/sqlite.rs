//! SQLite store. The only implementation that ships.
//!
//! Design notes that are easy to get wrong and expensive to fix later:
//!
//! * WAL mode, one connection, one writer thread. No `SQLITE_BUSY` handling
//!   because there is no contention by construction.
//! * The `live` table mirrors the tuples seen in the previous poll. A tuple that
//!   leaves `live` and comes back is a new open, which is what the receipt
//!   counts; without it a long-lived websocket would be counted once and a
//!   reconnecting client would never be counted at all.
//! * Categories are resolved at report time by suffix walk, so a list update
//!   retroactively improves reports already collected.

use std::path::Path;

use crate::dns::site_of;
use crate::model::{App, Category, Connection, DnsRecord, Proto, Sample, Tier};
use crate::store::{AppRow, SiteRow, Store, Totals};

/// The schema. Versioned so a v0.2 can migrate instead of dropping data.
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS app (
    id          INTEGER PRIMARY KEY,
    path        TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    friendly    TEXT    NOT NULL DEFAULT '',
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS domain (
    host        TEXT    PRIMARY KEY,
    site        TEXT    NOT NULL,
    category    TEXT    NOT NULL DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS conn (
    id          INTEGER PRIMARY KEY,
    app_id      INTEGER NOT NULL REFERENCES app(id),
    ip          TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    proto       TEXT    NOT NULL,
    first_at    INTEGER NOT NULL,
    last_at     INTEGER NOT NULL,
    last_open_at INTEGER NOT NULL DEFAULT 0,
    opens       INTEGER NOT NULL DEFAULT 1,
    UNIQUE(app_id, ip, port, proto)
);

CREATE INDEX IF NOT EXISTS conn_last ON conn(last_at);

CREATE TABLE IF NOT EXISTS live (
    app_id      INTEGER NOT NULL,
    ip          TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    proto       TEXT    NOT NULL,
    PRIMARY KEY(app_id, ip, port, proto)
);

CREATE TABLE IF NOT EXISTS dns_obs (
    host        TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    rtype       INTEGER NOT NULL,
    section     INTEGER NOT NULL,
    ttl         INTEGER NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    source      TEXT    NOT NULL,
    PRIMARY KEY(host, ip, rtype)
);

CREATE INDEX IF NOT EXISTS dns_ip ON dns_obs(ip, first_seen);

CREATE TABLE IF NOT EXISTS attribution (
    conn_id     INTEGER NOT NULL REFERENCES conn(id) ON DELETE CASCADE,
    host        TEXT    NOT NULL,
    site        TEXT    NOT NULL,
    tier        INTEGER NOT NULL,
    method      TEXT    NOT NULL,
    at          INTEGER NOT NULL,
    PRIMARY KEY(conn_id, host)
);

CREATE INDEX IF NOT EXISTS attribution_conn ON attribution(conn_id);

-- A connection the engine has already looked at, even when it found no name.
-- Without this, an `Unknown` decision would be retried on every pass forever.
CREATE TABLE IF NOT EXISTS resolved (
    conn_id     INTEGER PRIMARY KEY REFERENCES conn(id) ON DELETE CASCADE,
    tier        INTEGER NOT NULL,
    at          INTEGER NOT NULL
);
"#;

/// A SQLite-backed store.
pub struct SqliteStore {
    conn: rusqlite::Connection,
}

impl SqliteStore {
    /// Open or create a database at `path`.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        Self::init(conn)
    }

    /// An in-memory database, for tests and for `tattle demo`.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::init(rusqlite::Connection::open_in_memory()?)
    }

    fn init(conn: rusqlite::Connection) -> anyhow::Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }
}

impl Store for SqliteStore {
    fn record(&mut self, samples: &[Sample]) -> anyhow::Result<Vec<Connection>> {
        let tx = self.conn.transaction()?;
        let mut touched = Vec::new();

        for sample in samples {
            // Find or create the app inside the transaction.
            tx.execute(
                "INSERT INTO app (path, name, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(path) DO UPDATE SET last_seen = ?3",
                rusqlite::params![sample.app_path, sample.app_name, sample.at],
            )?;
            let app_id: i64 = tx.query_row(
                "SELECT id FROM app WHERE path = ?1",
                [&sample.app_path],
                |r| r.get(0),
            )?;

            let proto = sample.proto.as_str();
            let continued: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM live WHERE app_id=?1 AND ip=?2 AND port=?3 AND proto=?4)",
                rusqlite::params![app_id, sample.ip, sample.port, proto],
                |r| r.get(0),
            )?;

            if continued {
                tx.execute(
                    "UPDATE conn SET last_at = ?5 WHERE app_id=?1 AND ip=?2 AND port=?3 AND proto=?4",
                    rusqlite::params![app_id, sample.ip, sample.port, proto, sample.at],
                )?;
            } else {
                // New, or back after going away: either way, count an open.
                tx.execute(
                    "INSERT INTO conn (app_id, ip, port, proto, first_at, last_at, last_open_at, opens)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5, 1)
                     ON CONFLICT(app_id, ip, port, proto) DO UPDATE SET
                        last_at = ?5, last_open_at = ?5, opens = opens + 1",
                    rusqlite::params![app_id, sample.ip, sample.port, proto, sample.at],
                )?;
            }

            tx.execute(
                "INSERT OR IGNORE INTO live (app_id, ip, port, proto) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(app_id, ip, port, proto) DO NOTHING",
                rusqlite::params![app_id, sample.ip, sample.port, proto],
            )?;

            let conn = tx.query_row(
                "SELECT id, app_id, ip, port, proto, first_at, last_at, last_open_at, opens
                 FROM conn WHERE app_id=?1 AND ip=?2 AND port=?3 AND proto=?4",
                rusqlite::params![app_id, sample.ip, sample.port, proto],
                |row| {
                    Ok(Connection {
                        id: row.get(0)?,
                        app_id: row.get(1)?,
                        ip: row.get(2)?,
                        port: row.get::<_, i64>(3)? as u16,
                        proto: Proto::parse(&row.get::<_, String>(4)?).unwrap_or(Proto::Tcp),
                        first_at: row.get(5)?,
                        last_at: row.get(6)?,
                        last_open_at: row.get(7)?,
                        opens: row.get::<_, i64>(8)? as u32,
                    })
                },
            )?;
            touched.push(conn);
        }

        // Tuples that were live and are not in this batch have gone away.
        // SQLite has no "delete where not in this list" that scales, so a
        // marker table is used: clear and re-insert the live set.
        tx.execute("DELETE FROM live", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO live (app_id, ip, port, proto) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for sample in samples {
                let app_id: i64 = tx.query_row(
                    "SELECT id FROM app WHERE path = ?1",
                    [&sample.app_path],
                    |r| r.get(0),
                )?;
                stmt.execute(rusqlite::params![
                    app_id,
                    sample.ip,
                    sample.port,
                    sample.proto.as_str()
                ])?;
            }
        }

        tx.commit()?;
        Ok(touched)
    }

    fn record_dns(&mut self, records: &[DnsRecord]) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO dns_obs (host, ip, rtype, section, ttl, first_seen, last_seen, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(host, ip, rtype) DO UPDATE SET
                    first_seen = MIN(first_seen, excluded.first_seen),
                    last_seen  = MAX(last_seen, excluded.last_seen),
                    ttl        = excluded.ttl,
                    section    = MAX(section, excluded.section)",
            )?;
            for record in records {
                stmt.execute(rusqlite::params![
                    record.host,
                    record.ip,
                    record.rtype,
                    record.section as i64,
                    record.ttl,
                    record.first_seen,
                    record.last_seen,
                    record.source.as_str(),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn observations(&self, at: i64, window: i64) -> anyhow::Result<Vec<DnsRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT host, ip, rtype, section, ttl, first_seen, last_seen, source
             FROM dns_obs
             WHERE first_seen <= ?1 AND first_seen >= ?2
             ORDER BY first_seen DESC",
        )?;
        let rows = stmt.query_map(rusqlite::params![at + 3, at - window], |row| {
            Ok(DnsRecord {
                host: row.get(0)?,
                ip: row.get(1)?,
                rtype: row.get::<_, i64>(2)? as u16,
                section: match row.get::<_, i64>(3)? {
                    2 => crate::model::DnsSection::Answer,
                    1 => crate::model::DnsSection::Additional,
                    _ => crate::model::DnsSection::Ptr,
                },
                ttl: row.get::<_, i64>(4)? as u32,
                first_seen: row.get(5)?,
                last_seen: row.get(6)?,
                source: crate::model::DnsSource::parse(&row.get::<_, String>(7)?),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn save_attributions(&mut self, decisions: &[crate::resolve::Decision]) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO attribution (conn_id, host, site, tier, method, at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(conn_id, host) DO UPDATE SET tier = excluded.tier, method = excluded.method",
            )?;
            let mut domain = tx.prepare(
                "INSERT OR IGNORE INTO domain (host, site, category) VALUES (?1, ?2, 'unknown')",
            )?;
            // Record the attempt even when no name was found, so an `Unknown`
            // connection is not resolved again on every pass.
            let mut resolved = tx.prepare(
                "INSERT INTO resolved (conn_id, tier, at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(conn_id) DO UPDATE SET tier = excluded.tier, at = excluded.at",
            )?;

            for decision in decisions {
                for attribution in &decision.attributions {
                    stmt.execute(rusqlite::params![
                        attribution.conn_id,
                        attribution.host,
                        attribution.site,
                        attribution.tier.as_int(),
                        attribution.method,
                        attribution.at,
                    ])?;
                    domain.execute(rusqlite::params![attribution.host, attribution.site])?;
                }
                resolved.execute(rusqlite::params![
                    decision.conn_id,
                    decision.tier.as_int(),
                    decision.at
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn set_category(&mut self, host: &str, category: Category) -> anyhow::Result<()> {
        let site = site_of(host);
        self.conn.execute(
            "INSERT INTO domain (host, site, category) VALUES (?1, ?2, ?3)
             ON CONFLICT(host) DO UPDATE SET category = ?3",
            rusqlite::params![host, site, category.as_str()],
        )?;
        Ok(())
    }

    fn prune(&mut self, now: i64) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM conn WHERE last_at < ?1",
            [now - crate::store::CONNECTION_RETENTION_SECONDS],
        )?;
        self.conn.execute(
            "DELETE FROM dns_obs WHERE last_seen < ?1",
            [now - crate::store::DNS_RETENTION_SECONDS],
        )?;
        Ok(())
    }

    fn pending(&self, limit: usize) -> anyhow::Result<Vec<crate::resolve::Pending>> {
        // A connection is pending if it has never been resolved, or if it
        // reopened after the last resolution: a client that reconnects was
        // probably resolved again and deserves a fresh answer.
        let mut stmt = self.conn.prepare(
            "SELECT c.id, c.app_id, c.ip, c.last_open_at
             FROM conn c
             LEFT JOIN resolved r ON r.conn_id = c.id
             WHERE r.conn_id IS NULL OR c.last_open_at > r.at
             ORDER BY c.id
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| {
            Ok(crate::resolve::Pending {
                conn_id: row.get(0)?,
                app_id: row.get(1)?,
                ip: row.get(2)?,
                at: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn apps(&self) -> anyhow::Result<Vec<App>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, path, name, friendly FROM app ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            Ok(App {
                id: row.get(0)?,
                path: row.get(1)?,
                name: row.get(2)?,
                friendly: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn totals(&self, since: i64) -> anyhow::Result<Totals> {
        let connections: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(opens), 0) FROM conn WHERE last_at >= ?1",
            [since],
            |r| r.get(0),
        )?;
        let apps: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT app_id) FROM conn WHERE last_at >= ?1",
            [since],
            |r| r.get(0),
        )?;
        let sites: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT a.site) FROM attribution a
             JOIN conn c ON c.id = a.conn_id WHERE c.last_at >= ?1",
            [since],
            |r| r.get(0),
        )?;
        let tracked: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT a.conn_id) FROM attribution a
             JOIN conn c ON c.id = a.conn_id
             JOIN domain d ON d.host = a.host
             WHERE c.last_at >= ?1 AND d.category IN ('tracker','ads','analytics')",
            [since],
            |r| r.get(0),
        )?;
        Ok(Totals {
            connections: connections as u64,
            apps: apps as u64,
            sites: sites as u64,
            tracked: tracked as u64,
            flagged: 0,
        })
    }

    fn app_rows(&self, since: i64, limit: usize) -> anyhow::Result<Vec<AppRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.path, p.name, p.friendly,
                    COALESCE(SUM(c.opens), 0) AS conns,
                    COUNT(DISTINCT a.site)     AS sites,
                    COALESCE(SUM(CASE WHEN d.category IN ('tracker','ads','analytics') THEN c.opens ELSE 0 END), 0) AS tracked,
                    COALESCE(MAX(a.tier), 0)   AS tier
             FROM app p
             JOIN conn c ON c.app_id = p.id AND c.last_at >= ?1
             LEFT JOIN attribution a ON a.conn_id = c.id
             LEFT JOIN domain d ON d.host = a.host
             GROUP BY p.id
             ORDER BY conns DESC, p.name
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![since, limit as i64], |row| {
            Ok(AppRow {
                app: App {
                    id: row.get(0)?,
                    path: row.get(1)?,
                    name: row.get(2)?,
                    friendly: row.get(3)?,
                },
                connections: row.get::<_, i64>(4)? as u64,
                sites: row.get::<_, i64>(5)? as u64,
                tracked: row.get::<_, i64>(6)? as u64,
                tier: Tier::from_int(row.get(7)?),
                top_sites: Vec::new(),
            })
        })?;
        let mut apps = rows.collect::<Result<Vec<_>, _>>()?;

        for app in &mut apps {
            app.top_sites = self.top_sites_for(app.app.id, since, 5)?;
        }
        Ok(apps)
    }

    fn site_rows(&self, since: i64, limit: usize) -> anyhow::Result<Vec<SiteRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.site,
                    MIN(a.host),
                    COALESCE(d.category, 'unknown'),
                    COALESCE(SUM(c.opens), 0) AS conns,
                    COALESCE(MAX(a.tier), 0)
             FROM attribution a
             JOIN conn c ON c.id = a.conn_id AND c.last_at >= ?1
             LEFT JOIN domain d ON d.host = a.host
             GROUP BY a.site
             ORDER BY conns DESC, a.site
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![since, limit as i64], |row| {
            Ok(SiteRow {
                site: row.get(0)?,
                host: row.get(1)?,
                category: Category::parse(&row.get::<_, String>(2)?),
                connections: row.get::<_, i64>(3)? as u64,
                tier: Tier::from_int(row.get(4)?),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    fn events(&self, since: i64, limit: usize) -> anyhow::Result<Vec<crate::report::build::Event>> {
        // One row per connection, not per attribution: a connection that had
        // three candidate names is still one connection on the chart.
        let mut stmt = self.conn.prepare(
            "SELECT p.name, MIN(a.site), c.last_open_at, COALESCE(MAX(a.tier), 0), c.ip, c.port
             FROM conn c
             JOIN app p ON p.id = c.app_id
             LEFT JOIN attribution a ON a.conn_id = c.id
             WHERE c.last_at >= ?1
             GROUP BY c.id
             ORDER BY c.last_open_at
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![since, limit as i64], |row| {
            Ok(crate::report::build::Event {
                app: row.get(0)?,
                site: row.get::<_, Option<String>>(1)?,
                at: row.get(2)?,
                tier: Tier::from_int(row.get(3)?),
                ip: row.get(4)?,
                port: row.get::<_, i64>(5)? as u16,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

impl SqliteStore {
    fn top_sites_for(&self, app_id: i64, since: i64, limit: usize) -> anyhow::Result<Vec<SiteRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.site, MIN(a.host), COALESCE(d.category, 'unknown'),
                    COALESCE(SUM(c.opens), 0), COALESCE(MAX(a.tier), 0)
             FROM attribution a
             JOIN conn c ON c.id = a.conn_id AND c.app_id = ?1 AND c.last_at >= ?2
             LEFT JOIN domain d ON d.host = a.host
             GROUP BY a.site
             ORDER BY 4 DESC, a.site
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(rusqlite::params![app_id, since, limit as i64], |row| {
            Ok(SiteRow {
                site: row.get(0)?,
                host: row.get(1)?,
                category: Category::parse(&row.get::<_, String>(2)?),
                connections: row.get::<_, i64>(3)? as u64,
                tier: Tier::from_int(row.get(4)?),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}
