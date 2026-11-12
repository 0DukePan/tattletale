//! In-memory store used by the tests and by `tattle replay`.
//!
//! It implements the same contract as the SQLite store, including the counting
//! rules, so a test that passes here is testing behaviour and not SQL. Keeping
//! the two implementations honest is the job of `tests/store_contract.rs`, which
//! runs the same assertions against both.

use std::collections::HashMap;

use crate::dns::site_of;
use crate::model::{App, Category, Connection, DnsRecord, Proto, Sample, Tier};
use crate::store::{AppRow, SiteRow, Store, Totals};

#[derive(Debug, Default)]
pub struct MemoryStore {
    apps: HashMap<String, App>,
    next_app_id: i64,
    /// Keyed by `(app_id, ip, port, proto)`.
    conns: HashMap<(i64, String, u16, Proto), Connection>,
    next_conn_id: i64,
    dns: HashMap<(String, String), DnsRecord>,
    /// `conn_id -> (host, tier)`.
    attributions: HashMap<i64, Vec<(String, Tier)>>,
    categories: HashMap<String, Category>,
    /// When each connection was last resolved by the engine.
    resolved: HashMap<i64, i64>,
    /// Tuples present in the previous poll. A tuple absent here and present now
    /// is a new open; a tuple present in both is the same connection continuing.
    live: std::collections::HashSet<(i64, String, u16, Proto)>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an application, returning its id. Repeated paths reuse the id.
    pub fn app_id(&mut self, sample: &Sample) -> i64 {
        if let Some(app) = self.apps.get(&sample.app_path) {
            return app.id;
        }
        self.next_app_id += 1;
        let id = self.next_app_id;
        let app = App {
            id,
            path: sample.app_path.clone(),
            name: sample.app_name.clone(),
            friendly: String::new(),
        };
        self.apps.insert(sample.app_path.clone(), app);
        id
    }

    pub fn connection(&self, id: i64) -> Option<&Connection> {
        self.conns.values().find(|c| c.id == id)
    }
}

impl Store for MemoryStore {
    fn record(&mut self, samples: &[Sample]) -> anyhow::Result<Vec<Connection>> {
        let mut seen: std::collections::HashSet<(i64, String, u16, Proto)> =
            std::collections::HashSet::with_capacity(samples.len());
        let mut touched = Vec::new();

        for sample in samples {
            let app_id = self.app_id(sample);
            let key = (app_id, sample.ip.clone(), sample.port, sample.proto);
            seen.insert(key.clone());

            let continued = self.live.contains(&key);
            match self.conns.get_mut(&key) {
                Some(existing) if continued => {
                    // Same tuple, still alive: extend it, do not count it twice.
                    existing.last_at = sample.at;
                }
                Some(existing) => {
                    // The tuple had gone away and came back: a new open, and
                    // a new chance for the resolver to have named it.
                    existing.last_at = sample.at;
                    existing.last_open_at = sample.at;
                    existing.opens += 1;
                }
                None => {
                    self.next_conn_id += 1;
                    let id = self.next_conn_id;
                    let conn = Connection {
                        id,
                        app_id,
                        ip: sample.ip.clone(),
                        port: sample.port,
                        proto: sample.proto,
                        first_at: sample.at,
                        last_at: sample.at,
                        last_open_at: sample.at,
                        opens: 1,
                    };
                    self.conns.insert(key.clone(), conn);
                }
            }

            if let Some(conn) = self.conns.get(&key) {
                touched.push(conn.clone());
            }
        }

        // Anything not seen in this batch has gone away.
        self.live = seen;
        Ok(touched)
    }

    fn record_dns(&mut self, records: &[DnsRecord]) -> anyhow::Result<()> {
        for record in records {
            let key = (record.host.clone(), record.ip.clone());
            match self.dns.get_mut(&key) {
                Some(existing) => {
                    // Keep the earliest sighting: that is when the name was
                    // resolved, which is what the engine scores against.
                    if record.first_seen < existing.first_seen {
                        existing.first_seen = record.first_seen;
                    }
                    existing.last_seen = existing.last_seen.max(record.last_seen);
                    existing.ttl = record.ttl;
                    existing.section = existing.section.max(record.section);
                }
                None => {
                    self.dns.insert(key, record.clone());
                }
            }
        }
        Ok(())
    }

    fn observations(&self, at: i64, window: i64) -> anyhow::Result<Vec<DnsRecord>> {
        let mut out: Vec<DnsRecord> = self
            .dns
            .values()
            .filter(|r| r.first_seen <= at + 3 && r.first_seen >= at - window)
            .cloned()
            .collect();
        out.sort_by_key(|r| -r.first_seen);
        Ok(out)
    }

    fn save_attributions(&mut self, decisions: &[crate::resolve::Decision]) -> anyhow::Result<()> {
        for decision in decisions {
            let rows = decision
                .attributions
                .iter()
                .map(|a| (a.host.clone(), a.tier))
                .collect::<Vec<_>>();
            self.attributions.insert(decision.conn_id, rows);
            // Record the attempt even when no name was found: an `Unknown`
            // decision is an answer, and must not be recomputed forever.
            self.resolved.insert(decision.conn_id, decision.at);
        }
        Ok(())
    }

    fn set_category(&mut self, host: &str, category: Category) -> anyhow::Result<()> {
        self.categories.insert(host.to_string(), category);
        Ok(())
    }

    fn prune(&mut self, now: i64) -> anyhow::Result<()> {
        let conn_cutoff = now - crate::store::CONNECTION_RETENTION_SECONDS;
        let dns_cutoff = now - crate::store::DNS_RETENTION_SECONDS;
        self.conns.retain(|_, conn| conn.last_at >= conn_cutoff);
        self.dns.retain(|_, record| record.last_seen >= dns_cutoff);
        Ok(())
    }

    fn pending(&self, limit: usize) -> anyhow::Result<Vec<crate::resolve::Pending>> {
        // Pending means "never resolved", or "reopened since the last
        // resolution". The second case is why a reconnecting client gets a
        // fresh answer instead of the stale one from its first connection.
        let mut out: Vec<crate::resolve::Pending> = self
            .conns
            .values()
            .filter(|conn| match self.resolved.get(&conn.id) {
                None => true,
                Some(at) => conn.last_open_at > *at,
            })
            .map(|conn| crate::resolve::Pending {
                conn_id: conn.id,
                app_id: conn.app_id,
                ip: conn.ip.clone(),
                at: conn.last_open_at,
            })
            .collect();
        out.sort_by_key(|p| p.conn_id);
        out.truncate(limit);
        Ok(out)
    }

    fn apps(&self) -> anyhow::Result<Vec<App>> {
        let mut apps: Vec<App> = self.apps.values().cloned().collect();
        apps.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(apps)
    }

    fn totals(&self, since: i64) -> anyhow::Result<Totals> {
        let live: Vec<&Connection> = self.conns.values().filter(|c| c.last_at >= since).collect();
        let mut apps: Vec<i64> = live.iter().map(|c| c.app_id).collect();
        apps.sort_unstable();
        apps.dedup();

        let mut sites: Vec<String> = Vec::new();
        let mut tracked = 0u64;
        for conn in &live {
            if let Some(rows) = self.attributions.get(&conn.id) {
                if let Some((host, _)) = rows.first() {
                    sites.push(site_of(host));
                    if self.is_tracked(host) {
                        tracked += 1;
                    }
                }
            }
        }
        sites.sort();
        sites.dedup();

        Ok(Totals {
            connections: live.iter().map(|c| c.opens as u64).sum(),
            apps: apps.len() as u64,
            sites: sites.len() as u64,
            tracked,
            flagged: 0,
        })
    }

    fn app_rows(&self, since: i64, limit: usize) -> anyhow::Result<Vec<AppRow>> {
        let mut by_app: HashMap<i64, Vec<&Connection>> = HashMap::new();
        for conn in self.conns.values().filter(|c| c.last_at >= since) {
            by_app.entry(conn.app_id).or_default().push(conn);
        }

        let mut rows: Vec<AppRow> = by_app
            .into_iter()
            .filter_map(|(app_id, conns)| {
                let app = self.apps.values().find(|a| a.id == app_id)?.clone();
                let mut sites: HashMap<String, (u64, Tier, String)> = HashMap::new();
                let mut tracked = 0u64;

                for conn in &conns {
                    let Some(attr) = self.attributions.get(&conn.id).and_then(|a| a.first()) else {
                        continue;
                    };
                    let (host, tier) = attr;
                    if self.is_tracked(host) {
                        tracked += 1;
                    }
                    let entry =
                        sites
                            .entry(site_of(host))
                            .or_insert((0, Tier::Unknown, host.clone()));
                    entry.0 += conn.opens as u64;
                    if *tier > entry.1 {
                        entry.1 = *tier;
                    }
                }

                let tier = sites
                    .values()
                    .map(|(_, t, _)| *t)
                    .max()
                    .unwrap_or(Tier::Unknown);
                let mut top_sites: Vec<SiteRow> = sites
                    .into_iter()
                    .map(|(site, (connections, tier, host))| SiteRow {
                        category: self.category_of(&host),
                        host,
                        site,
                        connections,
                        tier,
                    })
                    .collect();
                top_sites
                    .sort_by(|a, b| b.connections.cmp(&a.connections).then(a.site.cmp(&b.site)));

                Some(AppRow {
                    app,
                    connections: conns.iter().map(|c| c.opens as u64).sum(),
                    sites: top_sites.len() as u64,
                    tracked,
                    tier,
                    top_sites,
                })
            })
            .collect();

        rows.sort_by(|a, b| {
            b.connections
                .cmp(&a.connections)
                .then(a.app.name.cmp(&b.app.name))
        });
        rows.truncate(limit);
        Ok(rows)
    }

    fn site_rows(&self, since: i64, limit: usize) -> anyhow::Result<Vec<SiteRow>> {
        let mut sites: HashMap<String, (u64, Tier, String)> = HashMap::new();
        for conn in self.conns.values().filter(|c| c.last_at >= since) {
            let Some((host, tier)) = self.attributions.get(&conn.id).and_then(|a| a.first()) else {
                continue;
            };
            let entry = sites
                .entry(site_of(host))
                .or_insert((0, Tier::Unknown, host.clone()));
            entry.0 += conn.opens as u64;
            if *tier > entry.1 {
                entry.1 = *tier;
            }
        }

        let mut rows: Vec<SiteRow> = sites
            .into_iter()
            .map(|(site, (connections, tier, host))| SiteRow {
                category: self.category_of(&host),
                host,
                site,
                connections,
                tier,
            })
            .collect();
        rows.sort_by(|a, b| b.connections.cmp(&a.connections).then(a.site.cmp(&b.site)));
        rows.truncate(limit);
        Ok(rows)
    }
    fn events(&self, since: i64, limit: usize) -> anyhow::Result<Vec<crate::report::build::Event>> {
        let app_names: std::collections::HashMap<i64, String> =
            self.apps.values().map(|a| (a.id, a.name.clone())).collect();

        let mut out: Vec<crate::report::build::Event> = self
            .conns
            .values()
            .filter(|c| c.last_at >= since)
            .map(|conn| crate::report::build::Event {
                app: app_names.get(&conn.app_id).cloned().unwrap_or_default(),
                site: self
                    .attributions
                    .get(&conn.id)
                    .and_then(|rows| rows.first())
                    .map(|(host, _)| site_of(host)),
                at: conn.last_open_at,
                ip: conn.ip.clone(),
                port: conn.port,
                tier: self
                    .attributions
                    .get(&conn.id)
                    .and_then(|rows| rows.first())
                    .map(|(_, tier)| *tier)
                    .unwrap_or(Tier::Unknown),
            })
            .collect();
        out.sort_by_key(|e| e.at);
        out.truncate(limit);
        Ok(out)
    }
}

impl MemoryStore {
    fn is_tracked(&self, host: &str) -> bool {
        self.category_of(host).is_flagged()
    }

    fn category_of(&self, host: &str) -> Category {
        let mut probe = host;
        loop {
            if let Some(category) = self.categories.get(probe) {
                return *category;
            }
            match probe.split_once('.') {
                Some((_, rest)) if rest.contains('.') => probe = rest,
                Some((_, rest)) => {
                    return self
                        .categories
                        .get(rest)
                        .copied()
                        .unwrap_or(Category::Unknown);
                }
                None => return Category::Unknown,
            }
        }
    }
}
