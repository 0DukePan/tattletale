//! `tattle watch` — record for a fixed duration, then summarise.

use std::io::Write;
use std::path::Path;

use crate::commands::{format::parse_window, paths};
use crate::store::sqlite::SqliteStore;
use crate::watch::{OncePerSecond, TickStats, Watcher};

/// Record for `duration`, then print what was seen.
pub fn run(
    out: &mut dyn Write,
    db: Option<&Path>,
    duration: &str,
    now: i64,
    reverse_dns: bool,
) -> anyhow::Result<TickStats> {
    let span = parse_window(duration)?;
    let db_path = paths::db_path(db);
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let store = SqliteStore::open(&db_path)?;
    let mut watcher = Watcher::new(store).with_reverse_dns(reverse_dns);
    let started = now;

    writeln!(out, "recording for {duration} into {}", db_path.display())?;

    // Accumulate across ticks. Reporting only the final tick made the summary
    // say "0 attributed" whenever the last second happened to have no new
    // connections, which reads as if attribution had failed entirely.
    let mut total = TickStats::default();
    let mut peak_connections = 0usize;
    let mut last_names = 0usize;

    watcher.run(
        std::time::Duration::from_secs(span as u64),
        &mut OncePerSecond,
        |stats| {
            total.resolved += stats.resolved;
            peak_connections = peak_connections.max(stats.connections);
            if stats.names > 0 {
                last_names = stats.names;
            }
        },
    )?;
    watcher.finish(crate::now_unix())?;

    writeln!(
        out,
        "done: up to {peak_connections} connections observed, \
         {last_names} names in the resolver cache, {} attributed",
        total.resolved
    )?;
    writeln!(
        out,
        "elapsed {}s; next: tattle report --since {}",
        crate::now_unix() - started,
        duration
    )?;

    Ok(TickStats {
        connections: peak_connections,
        names: last_names,
        resolved: total.resolved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invalid_duration_fails_before_creating_a_database() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let mut sink = Vec::new();

        let err = run(&mut sink, Some(&db), "5x", 0, false).unwrap_err();
        assert!(err.to_string().contains("unknown unit"), "got: {err}");
        assert!(!db.exists(), "a bad argument must not create a database");
        assert!(sink.is_empty(), "nothing printed on failure");
    }

    #[test]
    fn a_zero_duration_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = Vec::new();
        assert!(run(&mut sink, Some(&dir.path().join("t.db")), "0s", 0, false).is_err());
    }
}
