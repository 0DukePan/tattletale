//! `tattle` with no arguments — the live view.

use std::io::Write;
use std::path::Path;

use crate::commands::paths;
use crate::live::Frame;
use crate::store::sqlite::SqliteStore;
use crate::watch::Watcher;

/// Run the live view until interrupted, then point at the next command.
pub fn run(out: &mut dyn Write, db: Option<&Path>) -> anyhow::Result<Frame> {
    let db_path = paths::db_path(db);
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let store = SqliteStore::open(&db_path)?;
    let frame = crate::live::run(Watcher::new(store))?;

    writeln!(out)?;
    writeln!(out, "  {}\n", frame.closing_hint())?;
    Ok(frame)
}
