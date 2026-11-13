//! The CLI commands, as library code.
//!
//! Commands live here rather than in `main.rs` so they can be tested. Each one
//! takes its output sink as a parameter, which lets a test assert on what a user
//! would actually see without spawning a process, reading the real database, or
//! capturing a terminal.
//!
//! `main.rs` keeps only the argument schema, the dispatch, and the exit code.

pub mod accuracy;
pub mod app;
pub mod block;
pub mod demo;
pub mod doctor;
pub mod format;
pub mod lists;
pub mod live;
pub mod paths;
pub mod purge;
pub mod report;
pub mod top;
pub mod update;
pub mod watch;

pub use format::{parse_window, truncate, RankBy};
pub use paths::{data_dir, db_path, machine_name, report_path};

use std::path::Path;

use crate::store::sqlite::SqliteStore;

/// Open the database for a command that only reads it.
///
/// A missing file almost always means "I have not recorded anything yet", so it
/// gets an actionable message instead of an empty table that explains nothing.
pub(crate) fn open_store(db: &Path) -> anyhow::Result<SqliteStore> {
    if !db.exists() {
        anyhow::bail!(
            "nothing recorded yet ({} does not exist).\n  \
             run `tattle watch --duration 10m`, or `tattle demo` to see an example",
            db.display()
        );
    }
    SqliteStore::open(db)
}

/// The classifier every command reports through.
///
/// Loaded per invocation rather than cached: a command is a short-lived process,
/// and a stale in-memory list would be worse than a 40 ms read.
pub(crate) fn classifier() -> crate::classify::Classifier {
    crate::classify::Classifier::load(Some(&crate::classify::lists_dir()))
}
