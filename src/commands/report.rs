//! `tattle report` — write an HTML receipt.

use std::io::Write;
use std::path::Path;

use crate::commands::{format::parse_window, open_store, paths};
use crate::store::Store;

/// Write a receipt for a window ending now.
///
/// Returns the path written. `open` is separated out so a test never launches a
/// browser.
pub fn run(
    out: &mut dyn Write,
    db: Option<&Path>,
    since: &str,
    target: Option<&Path>,
    now: i64,
) -> anyhow::Result<std::path::PathBuf> {
    let window = parse_window(since)?;
    let store = open_store(&paths::db_path(db))?;

    let model = crate::report::build::build(
        &store as &dyn Store,
        now - window,
        now,
        paths::machine_name(),
    )?;

    let path = paths::report_path(target);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, crate::report::render(&model))?;

    if model.totals.connections == 0 {
        writeln!(out, "receipt written to {}", path.display())?;
        writeln!(out, "  nothing recorded in the last {since}")?;
        writeln!(out)?;
        writeln!(out, "  record something first:")?;
        writeln!(
            out,
            "    tattle watch --duration 10m   then  tattle report --open"
        )?;
        writeln!(out, "  or see what a receipt looks like:")?;
        writeln!(out, "    tattle demo --open")?;
        return Ok(path);
    }

    writeln!(out, "receipt written to {}", path.display())?;
    writeln!(
        out,
        "  {} connections | {} apps | {} sites | {:.0}% flagged",
        model.totals.connections,
        model.totals.apps,
        model.totals.sites,
        model.tracker_share()
    )?;

    Ok(path)
}

/// Open a path with the platform's default handler.
pub fn open_in_browser(path: &Path) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(path)
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Proto, Sample};

    fn seed(db: &Path, now: i64) {
        let mut store = crate::store::sqlite::SqliteStore::open(db).expect("open");
        store
            .record(&[Sample {
                at: now,
                app_path: "C:\\x\\chrome.exe".into(),
                app_name: "chrome.exe".into(),
                ip: "203.0.113.9".into(),
                port: 443,
                proto: Proto::Tcp,
            }])
            .expect("record");
    }

    #[test]
    fn an_empty_database_explains_how_to_fill_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let out_path = dir.path().join("r.html");
        let mut sink = Vec::new();

        // A missing database is an error, not an empty receipt.
        let err = run(&mut sink, Some(&db), "1h", Some(&out_path), 1_000).unwrap_err();
        assert!(
            err.to_string().contains("nothing recorded yet"),
            "got: {err}"
        );

        // An existing but empty database writes a receipt and says so.
        crate::store::sqlite::SqliteStore::open(&db).expect("create");
        let mut sink = Vec::new();
        run(&mut sink, Some(&db), "1h", Some(&out_path), 1_000).expect("run");
        let text = String::from_utf8(sink).unwrap();
        assert!(
            text.contains("nothing recorded in the last 1h"),
            "got: {text}"
        );
        assert!(
            text.contains("tattle demo"),
            "must offer the demo as a next step"
        );
        assert!(
            out_path.exists(),
            "the receipt file is written even when empty"
        );
    }

    #[test]
    fn a_populated_database_produces_a_receipt_with_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let out_path = dir.path().join("r.html");
        let now = 1_000_000;
        seed(&db, now);

        let mut sink = Vec::new();
        run(&mut sink, Some(&db), "1h", Some(&out_path), now).expect("run");

        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("receipt written to"), "got: {text}");
        assert!(
            text.contains("1 connections"),
            "the summary must carry the count: {text}"
        );

        let html = std::fs::read_to_string(&out_path).expect("receipt");
        assert!(html.starts_with("<!doctype html>"));
        assert!(
            html.contains("chrome.exe"),
            "the app must appear in the receipt"
        );
    }

    #[test]
    fn an_invalid_window_fails_before_touching_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = Vec::new();
        let err = run(&mut sink, Some(&dir.path().join("nope.db")), "5x", None, 0).unwrap_err();
        assert!(err.to_string().contains("unknown unit"), "got: {err}");
        assert!(
            sink.is_empty(),
            "nothing should be printed when the arguments are wrong"
        );
    }
}
