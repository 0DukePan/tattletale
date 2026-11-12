//! `tattle app` — one application's traffic, by site.

use std::io::Write;
use std::path::Path;

use crate::commands::{
    classifier,
    format::{parse_window, plural, truncate},
    open_store, paths,
};
use crate::model::Category;
use crate::store::Store;

/// Print every site one application contacted.
pub fn run(
    out: &mut dyn Write,
    db: Option<&Path>,
    name: &str,
    since: &str,
    now: i64,
) -> anyhow::Result<()> {
    let window = parse_window(since)?;
    let store = open_store(&paths::db_path(db))?;
    let needle = name.to_ascii_lowercase();

    let matching: Vec<_> = store
        .app_rows(now - window, 100)?
        .into_iter()
        .filter(|row| row.app.display().to_ascii_lowercase().contains(&needle))
        .collect();

    if matching.is_empty() {
        anyhow::bail!("no recorded application matches {name:?} in the last {since}");
    }

    let classifier = classifier();
    for row in matching {
        writeln!(
            out,
            "\n{}  ({}, {}, {} flagged)\n",
            row.app.display(),
            plural(row.connections, "connection"),
            plural(row.sites, "site"),
            row.tracked
        )?;
        writeln!(
            out,
            "  {:<10} {:<40} {:>6}  VERDICT",
            "CONF", "SITE", "CONNS"
        )?;
        for site in &row.top_sites {
            let verdict = match classifier.classify(&site.host) {
                Category::Unknown => "",
                other => other.as_str(),
            };
            writeln!(
                out,
                "  {:<10} {:<40} {:>6}  {}",
                site.tier.glyph(),
                truncate(&site.site, 40),
                site.connections,
                verdict
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Proto, Sample};

    fn seeded(dir: &tempfile::TempDir, now: i64) -> std::path::PathBuf {
        let db = dir.path().join("t.db");
        let mut store = crate::store::sqlite::SqliteStore::open(&db).expect("open");
        store
            .record(&[
                Sample {
                    at: now,
                    app_path: "C:\\x\\chrome.exe".into(),
                    app_name: "chrome.exe".into(),
                    ip: "203.0.113.10".into(),
                    port: 443,
                    proto: Proto::Tcp,
                },
                Sample {
                    at: now,
                    app_path: "C:\\x\\slack.exe".into(),
                    app_name: "slack.exe".into(),
                    ip: "203.0.113.11".into(),
                    port: 443,
                    proto: Proto::Tcp,
                },
            ])
            .expect("record");
        db
    }

    #[test]
    fn matching_is_case_insensitive_and_partial() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000;
        let db = seeded(&dir, now);

        let mut sink = Vec::new();
        run(&mut sink, Some(&db), "CHROME", "1h", now).expect("run");
        let text = String::from_utf8(sink).unwrap();

        assert!(text.contains("chrome.exe"), "got: {text}");
        assert!(
            !text.contains("slack.exe"),
            "only the match should be shown"
        );
        assert!(text.contains("CONF"), "the table needs a header");
    }

    #[test]
    fn an_unknown_application_is_an_error_not_an_empty_table() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000;
        let db = seeded(&dir, now);

        let mut sink = Vec::new();
        let err = run(&mut sink, Some(&db), "not-a-real-app", "1h", now).unwrap_err();
        assert!(
            err.to_string().contains("no recorded application matches"),
            "got: {err}"
        );
        assert!(sink.is_empty(), "nothing is printed on failure");
    }

    #[test]
    fn the_header_reports_the_totals_for_that_application() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000;
        let db = seeded(&dir, now);

        let mut sink = Vec::new();
        run(&mut sink, Some(&db), "slack", "1h", now).expect("run");
        let text = String::from_utf8(sink).unwrap();
        // Singular, not "1 connections": this header is on every run.
        assert!(
            text.contains("1 connection,"),
            "the header must be grammatical: {text}"
        );
        assert!(text.contains("0 sites"), "plural for zero: {text}");
        assert!(!text.contains("1 sites"), "got: {text}");
    }
}
