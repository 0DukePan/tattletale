//! `tattle top` — rank applications, sites or domains.

use std::io::Write;
use std::path::Path;

use crate::commands::{
    classifier,
    format::{parse_window, truncate, RankBy},
    open_store, paths,
};
use crate::model::Category;
use crate::store::Store;

/// Print a ranked table.
///
/// This exists because most people will never open the HTML receipt, and a
/// one-screen answer is often all they wanted.
pub fn run(
    out: &mut dyn Write,
    db: Option<&Path>,
    since: &str,
    by: RankBy,
    limit: usize,
    json: bool,
    now: i64,
) -> anyhow::Result<()> {
    let window = parse_window(since)?;
    let store = open_store(&paths::db_path(db))?;
    let classifier = classifier();

    match by {
        RankBy::Apps => {
            let rows = store.app_rows(now - window, limit)?;
            if json {
                let payload: Vec<_> = rows
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "app": r.app.display(),
                            "path": r.app.path,
                            "connections": r.connections,
                            "sites": r.sites,
                            "flagged": r.tracked,
                            "confidence": r.tier.label(),
                        })
                    })
                    .collect();
                writeln!(out, "{}", serde_json::to_string_pretty(&payload)?)?;
                return Ok(());
            }
            if rows.is_empty() {
                writeln!(out, "nothing recorded in the last {since}")?;
                return Ok(());
            }
            writeln!(
                out,
                "{:<28} {:>7} {:>7} {:>9}",
                "APP", "CONNS", "SITES", "FLAGGED"
            )?;
            for row in rows {
                let flagged = if row.tracked > 0 {
                    format!("{} !", row.tracked)
                } else {
                    row.tracked.to_string()
                };
                writeln!(
                    out,
                    "{:<28} {:>7} {:>7} {:>9}",
                    truncate(row.app.display(), 28),
                    row.connections,
                    row.sites,
                    flagged
                )?;
            }
        }
        RankBy::Sites => {
            let rows = store.site_rows(now - window, limit)?;
            if json {
                let payload: Vec<_> = rows
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "site": r.site,
                            "host": r.host,
                            "connections": r.connections,
                            "category": classifier.classify(&r.host).as_str(),
                            "confidence": r.tier.label(),
                        })
                    })
                    .collect();
                writeln!(out, "{}", serde_json::to_string_pretty(&payload)?)?;
                return Ok(());
            }
            writeln!(out, "{:<40} {:>7}  VERDICT", "SITE", "CONNS")?;
            for row in rows {
                writeln!(
                    out,
                    "{:<40} {:>7}  {}",
                    truncate(&row.site, 40),
                    row.connections,
                    verdict(classifier.classify(&row.host))
                )?;
            }
        }
        RankBy::Domains => {
            // Host level: the exact hostname behind a site.
            let rows = store.site_rows(now - window, limit.saturating_mul(4).max(limit))?;
            writeln!(out, "{:<52} {:>7}  VERDICT", "DOMAIN", "CONNS")?;
            for row in rows.into_iter().take(limit) {
                writeln!(
                    out,
                    "{:<52} {:>7}  {}",
                    truncate(&row.host, 52),
                    row.connections,
                    verdict(classifier.classify(&row.host))
                )?;
            }
        }
    }
    Ok(())
}

/// The word shown in the verdict column. An unlisted domain shows nothing,
/// because "not on a list" is not a finding.
fn verdict(category: Category) -> &'static str {
    match category {
        Category::Unknown => "",
        other => other.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Proto, Sample};

    fn seeded(db: &Path, now: i64) {
        let mut store = crate::store::sqlite::SqliteStore::open(db).expect("open");
        for (app, ip) in [
            ("chrome.exe", "203.0.113.10"),
            ("slack.exe", "203.0.113.11"),
        ] {
            store
                .record(&[Sample {
                    at: now,
                    app_path: format!("C:\\x\\{app}"),
                    app_name: app.into(),
                    ip: ip.into(),
                    port: 443,
                    proto: Proto::Tcp,
                }])
                .expect("record");
        }
    }

    #[test]
    fn a_missing_database_says_how_to_start_recording() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = Vec::new();
        let err = run(
            &mut sink,
            Some(&dir.path().join("none.db")),
            "1h",
            RankBy::Apps,
            10,
            false,
            0,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("nothing recorded yet"),
            "got: {err}"
        );
    }

    #[test]
    fn apps_are_listed_with_a_header_and_their_counts() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let now = 1_000_000;
        seeded(&db, now);

        let mut sink = Vec::new();
        run(&mut sink, Some(&db), "1h", RankBy::Apps, 10, false, now).expect("run");
        let text = String::from_utf8(sink).unwrap();

        assert!(text.contains("APP"), "a table needs a header: {text}");
        assert!(text.contains("chrome.exe"));
        assert!(text.contains("slack.exe"));
        assert_eq!(text.lines().count(), 3, "header plus two rows");
    }

    #[test]
    fn the_limit_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let now = 1_000_000;
        seeded(&db, now);

        let mut sink = Vec::new();
        run(&mut sink, Some(&db), "1h", RankBy::Apps, 1, false, now).expect("run");
        let text = String::from_utf8(sink).unwrap();
        assert_eq!(text.lines().count(), 2, "header plus one row: {text}");
    }

    #[test]
    fn json_output_is_valid_and_carries_the_same_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let now = 1_000_000;
        seeded(&db, now);

        let mut sink = Vec::new();
        run(&mut sink, Some(&db), "1h", RankBy::Apps, 10, true, now).expect("run");

        let parsed: serde_json::Value = serde_json::from_slice(&sink).expect("valid json");
        let array = parsed.as_array().expect("top-level array");
        assert_eq!(array.len(), 2);
        assert!(array.iter().any(|row| row["app"] == "chrome.exe"));
        assert!(array[0]["connections"].is_number());
        assert!(array[0]["confidence"].is_string());
    }

    #[test]
    fn an_empty_window_says_so_instead_of_printing_a_bare_header() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        crate::store::sqlite::SqliteStore::open(&db).expect("create");

        let mut sink = Vec::new();
        run(
            &mut sink,
            Some(&db),
            "1h",
            RankBy::Apps,
            10,
            false,
            5_000_000,
        )
        .expect("run");
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("nothing recorded"), "got: {text}");
    }

    #[test]
    fn an_unlisted_domain_has_no_verdict_word() {
        // "not on a list" is not a finding, so the column stays empty.
        assert_eq!(verdict(Category::Unknown), "");
        assert_eq!(verdict(Category::Ads), "ads");
    }
}
