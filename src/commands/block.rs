//! `tattle block` — turn the findings into something you can act on.
//!
//! This tool does not block anything. A blocker needs elevation, a filter
//! driver or a hosts file, and it inherits a failure mode this project is not
//! willing to own: silently breaking an application with no way to tell why.
//!
//! What it does instead is produce the artefact a blocker would need — a
//! hosts-file fragment for the domains that were actually flagged on this
//! machine — so the decision and the mechanism stay with the user, who can see
//! what they are about to break and undo it in a text editor.

use std::io::Write;
use std::path::Path;

use crate::commands::{classifier, format::parse_window, open_store, paths};
use crate::store::Store;

/// Where Windows keeps its hosts file.
pub const HOSTS_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";

/// One line per blocked domain.
///
/// `0.0.0.0` rather than `127.0.0.1`: it is unreachable on purpose, so a
/// blocked domain fails fast instead of hitting a server on the loopback
/// interface that almost certainly is not listening.
pub fn hosts_line(domain: &str) -> String {
    format!("0.0.0.0 {domain}")
}

/// Write a hosts-file fragment for every flagged domain in the window.
///
/// Returns the number of domains written.
pub fn run(
    out: &mut dyn Write,
    db: Option<&Path>,
    since: &str,
    target: Option<&Path>,
    append: bool,
    now: i64,
) -> anyhow::Result<usize> {
    let window = parse_window(since)?;
    let store = open_store(&paths::db_path(db))?;
    let classifier = classifier();

    let mut domains: Vec<String> = store
        .site_rows(now - window, 500)?
        .into_iter()
        .filter(|row| classifier.classify(&row.host).is_flagged())
        .map(|row| row.site)
        .collect();
    domains.sort();
    domains.dedup();

    if domains.is_empty() {
        writeln!(
            out,
            "nothing was flagged in the last {since}, so there is nothing to block"
        )?;
        return Ok(0);
    }

    let mut body = String::new();
    body.push_str("# tattletale: domains flagged on this machine\n");
    body.push_str("# Applied by hand. Back up the original file first.\n");
    body.push_str("# A blocked domain fails to resolve, which can break an app.\n");
    for domain in &domains {
        body.push_str(&hosts_line(domain));
        body.push('\n');
    }

    match target {
        Some(path) => {
            use std::io::Write as _;
            let mut file = if append {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?
            } else {
                std::fs::File::create(path)?
            };
            file.write_all(body.as_bytes())?;
            writeln!(
                out,
                "{} domains written to {}",
                domains.len(),
                path.display()
            )?;
            if append {
                writeln!(out, "  appended; nothing already in that file was changed")?;
            }
        }
        None => {
            write!(out, "{body}")?;
            writeln!(out, "\n# {} domains", domains.len())?;
        }
    }

    writeln!(out)?;
    writeln!(out, "  to apply, save this into {HOSTS_PATH}")?;
    writeln!(
        out,
        "  that file needs administrator rights, and the tool does not ask for them"
    )?;
    writeln!(
        out,
        "  undo: remove the lines between the tattletale header and the end"
    )?;

    Ok(domains.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Proto, Sample};

    fn seeded(dir: &tempfile::TempDir, now: i64) -> std::path::PathBuf {
        let db = dir.path().join("t.db");
        let mut store = crate::store::sqlite::SqliteStore::open(&db).expect("open");
        store
            .record(&[Sample {
                at: now,
                app_path: "C:\\x\\chrome.exe".into(),
                app_name: "chrome.exe".into(),
                ip: "203.0.113.10".into(),
                port: 443,
                proto: Proto::Tcp,
            }])
            .expect("record");
        // Attribute it to a domain the bundled seed flags.
        let dns = crate::model::DnsRecord {
            host: "doubleclick.net".into(),
            ip: "203.0.113.10".into(),
            rtype: 1,
            section: crate::model::DnsSection::Answer,
            ttl: 300,
            first_seen: now - 1,
            last_seen: now,
            source: crate::model::DnsSource::Replay,
        };
        store.record_dns(&[dns]).expect("dns");
        let pending = store.pending(10).expect("pending");
        let observations = store.observations(now, 90).expect("obs");
        let decisions = crate::resolve::resolve(&pending, &observations);
        store.save_attributions(&decisions).expect("save");
        db
    }

    #[test]
    fn a_hosts_line_is_unroutable_by_design() {
        assert_eq!(hosts_line("doubleclick.net"), "0.0.0.0 doubleclick.net");
    }

    #[test]
    fn flagged_domains_are_written_as_hosts_entries() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000;
        let db = seeded(&dir, now);
        let mut sink = Vec::new();

        let count = run(&mut sink, Some(&db), "1h", None, false, now).expect("run");

        assert_eq!(count, 1);
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("0.0.0.0 doubleclick.net"), "got: {text}");
        assert!(
            text.contains("administrator rights"),
            "must state what applying needs"
        );
        assert!(text.contains("undo"), "must explain how to reverse it");
    }

    #[test]
    fn writing_to_a_file_produces_a_fragment_with_a_header() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000;
        let db = seeded(&dir, now);
        let target = dir.path().join("hosts.fragment");
        let mut sink = Vec::new();

        run(&mut sink, Some(&db), "1h", Some(&target), false, now).expect("run");

        let body = std::fs::read_to_string(&target).expect("fragment");
        assert!(
            body.starts_with("# tattletale"),
            "the fragment must be identifiable"
        );
        assert!(body.contains("0.0.0.0 doubleclick.net"));
        assert!(
            !body.contains("localhost"),
            "must not touch existing entries"
        );
    }

    #[test]
    fn appending_leaves_existing_content_alone() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000;
        let db = seeded(&dir, now);
        let target = dir.path().join("hosts.fragment");
        std::fs::write(&target, "# existing entry\n0.0.0.0 example.org\n").expect("pre");

        let mut sink = Vec::new();
        run(&mut sink, Some(&db), "1h", Some(&target), true, now).expect("run");

        let body = std::fs::read_to_string(&target).unwrap();
        assert!(
            body.starts_with("# existing entry"),
            "existing content must survive"
        );
        assert!(body.contains("0.0.0.0 doubleclick.net"));
    }

    #[test]
    fn nothing_flagged_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        crate::store::sqlite::SqliteStore::open(&db).expect("create");
        let mut sink = Vec::new();

        let count = run(&mut sink, Some(&db), "1h", None, false, 5_000_000).expect("run");
        assert_eq!(count, 0);
        assert!(String::from_utf8(sink)
            .unwrap()
            .contains("nothing to block"));
    }
}
