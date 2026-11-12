//! `tattle lists` — inspect and refresh the tracker lists.

use std::io::Write;
use std::path::Path;

use crate::classify;

/// Show which lists are loaded and how many rules they carry.
pub fn status(out: &mut dyn Write, lists_dir: &Path) -> anyhow::Result<()> {
    let classifier = classify::Classifier::load(Some(lists_dir));
    let seed = classify::Classifier::seed();

    writeln!(out, "lists directory  {}", lists_dir.display())?;
    writeln!(out, "rules loaded     {}", classifier.len())?;
    writeln!(out, "source           {}", classifier.source())?;
    writeln!(out, "  bundled seed   {} rules", seed.len())?;

    let mut downloaded = 0;
    if let Ok(entries) = std::fs::read_dir(lists_dir) {
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|e| e == "txt") {
                downloaded += 1;
            }
        }
    }
    writeln!(out, "  downloaded     {downloaded} file(s)")?;
    if downloaded == 0 {
        writeln!(
            out,
            "\nNo downloaded lists. `tattle lists update` fetches them."
        )?;
    }
    Ok(())
}

/// Download every source into `lists_dir`.
///
/// A failed list is reported and skipped: a partial update is better than none,
/// and the bundled seed still works offline.
pub fn update(out: &mut dyn Write, lists_dir: &Path) -> anyhow::Result<usize> {
    std::fs::create_dir_all(lists_dir)?;
    writeln!(
        out,
        "downloading tracker lists into {}",
        lists_dir.display()
    )?;

    let mut total = 0usize;
    for source in classify::SOURCES {
        match classify::download(source, lists_dir) {
            Ok(rules) => {
                total += rules;
                writeln!(out, "  {:<28} {:>7} rules", source.name, rules)?;
            }
            Err(err) => {
                writeln!(out, "  {:<28} failed: {err}", source.name)?;
            }
        }
    }

    let active = classify::Classifier::load(Some(lists_dir)).len();
    writeln!(out, "\n{total} rules downloaded; {active} rules active")?;
    if total == 0 {
        anyhow::bail!("no list could be downloaded; check the network and the URLs");
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_the_seed_when_nothing_is_downloaded() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = Vec::new();
        status(&mut sink, dir.path()).expect("status");

        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("bundled seed"), "got: {text}");
        assert!(text.contains("downloaded     0 file(s)"), "got: {text}");
        assert!(text.contains("lists update"), "must say how to get more");
    }

    #[test]
    fn status_counts_a_downloaded_list() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("some-list.txt"), "ads.example\n").expect("write");

        let mut sink = Vec::new();
        status(&mut sink, dir.path()).expect("status");
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("downloaded     1 file(s)"), "got: {text}");
    }

    #[test]
    fn status_does_not_require_the_directory_to_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-created-yet");
        let mut sink = Vec::new();
        status(&mut sink, &missing).expect("status on a missing directory");
    }
}
