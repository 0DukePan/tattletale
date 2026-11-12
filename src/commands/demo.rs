//! `tattle demo` — render a labelled synthetic day.

use std::io::Write;
use std::path::Path;

use crate::commands::paths;
use crate::store::{sqlite::SqliteStore, Store};

/// Build the demo scene, render a receipt, and write it.
///
/// The data is synthetic and the receipt says so in a banner. A fabricated
/// screenshot presented as real would be the one unforgivable thing a privacy
/// tool could do, so the label is part of the output rather than a footnote.
pub fn run(
    out: &mut dyn Write,
    target: Option<&Path>,
    now: i64,
    open: bool,
) -> anyhow::Result<std::path::PathBuf> {
    let since = now - 24 * 3600;

    // An in-memory database, never the user's: a synthetic row must not be able
    // to contaminate a real receipt.
    let mut store = SqliteStore::open_in_memory()?;

    let (day_samples, day_names) = crate::demo::materialise(crate::demo::BROWSING, since, now, 24);
    let (night_samples, night_names) =
        crate::demo::materialise_night(crate::demo::NIGHT, since, now, 24);

    store.record_dns(&day_names)?;
    store.record_dns(&night_names)?;

    // Replay one second at a time so the store's open/continue logic runs for
    // real instead of being faked with a precomputed counter.
    let mut all = day_samples;
    all.extend(night_samples);
    all.sort_by_key(|sample| sample.at);

    let mut index = 0;
    while index < all.len() {
        let at = all[index].at;
        let end = all[index..]
            .iter()
            .position(|s| s.at != at)
            .map_or(all.len(), |p| index + p);
        store.record(&all[index..end])?;

        let pending = store.pending(512)?;
        if !pending.is_empty() {
            let observations = store.observations(at, crate::resolve::WINDOW_SECONDS)?;
            let decisions = crate::resolve::resolve(&pending, &observations);
            store.save_attributions(&decisions)?;
        }
        index = end;
    }

    let mut model =
        crate::report::build::build(&store as &dyn Store, since, now, "demo machine".to_string())?;
    model.synthetic = true;
    model.caveats.push(
        "This receipt is built from a synthetic scene, not from observed traffic. \
         Run `tattle watch` to record your own."
            .to_string(),
    );

    let path = paths::report_path(target);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&path, crate::report::render(&model))?;

    writeln!(out, "synthetic receipt written to {}", path.display())?;
    writeln!(
        out,
        "  {} connections | {} apps | {} sites | {:.0}% flagged | {:.0}% named",
        model.totals.connections,
        model.totals.apps,
        model.totals.sites,
        model.tracker_share(),
        model.coverage * 100.0
    )?;

    if open {
        super::report::open_in_browser(&path);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_demo_receipt_is_labelled_synthetic() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("demo.html");
        let mut sink = Vec::new();

        run(&mut sink, Some(&target), 1_794_500_000, false).expect("run");

        let html = std::fs::read_to_string(&target).expect("receipt");
        assert!(
            html.contains("Synthetic demo data"),
            "the banner is mandatory"
        );
        assert!(
            html.contains("not a record of this machine"),
            "the banner must say what it is not"
        );

        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("synthetic receipt written to"), "got: {text}");
    }

    #[test]
    fn the_demo_shows_flagged_domains_so_the_feature_is_visible() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("demo.html");
        let mut sink = Vec::new();

        run(&mut sink, Some(&target), 1_794_500_000, false).expect("run");

        let text = String::from_utf8(sink).unwrap();
        // The demo exists to show the tracker chips; 0% would make it pointless.
        assert!(
            !text.contains("| 0% flagged"),
            "the demo scene must contain flaggable domains: {text}"
        );
    }

    #[test]
    fn the_demo_never_touches_the_real_database() {
        // It writes to an in-memory store, so a caller cannot point it at a
        // user's data even by passing --db.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("demo.html");
        let mut sink = Vec::new();
        run(&mut sink, Some(&target), 1_794_500_000, false).expect("run");
        assert!(!dir.path().join("tattletale.db").exists());
    }
}
