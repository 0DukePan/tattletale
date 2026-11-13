//! The privacy claims, as executable assertions.
//!
//! A README that says "makes no outbound connections" is worthless unless
//! something fails when that stops being true. These tests read the source and
//! the rendered receipt, so the claim is checked by CI on every commit rather
//! than trusted.

use std::path::{Path, PathBuf};

/// Every `.rs` file in `src/`.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new("src"), &mut out);
    out
}

#[test]
fn only_two_modules_can_open_a_socket() {
    // `ureq` is the only network dependency, and it lives in exactly two
    // modules: the list loader and the updater. Both exist only behind a
    // command the user types. A third one appearing is a product change, not a
    // refactor.
    let allowed = tattletale::commands::update::NETWORK_MODULES;

    let mut offenders = Vec::new();
    for path in source_files() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if allowed.contains(&name) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("source file must be readable");
        if text.contains("ureq") {
            offenders.push(path.display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "these modules gained an HTTP client; the only two allowed are {allowed:?}: {offenders:#?}"
    );
}

#[test]
fn the_collection_loop_never_touches_the_network() {
    // The promise is not "no network anywhere", it is "no network while
    // collecting". `watch` runs for minutes at a time, so a request hidden in
    // that path would be the worst possible place for one.
    for module in [
        "src/watch.rs",
        "src/live.rs",
        "src/resolve.rs",
        "src/dns/mod.rs",
    ] {
        let text = std::fs::read_to_string(module).expect("source file must be readable");
        for forbidden in ["ureq", "TcpStream::connect", "UdpSocket::bind"] {
            assert!(
                !text.contains(forbidden),
                "{module} uses {forbidden}: collection must never open a socket"
            );
        }
    }
}

#[test]
fn the_default_command_stays_offline() {
    // The bare invocation runs the live view. If that ever grew a network call,
    // the product's central claim would be false for the way it is actually used.
    let main = std::fs::read_to_string("src/main.rs").expect("main.rs");
    assert!(
        main.contains("commands::live::run"),
        "the default command must remain the offline live view"
    );
    for command in ["commands::lists::", "commands::update::"] {
        assert!(main.contains(command), "main.rs should dispatch {command}");
    }
}

#[test]
fn no_heavy_http_stack_is_linked_in() {
    // A TLS stack pulled in "for convenience" is how a privacy tool quietly
    // becomes a telemetry client. Keep the dependency list honest.
    let manifest = std::fs::read_to_string("Cargo.toml").expect("Cargo.toml");
    for forbidden in ["reqwest", "hyper", "curl-sys", "isahc", "surf"] {
        assert!(
            !manifest.contains(forbidden),
            "Cargo.toml contains {forbidden}; the only HTTP client allowed is ureq in the list loader"
        );
    }
}

#[test]
fn the_receipt_is_self_contained() {
    // The receipt must open from a USB stick with no network. Any external
    // reference would break that promise and leak a request when opened.
    let model = tattletale::report::ReportModel {
        generated_at: 1_794_509_596,
        since: 1_794_509_596 - 86_400,
        machine: "TEST-PC".into(),
        totals: Default::default(),
        apps: vec![],
        sites: vec![],
        night: Default::default(),
        hourly: vec![0; 24],
        caveats: vec![],
        coverage: 0.0,
        named: 0,
        synthetic: false,
    };

    let html = tattletale::report::render(&model);

    for forbidden in [
        "http://",
        "https://",
        "<script src",
        "<link rel=\"stylesheet\"",
        "<iframe",
    ] {
        assert!(
            !html.contains(forbidden),
            "the receipt contains {forbidden:?}; it must be one self-contained file"
        );
    }

    // A real CSS import pulls a font from the network. The word itself appears
    // in the stylesheet's comment explaining why there are none, so match the
    // syntax rather than the word.
    assert!(
        !html.contains("@import url"),
        "the receipt imports an external stylesheet"
    );

    assert!(
        html.starts_with("<!doctype html>"),
        "the receipt must be a complete document"
    );
    assert!(html.contains("<style>"), "the stylesheet must be inlined");
}

#[test]
fn the_receipt_escapes_network_controlled_text() {
    // A hostname comes from the network. Rendering it unescaped would be an
    // injection vector in every receipt the user opens or shares.
    use tattletale::model::{App, Category, Tier};
    use tattletale::store::{AppRow, SiteRow};

    let hostile = r#"<img src=x onerror="alert(1)">"#.to_string();
    let model = tattletale::report::ReportModel {
        generated_at: 1_794_509_596,
        since: 1_794_509_596 - 86_400,
        machine: hostile.clone(),
        totals: Default::default(),
        apps: vec![AppRow {
            app: App {
                id: 1,
                path: hostile.clone(),
                name: hostile.clone(),
                friendly: hostile.clone(),
            },
            connections: 1,
            sites: 1,
            tracked: 0,
            tier: Tier::High,
            top_sites: vec![SiteRow {
                host: hostile.clone(),
                site: hostile.clone(),
                category: Category::Ads,
                connections: 1,
                tier: Tier::High,
            }],
        }],
        sites: vec![],
        night: Default::default(),
        hourly: vec![0; 24],
        caveats: vec![hostile.clone()],
        coverage: 1.0,
        named: 1,
        synthetic: false,
    };

    let html = tattletale::report::render(&model);
    assert!(
        !html.contains("<img src=x"),
        "a hostname reached the output unescaped"
    );
    assert!(
        html.contains("&lt;img"),
        "the hostile value should be escaped, not dropped"
    );
}

#[test]
fn no_source_file_contains_mojibake() {
    // Text written through a mis-decoding layer produces runs like "Ã©" or
    // "Â·". They are invisible in a terminal that guesses the encoding and
    // embarrassing in a README, so they are checked rather than trusted.
    let mut offenders = Vec::new();
    for path in source_files() {
        let text = std::fs::read_to_string(&path).expect("source file must be readable");
        // Real accented characters are a single scalar (é = U+00E9). The
        // mis-decoded form is two to four scalars starting with C3 or C2.
        if text.contains('\u{00C3}') || text.contains('\u{00C2}') {
            offenders.push(path.display().to_string());
        }
    }
    assert!(offenders.is_empty(), "mojibake found in: {offenders:#?}");
}
