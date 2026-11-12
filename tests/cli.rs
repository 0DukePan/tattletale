//! End-to-end tests that run the compiled binary.
//!
//! Everything else in this project tests functions. These test the thing a user
//! actually types: argument parsing, exit codes, and which stream the output
//! goes to. The `watch` summary bug ("0 attributed" on an idle run) and the
//! `purge` prompt both lived in this gap — every function they call had a test.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The binary under test, built by cargo for this integration test.
const BIN: &str = env!("CARGO_BIN_EXE_tattle");

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("the binary must be runnable")
}

/// Run the binary with a working directory of its own, so a test that cares
/// about relative paths is not reading the state of the machine or of an
/// earlier manual run. The first version of this file asserted that no
/// `receipt.html` existed in the repository root, which failed because a
/// previous shell command had left one there.
fn run_in(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .output()
        .expect("the binary must be runnable")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

fn db_in(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("tattle.db")
}

#[test]
fn version_and_help_are_available_without_a_database() {
    let version = run(&["--version"]);
    assert!(version.status.success());
    assert!(
        stdout(&version).contains("tattle"),
        "got: {}",
        stdout(&version)
    );

    let help = run(&["--help"]);
    assert!(help.status.success());
    let text = stdout(&help);
    for command in [
        "report", "watch", "demo", "lists", "top", "app", "purge", "doctor",
    ] {
        assert!(text.contains(command), "help must list {command}: {text}");
    }
}

#[test]
fn doctor_succeeds_and_reports_this_machine() {
    let output = run(&["doctor"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let text = stdout(&output);
    assert!(text.contains("tattletale "), "got: {text}");
    assert!(text.contains("os "), "got: {text}");
    assert!(text.contains("db "), "got: {text}");
}

#[test]
fn demo_writes_a_labelled_receipt_and_exits_zero() {
    let dir = temp_dir();
    let target = dir.path().join("demo.html");

    let output = run(&["demo", "--out", target.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let html = std::fs::read_to_string(&target).expect("the receipt must exist");
    assert!(
        html.contains("Synthetic demo data"),
        "the banner is mandatory"
    );
    assert!(html.starts_with("<!doctype html>"));

    let text = stdout(&output);
    assert!(text.contains("synthetic receipt written to"), "got: {text}");
}

#[test]
fn a_missing_database_is_reported_on_stderr_with_a_next_step() {
    let dir = temp_dir();
    let missing = dir.path().join("absent.db");

    for args in [
        vec!["report", "--db", missing.to_str().unwrap()],
        vec!["top", "--db", missing.to_str().unwrap()],
        vec!["app", "chrome", "--db", missing.to_str().unwrap()],
    ] {
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "expected failure for {args:?}"
        );
        assert!(
            stdout(&output).is_empty(),
            "nothing belongs on stdout for {args:?}"
        );

        let err = stderr(&output);
        assert!(err.contains("nothing recorded yet"), "got: {err}");
        assert!(
            err.contains("tattle demo"),
            "the error must offer a next step: {err}"
        );
    }
}

#[test]
fn a_bad_window_fails_with_a_usable_message() {
    let dir = temp_dir();
    let output = run(&[
        "report",
        "--since",
        "5x",
        "--db",
        db_in(&dir).to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("unknown unit"),
        "got: {}",
        stderr(&output)
    );
}

#[test]
fn records_traffic_then_reports_on_it() {
    // One second of real collection. On a quiet machine this may observe
    // nothing, which must still be a success — the assertion is on the flow,
    // not on the machine having traffic.
    let dir = temp_dir();
    let db = db_in(&dir);
    let db_arg = db.to_str().unwrap();

    let watch = run(&["watch", "--duration", "1s", "--db", db_arg]);
    assert!(watch.status.success(), "stderr: {}", stderr(&watch));
    assert!(db.exists(), "watch must create the database");
    assert!(
        stdout(&watch).contains("recording for 1s"),
        "got: {}",
        stdout(&watch)
    );

    let top = run(&["top", "--since", "1h", "--db", db_arg]);
    assert!(top.status.success(), "stderr: {}", stderr(&top));
    assert!(!stdout(&top).is_empty(), "top must print something");

    let report = run(&[
        "report",
        "--since",
        "1h",
        "--db",
        db_arg,
        "--out",
        dir.path().join("r.html").to_str().unwrap(),
    ]);
    assert!(report.status.success(), "stderr: {}", stderr(&report));
    assert!(dir.path().join("r.html").exists());
}

#[test]
fn json_output_parses_as_json() {
    let dir = temp_dir();
    let db = db_in(&dir);
    let db_arg = db.to_str().unwrap();

    let watch = run(&["watch", "--duration", "1s", "--db", db_arg]);
    assert!(watch.status.success(), "stderr: {}", stderr(&watch));

    let output = run(&["top", "--since", "1h", "--db", db_arg, "--json"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("stdout must be valid JSON");
    assert!(parsed.is_array(), "the payload is a list of rows");
}

#[test]
fn purge_deletes_the_database_and_says_how_much() {
    let dir = temp_dir();
    let db = db_in(&dir);

    let watch = run(&["watch", "--duration", "1s", "--db", db.to_str().unwrap()]);
    assert!(watch.status.success());
    assert!(db.exists());

    let purge = run(&["purge", "--yes", "--db", db.to_str().unwrap()]);
    assert!(purge.status.success(), "stderr: {}", stderr(&purge));
    assert!(!db.exists(), "the database must be gone");
    assert!(
        stdout(&purge).contains("deleted"),
        "got: {}",
        stdout(&purge)
    );
}

#[test]
fn purge_without_confirmation_refuses_on_a_non_interactive_stdin() {
    // Reading a stray piped line as consent would delete a user's data by
    // accident. With no terminal there is nobody to ask, so it refuses.
    let dir = temp_dir();
    let db = db_in(&dir);
    let watch = run(&["watch", "--duration", "1s", "--db", db.to_str().unwrap()]);
    assert!(watch.status.success());

    let purge = run(&["purge", "--db", db.to_str().unwrap()]);
    assert_eq!(purge.status.code(), Some(1));
    assert!(db.exists(), "the database must survive a refused purge");
    assert!(
        stderr(&purge).contains("refusing to delete"),
        "got: {}",
        stderr(&purge)
    );
}

#[test]
fn lists_status_works_without_a_network() {
    let output = run(&["lists", "status"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("bundled seed"), "got: {text}");
    assert!(text.contains("rules loaded"), "got: {text}");
}

#[test]
fn an_unknown_subcommand_is_a_usage_error() {
    let output = run(&["definitely-not-a-command"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "clap usage errors exit with 2"
    );
}

#[test]
fn a_receipt_is_written_to_the_requested_path_only() {
    let dir = temp_dir();
    let db = db_in(&dir);
    let target = dir.path().join("nested").join("receipt.html");

    let watch = run(&["watch", "--duration", "1s", "--db", db.to_str().unwrap()]);
    assert!(watch.status.success());

    let report = run_in(
        dir.path(),
        &[
            "report",
            "--since",
            "1h",
            "--db",
            db.to_str().unwrap(),
            "--out",
            target.to_str().unwrap(),
        ],
    );
    assert!(report.status.success(), "stderr: {}", stderr(&report));
    assert!(
        target.exists(),
        "the receipt must be created, including its directory"
    );
    assert!(
        !dir.path().join("receipt.html").exists(),
        "the default path must not be written when --out is given"
    );
}
