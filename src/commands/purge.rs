//! `tattle purge` — delete everything this tool has recorded.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::commands::paths;

/// The files that together make up the database.
///
/// The WAL and shared-memory files hold recent rows. Deleting only the `.db`
/// would leave data that the next run could recover, which is not what "delete
/// everything" means.
fn database_files(db: &Path) -> Vec<PathBuf> {
    let mut files = vec![db.to_path_buf()];
    for suffix in ["-wal", "-shm"] {
        files.push(PathBuf::from(format!("{}{suffix}", db.display())));
    }
    files
}

/// Delete the recorded data.
///
/// `assume_yes` skips the confirmation. The prompt exists because the data
/// cannot be recovered, not because deleting is discouraged.
pub fn run(
    out: &mut dyn Write,
    input: &mut dyn std::io::BufRead,
    db: Option<&Path>,
    assume_yes: bool,
) -> anyhow::Result<usize> {
    let db = paths::db_path(db);

    if !assume_yes {
        writeln!(out, "this deletes:")?;
        if db.exists() {
            writeln!(out, "  {}", db.display())?;
        }
        writeln!(
            out,
            "\n  (downloaded tracker lists are kept: they are public data, not a record of you)"
        )?;
        write!(out, "continue? [y/N] ")?;
        out.flush()?;

        let mut answer = String::new();
        input.read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            writeln!(out, "nothing deleted")?;
            return Ok(0);
        }
    }

    let mut removed = 0;
    for file in database_files(&db) {
        if file.exists() {
            std::fs::remove_file(&file)?;
            removed += 1;
        }
    }

    writeln!(out, "deleted {removed} item(s); nothing recorded remains")?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Proto, Sample};
    use crate::store::Store;

    fn create_db(dir: &tempfile::TempDir) -> PathBuf {
        let db = dir.path().join("t.db");
        let mut store = crate::store::sqlite::SqliteStore::open(&db).expect("open");
        store
            .record(&[Sample {
                at: 1_000,
                app_path: "C:\\x\\chrome.exe".into(),
                app_name: "chrome.exe".into(),
                ip: "203.0.113.1".into(),
                port: 443,
                proto: Proto::Tcp,
            }])
            .expect("record");
        db
    }

    fn no_input() -> impl std::io::BufRead {
        std::io::Cursor::new(Vec::<u8>::new())
    }

    #[test]
    fn declining_the_prompt_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db = create_db(&dir);
        let before = std::fs::metadata(&db).unwrap().len();

        let mut sink = Vec::new();
        let mut input = std::io::Cursor::new(b"n\n".to_vec());
        let removed = run(&mut sink, &mut input, Some(&db), false).expect("run");

        assert_eq!(removed, 0);
        assert!(db.exists(), "declining must be safe");
        assert_eq!(std::fs::metadata(&db).unwrap().len(), before);
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("nothing deleted"));
    }

    #[test]
    fn an_empty_answer_declines() {
        // Pressing enter must be the safe choice, not the destructive one.
        let dir = tempfile::tempdir().unwrap();
        let db = create_db(&dir);
        let mut sink = Vec::new();
        let mut input = std::io::Cursor::new(b"\n".to_vec());
        run(&mut sink, &mut input, Some(&db), false).expect("run");
        assert!(db.exists());
    }

    #[test]
    fn accepting_removes_the_database_and_its_wal() {
        let dir = tempfile::tempdir().unwrap();
        let db = create_db(&dir);
        // Force a WAL file to exist alongside the database.
        let wal = db.with_extension("db-wal");
        std::fs::write(&wal, b"x").expect("write wal");

        let mut sink = Vec::new();
        let mut input = std::io::Cursor::new(b"y\n".to_vec());
        let removed = run(&mut sink, &mut input, Some(&db), false).expect("run");

        assert!(!db.exists(), "the database must be gone");
        assert!(
            !wal.exists(),
            "a leftover WAL can be replayed; it must go too"
        );
        assert!(removed >= 2);
    }

    #[test]
    fn assume_yes_skips_the_prompt_entirely() {
        let dir = tempfile::tempdir().unwrap();
        let db = create_db(&dir);
        let mut sink = Vec::new();
        let mut input = no_input();
        run(&mut sink, &mut input, Some(&db), true).expect("run");
        assert!(!db.exists());
        let text = String::from_utf8(sink).unwrap();
        assert!(
            !text.contains("continue?"),
            "no prompt when --yes is passed"
        );
    }

    #[test]
    fn nothing_to_delete_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = Vec::new();
        let mut input = no_input();
        let removed = run(
            &mut sink,
            &mut input,
            Some(&dir.path().join("absent.db")),
            true,
        )
        .expect("run");
        assert_eq!(removed, 0);
    }
}
