//! Where things live on disk, and what this machine is called.

use std::path::{Path, PathBuf};

/// The per-user data directory: `%LOCALAPPDATA%\tattletale` on Windows.
///
/// Deliberately not `ProgramData` or the current directory: the database records
/// what this user did, so it belongs under this user's profile.
pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("tattletale")
}

/// The database to use, honouring an explicit `--db`.
pub fn db_path(explicit: Option<&Path>) -> PathBuf {
    match explicit {
        Some(path) => path.to_path_buf(),
        None => data_dir().join("tattletale.db"),
    }
}

/// Where a receipt is written when no `--out` is given.
///
/// The current directory rather than the data directory: a receipt is a
/// document the user asked for, and they should be able to find it without
/// hunting through `%LOCALAPPDATA%`.
pub fn report_path(explicit: Option<&Path>) -> PathBuf {
    match explicit {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("receipt.html"),
    }
}

/// A label for this machine, shown in the receipt masthead.
///
/// The computer name, never a username: the receipt is meant to be shareable.
pub fn machine_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "this machine".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_path_always_wins() {
        let explicit = Path::new("C:\\tmp\\custom.db");
        assert_eq!(db_path(Some(explicit)), explicit);
        assert_eq!(
            report_path(Some(Path::new("out.html"))),
            Path::new("out.html")
        );
    }

    #[test]
    fn the_default_database_sits_under_the_data_directory() {
        let path = db_path(None);
        assert!(path.ends_with("tattletale.db"), "got {}", path.display());
        assert!(
            path.parent().is_some_and(|p| p.ends_with("tattletale")),
            "the default database must live in the per-user data directory"
        );
    }

    #[test]
    fn the_default_receipt_is_in_the_working_directory() {
        let path = report_path(None);
        assert!(path.ends_with("receipt.html"));

        // The requirement is "not buried in the data directory", expressed by
        // comparing the directories. An earlier version asserted the path did
        // not contain "tattletale\tattletale", which is true of the checkout
        // path on GitHub Actions and made the test fail for the wrong reason:
        // it was testing where CI puts the repository, not where the receipt
        // goes.
        assert!(
            !path.starts_with(data_dir()),
            "the receipt must not be filed away in {}; got {}",
            data_dir().display(),
            path.display()
        );
    }

    #[test]
    fn the_machine_label_is_never_empty() {
        assert!(!machine_name().trim().is_empty());
    }
}
