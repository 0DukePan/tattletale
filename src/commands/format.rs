//! Presentation helpers shared by the terminal commands.

use clap::ValueEnum;

/// What `tattle top` ranks by.
///
/// Defined here rather than in the binary so the command and its arguments can
/// be tested together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RankBy {
    Apps,
    Sites,
    Domains,
}

/// Parse `24h`, `7d`, `30m`, `90s` into seconds.
pub fn parse_window(text: &str) -> anyhow::Result<i64> {
    let text = text.trim().to_ascii_lowercase();
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    let value: i64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("expected a window like 24h or 7d, got {text:?}"))?;
    if value <= 0 {
        anyhow::bail!("a window must be positive, got {text:?}");
    }
    let seconds = match unit {
        "s" => value,
        "m" => value * 60,
        "h" => value * 3600,
        "d" => value * 86_400,
        _ => anyhow::bail!("unknown unit {unit:?}; use s, m, h or d"),
    };
    Ok(seconds)
}

/// Pluralise a noun. Cheap grammar that keeps "1 sites" out of a terminal,
/// which is where it would be seen on every single run.
pub fn plural(count: u64, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// Truncate to `width` characters, marking the cut.
///
/// A clipped name must be visibly clipped: `a-very-long-na~` reads as truncated,
/// whereas `a-very-long-na` reads as a different application.
pub fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('~');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_parse_into_seconds() {
        assert_eq!(parse_window("24h").unwrap(), 86_400);
        assert_eq!(parse_window("7d").unwrap(), 604_800);
        assert_eq!(parse_window("30m").unwrap(), 1_800);
        assert_eq!(parse_window("90s").unwrap(), 90);
        assert_eq!(parse_window(" 24H ").unwrap(), 86_400);
    }

    #[test]
    fn nonsense_windows_are_rejected_with_a_usable_message() {
        let err = parse_window("24x").unwrap_err().to_string();
        assert!(err.contains("unknown unit"), "got: {err}");
        assert!(parse_window("0h").is_err());
        assert!(parse_window("abc").is_err());
        assert!(parse_window("").is_err());
        assert!(parse_window("-5h").is_err());
    }

    #[test]
    fn plural_matches_the_count() {
        assert_eq!(plural(0, "site"), "0 sites");
        assert_eq!(plural(1, "site"), "1 site");
        assert_eq!(
            plural(2, "sites"),
            "2 sitess",
            "callers pass a singular noun"
        );
    }

    #[test]
    fn truncation_marks_the_cut() {
        let long = "a-very-long-application-name-that-will-not-fit.exe";
        let cut = truncate(long, 26);
        assert_eq!(cut.chars().count(), 26);
        assert!(cut.ends_with('~'));
    }

    #[test]
    fn short_text_is_untouched() {
        assert_eq!(truncate("chrome.exe", 26), "chrome.exe");
        assert_eq!(truncate("exactly-ten", 11), "exactly-ten");
    }

    #[test]
    fn truncation_respects_multibyte_characters() {
        // Paths and hostnames are usually ASCII, but a display helper that
        // panics on a non-ASCII byte is a crash in the middle of a receipt.
        let text = "aplicación-muy-larga-que-no-cabe.exe";
        let cut = truncate(text, 10);
        assert_eq!(cut.chars().count(), 10);
        assert!(cut.ends_with('~'));
    }
}
