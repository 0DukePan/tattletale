//! `tattle doctor` — report whether this machine can be measured.

use std::io::Write;
use std::path::Path;

use crate::commands::paths;

/// Print the facts that decide whether attribution can work here.
///
/// This exists to turn "it doesn't work" into a specific answer, and it is the
/// first thing to ask for in a bug report.
pub fn run(out: &mut dyn Write, db: Option<&Path>, no_color: bool, now: i64) -> anyhow::Result<()> {
    writeln!(out, "tattletale {}", crate::VERSION)?;
    writeln!(out, "os           {}", std::env::consts::OS)?;
    writeln!(out, "arch         {}", std::env::consts::ARCH)?;
    writeln!(out, "now          {}", crate::report::clock(now))?;
    writeln!(out, "db           {}", paths::db_path(db).display())?;
    writeln!(out, "colour       {}", if no_color { "off" } else { "on" })?;

    #[cfg(windows)]
    {
        let mut collector = crate::platform::windows::Collector::new();
        match collector.tick(now) {
            Ok(samples) => writeln!(
                out,
                "collector    ok ({} connections visible)",
                samples.len()
            )?,
            Err(err) => writeln!(out, "collector    degraded: {err}")?,
        }
        match crate::platform::windows::interface_addresses() {
            Ok(addrs) => writeln!(out, "interfaces   {} addresses", addrs.len())?,
            Err(err) => writeln!(out, "interfaces   unavailable: {err}")?,
        }
        writeln!(out, "dns          ipconfig /displaydns (no elevation)")?;
        writeln!(
            out,
            "mode         standard (no ETW, so no exact attribution)"
        )?;
    }

    #[cfg(not(windows))]
    {
        writeln!(
            out,
            "collector    unavailable: no collector for this platform yet"
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_contains_the_fields_a_bug_report_needs() {
        let mut sink = Vec::new();
        run(&mut sink, None, false, 1_794_509_596).expect("doctor");
        let text = String::from_utf8(sink).unwrap();

        for field in ["tattletale ", "os ", "arch ", "db ", "colour ", "now "] {
            assert!(text.contains(field), "doctor must report {field:?}: {text}");
        }
        assert!(
            text.contains("2026-11-12"),
            "the timestamp must be rendered: {text}"
        );
    }

    #[test]
    fn an_explicit_database_is_reported() {
        let mut sink = Vec::new();
        run(&mut sink, Some(Path::new("C:\\tmp\\custom.db")), true, 0).expect("doctor");
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("custom.db"));
        assert!(text.contains("colour       off"));
    }

    #[cfg(windows)]
    #[test]
    fn on_windows_it_states_the_collection_mode() {
        // A user who expects exact attribution deserves to know it is not
        // available without elevation, on the screen they will actually read.
        let mut sink = Vec::new();
        run(&mut sink, None, false, 0).expect("doctor");
        let text = String::from_utf8(sink).unwrap();
        assert!(text.contains("standard"), "must name the mode: {text}");
        assert!(
            text.contains("no ETW"),
            "must explain what is missing: {text}"
        );
    }
}
