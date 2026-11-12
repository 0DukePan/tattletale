//! The live view: what `tattle` does with no arguments.
//!
//! This is the first thing anyone runs, so it has to work, show something
//! immediately, and tell the user what to do next. It is deliberately not a
//! full TUI framework: a redrawn table is enough to demonstrate the product,
//! and it keeps the binary small and the failure modes few.
//!
//! Two modes, chosen by whether stdout is a terminal:
//!
//! * a terminal gets a redrawn live table until Ctrl-C;
//! * a pipe gets a bounded recording followed by a summary, because escape
//!   codes in a log file are noise.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::commands::format::truncate;
use crate::model::Tier;
use crate::store::{AppRow, Store};
use crate::watch::Watcher;

/// How long a non-interactive run records before printing its summary.
pub const PIPE_DURATION: Duration = Duration::from_secs(10);

/// How long a connection stays in the live table.
const WINDOW_SECONDS: i64 = 3600;

/// How many applications the live table shows.
const MAX_ROWS: usize = 10;

/// One rendered frame, as a pure function of the numbers.
///
/// Keeping this separate from the loop is what makes the view testable without
/// a terminal, a clock, or a database.
#[derive(Debug, Clone)]
pub struct Frame {
    pub elapsed: Duration,
    pub connections: usize,
    pub apps: Vec<AppRow>,
    pub named: u64,
    pub total: u64,
    pub flagged: u64,
}

impl Frame {
    /// Render the frame as plain text with no escape codes.
    ///
    /// The caller decides whether to redraw in place; the text itself is
    /// identical either way, which is why the tests can assert on it.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(1024);
        let secs = self.elapsed.as_secs();
        let clock = format!(
            "{:02}:{:02}:{:02}",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        );

        out.push_str(&format!(
            "tattletale  live  {clock}  {} connections  {} apps  {} flagged\n\n",
            self.connections,
            self.apps.len(),
            self.flagged
        ));

        if self.apps.is_empty() {
            out.push_str(
                "  Nothing yet. Open an application - anything with a network connection.\n",
            );
            out.push_str("  If this stays empty, run `tattle doctor`.\n\n");
            return out;
        }

        out.push_str(&format!(
            "  {:<26} {:>7} {:>7} {:>9}  {}\n",
            "APP", "CONNS", "SITES", "FLAGGED", "CONFIDENCE"
        ));

        for app in self.apps.iter().take(MAX_ROWS) {
            let name = truncate(app.app.display(), 26);
            out.push_str(&format!(
                "  {:<26} {:>7} {:>7} {:>9}  {}\n",
                name,
                app.connections,
                app.sites,
                app.tracked,
                app.tier.glyph()
            ));
        }

        if self.total > 0 {
            out.push_str(&format!(
                "\n  {:.0}% of connections could be named\n",
                self.named as f64 / self.total as f64 * 100.0
            ));
        }
        out
    }

    /// The line printed after the live view stops.
    pub fn closing_hint(&self) -> String {
        if self.apps.is_empty() {
            return "nothing recorded; try `tattle doctor`".to_string();
        }
        "write a receipt with `tattle report --open`, or see a full example with `tattle demo`"
            .to_string()
    }
}

/// Run the live view until Ctrl-C, or for a fixed time when not a terminal.
pub fn run<S: Store + 'static>(mut watcher: Watcher<S>) -> anyhow::Result<Frame> {
    let interactive = std::io::stdout().is_terminal();

    let running = Arc::new(AtomicBool::new(true));
    {
        let flag = Arc::clone(&running);
        // A failure to install the handler is not fatal: the process can still
        // be killed, and SQLite's WAL survives it.
        let _ = ctrlc::set_handler(move || flag.store(false, Ordering::SeqCst));
    }

    let started = Instant::now();
    let base = super::now_unix();
    let deadline = if interactive {
        None
    } else {
        Some(PIPE_DURATION)
    };

    let mut last = Frame {
        elapsed: Duration::ZERO,
        connections: 0,
        apps: Vec::new(),
        named: 0,
        total: 0,
        flagged: 0,
    };

    if interactive {
        // Hide the cursor while redrawing; restore it on every exit path.
        print!("\x1b[?25l");
        let _ = std::io::stdout().flush();
    }

    let result = (|| -> anyhow::Result<()> {
        loop {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            if let Some(limit) = deadline {
                if started.elapsed() >= limit {
                    break;
                }
            }

            let now = base + started.elapsed().as_secs() as i64;
            watcher.tick(now)?;
            last = snapshot(&watcher, started.elapsed(), now)?;

            if interactive {
                // Home the cursor and clear instead of reprinting, so the table
                // grows in place rather than scrolling the terminal.
                print!("\x1b[H\x1b[2J");
                print!("{}", last.render());
                print!("\n  ctrl-c to stop\n");
                let _ = std::io::stdout().flush();
            }

            std::thread::sleep(Duration::from_secs(1));
        }
        Ok(())
    })();

    if interactive {
        print!("\x1b[?25h");
        let _ = std::io::stdout().flush();
    } else {
        // A pipe has no redraw, so print the final frame once.
        println!("{}", last.render());
    }

    // Flush what was collected even if the loop was interrupted.
    let _ = watcher.finish(super::now_unix());
    result?;
    Ok(last)
}

/// Read the current numbers out of the store.
fn snapshot<S: Store>(watcher: &Watcher<S>, elapsed: Duration, now: i64) -> anyhow::Result<Frame> {
    let store = watcher.store();
    let apps = store.app_rows(now - WINDOW_SECONDS, MAX_ROWS)?;
    let totals = store.totals(now - WINDOW_SECONDS)?;

    // Coverage comes from the same health rule the receipt uses, so the live
    // view and the receipt never disagree about how much is explained.
    let events = store.events(now - WINDOW_SECONDS, 20_000)?;
    let health = crate::health::assess(&events);
    let _ = &totals;

    Ok(Frame {
        elapsed,
        connections: apps.iter().map(|a| a.connections as usize).sum(),
        flagged: apps.iter().map(|a| a.tracked).sum(),
        named: health.named,
        total: health.total,
        apps,
    })
}

impl Frame {
    /// The confidence badge for a whole frame: the weakest tier present, since
    /// one confident row does not make an uncertain table trustworthy.
    pub fn weakest_tier(&self) -> Tier {
        self.apps
            .iter()
            .map(|a| a.tier)
            .min()
            .unwrap_or(Tier::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{App, Category};
    use crate::store::SiteRow;

    fn app(name: &str, connections: u64, tracked: u64, tier: Tier) -> AppRow {
        AppRow {
            app: App {
                id: 0,
                path: format!("C:\\x\\{name}"),
                name: name.into(),
                friendly: String::new(),
            },
            connections,
            sites: 2,
            tracked,
            tier,
            top_sites: vec![SiteRow {
                host: "doubleclick.net".into(),
                site: "doubleclick.net".into(),
                category: Category::Ads,
                connections: 1,
                tier,
            }],
        }
    }

    #[test]
    fn an_empty_frame_explains_what_to_do() {
        let frame = Frame {
            elapsed: Duration::from_secs(3),
            connections: 0,
            apps: vec![],
            named: 0,
            total: 0,
            flagged: 0,
        };
        let text = frame.render();
        assert!(text.contains("Nothing yet"), "{text}");
        assert!(
            text.contains("tattle doctor"),
            "an empty view must offer a next step"
        );
        assert!(
            text.contains("00:00:03"),
            "the clock must show elapsed time"
        );
    }

    #[test]
    fn a_frame_lists_apps_with_their_numbers() {
        let frame = Frame {
            elapsed: Duration::from_secs(75),
            connections: 14,
            apps: vec![
                app("chrome.exe", 12, 3, Tier::High),
                app("slack.exe", 2, 0, Tier::Unknown),
            ],
            named: 10,
            total: 14,
            flagged: 3,
        };
        let text = frame.render();
        assert!(text.contains("00:01:15"));
        assert!(text.contains("chrome.exe"));
        assert!(text.contains("slack.exe"));
        assert!(text.contains("14 connections"));
        assert!(text.contains("3 flagged"));
        assert!(text.contains("71%"), "coverage should be shown: {text}");
    }

    #[test]
    fn the_closing_hint_offers_the_next_command() {
        let frame = Frame {
            elapsed: Duration::ZERO,
            connections: 1,
            apps: vec![app("chrome.exe", 1, 0, Tier::High)],
            named: 1,
            total: 1,
            flagged: 0,
        };
        assert!(frame.closing_hint().contains("tattle report"));
        let empty = Frame {
            apps: vec![],
            ..frame
        };
        assert!(empty.closing_hint().contains("doctor"));
    }

    #[test]
    fn the_weakest_tier_represents_the_table() {
        let frame = Frame {
            elapsed: Duration::ZERO,
            connections: 3,
            apps: vec![
                app("a.exe", 1, 0, Tier::High),
                app("b.exe", 2, 0, Tier::Unknown),
            ],
            named: 1,
            total: 3,
            flagged: 0,
        };
        assert_eq!(frame.weakest_tier(), Tier::Unknown);
    }
}
