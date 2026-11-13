//! The live view: what `tattle` does with no arguments.
//!
//! This is the first thing anyone runs, so it has to work, show something
//! immediately, and tell the user what to do next. It is deliberately not a
//! full TUI framework: a redrawn table is enough to demonstrate the product,
//! and it keeps the binary small and the failure modes few.
//!
//! Two modes, chosen by whether stdout is a terminal:
//!
//! * a terminal gets a coloured table redrawn in place until Ctrl-C;
//! * a pipe gets a bounded recording followed by one plain frame, because
//!   escape codes in a log file are noise.
//!
//! The layout is built once as styled spans and rendered either plain or with
//! ANSI, so the two modes cannot drift apart.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::model::Tier;
use crate::store::{AppRow, Store};
use crate::watch::Watcher;

/// How long a non-interactive run records before printing its summary.
pub const PIPE_DURATION: Duration = Duration::from_secs(10);

/// How long a connection stays in the live table.
const WINDOW_SECONDS: i64 = 3600;

/// How many applications the live table shows.
const MAX_ROWS: usize = 10;

/// Column widths. Fixed so the table does not jitter as numbers change.
const NAME_W: usize = 26;
const CONNS_W: usize = 7;
const SITES_W: usize = 7;
const FLAG_W: usize = 9;
const CONF_W: usize = 5;
const LOAD_W: usize = 12;

/// How many ticks of history the sparkline shows.
const HISTORY: usize = 48;

/// Glyphs for the load bar and the sparkline.
const BAR: char = '█';
const SPARK: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Visual weight of a run of text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Normal,
    Dim,
    Accent,
    Danger,
    Good,
}

/// A run of text with one style. The whole layout is spans; how they are
/// painted is decided at render time.
type Span = (String, Style);

/// One rendered frame, as a pure function of the numbers.
#[derive(Debug, Clone)]
pub struct Frame {
    pub elapsed: Duration,
    pub connections: usize,
    pub apps: Vec<AppRow>,
    pub named: u64,
    pub total: u64,
    pub flagged: u64,
    /// Connection counts from recent ticks, oldest first.
    pub history: Vec<u64>,
}

impl Frame {
    fn clock(&self) -> String {
        let secs = self.elapsed.as_secs();
        format!(
            "{:02}:{:02}:{:02}",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        )
    }

    /// Share of connections that carry any name, as a percentage.
    fn coverage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.named as f64 / self.total as f64 * 100.0
        }
    }

    /// The tallest bar in the table, so bars are comparable within a frame.
    fn peak(&self) -> u64 {
        self.apps
            .iter()
            .map(|a| a.connections)
            .max()
            .unwrap_or(1)
            .max(1)
    }

    /// A proportional bar for one row.
    fn bar(&self, value: u64) -> String {
        let width = ((value as f64 / self.peak() as f64) * LOAD_W as f64).round() as usize;
        BAR.to_string()
            .repeat(width.clamp(usize::from(value > 0), LOAD_W))
    }

    /// A sparkline of recent connection counts, scaled to its own peak.
    fn sparkline(&self) -> String {
        if self.history.is_empty() {
            return String::new();
        }
        let peak = self.history.iter().copied().max().unwrap_or(0).max(1);
        self.history
            .iter()
            .map(|value| {
                let level = ((*value as f64 / peak as f64) * (SPARK.len() - 1) as f64).round();
                SPARK[(level as usize).min(SPARK.len() - 1)]
            })
            .collect()
    }

    /// Build the frame as styled lines. Every renderer consumes this.
    fn layout(&self) -> Vec<Vec<Span>> {
        let mut lines: Vec<Vec<Span>> = Vec::new();

        // Title, with the sparkline pushed to the right.
        lines.push(vec![
            ("tattletale".to_string(), Style::Accent),
            ("  live  ".to_string(), Style::Dim),
            (self.clock(), Style::Normal),
            ("   ".to_string(), Style::Dim),
            (self.sparkline(), Style::Good),
        ]);

        // Counts, on one line. Pluralised: "1 connections" is the kind of thing
        // a reader notices in a screenshot.
        let coverage = self.coverage();
        lines.push(vec![
            (format!("{:>4}", self.connections), Style::Normal),
            (
                format!(" {}", noun(self.connections as u64, "connection")),
                Style::Dim,
            ),
            ("  |  ".to_string(), Style::Dim),
            (self.apps.len().to_string(), Style::Normal),
            (
                format!(" {}", noun(self.apps.len() as u64, "app")),
                Style::Dim,
            ),
            ("  |  ".to_string(), Style::Dim),
            (
                self.flagged.to_string(),
                if self.flagged > 0 {
                    Style::Danger
                } else {
                    Style::Normal
                },
            ),
            (" flagged".to_string(), Style::Dim),
            ("  |  ".to_string(), Style::Dim),
            (
                format!("{coverage:.0}%"),
                if coverage < 50.0 {
                    Style::Accent
                } else {
                    Style::Normal
                },
            ),
            (" named".to_string(), Style::Dim),
        ]);
        lines.push(Vec::new());

        if self.apps.is_empty() {
            lines.push(vec![(
                "  Nothing yet. Open an application - anything with a network connection."
                    .to_string(),
                Style::Dim,
            )]);
            lines.push(vec![(
                "  If this stays empty, run `tattle doctor`.".to_string(),
                Style::Dim,
            )]);
            return lines;
        }

        // Header.
        lines.push(vec![(
            format!(
                "  {:<NAME_W$}{:>CONNS_W$}{:>SITES_W$}{:>FLAG_W$}  {:>CONF_W$}  LOAD",
                "APP", "CONNS", "SITES", "FLAGGED", "CONF"
            ),
            Style::Dim,
        )]);

        // Rows, most active first.
        for app in self.apps.iter().take(MAX_ROWS) {
            lines.push(vec![
                (
                    format!("  {:<NAME_W$}", truncate(app.app.display(), NAME_W)),
                    Style::Normal,
                ),
                (format!("{:>CONNS_W$}", app.connections), Style::Normal),
                (format!("{:>SITES_W$}", app.sites), Style::Normal),
                (
                    format!("{:>FLAG_W$}", app.tracked),
                    if app.tracked > 0 {
                        Style::Danger
                    } else {
                        Style::Dim
                    },
                ),
                ("  ".to_string(), Style::Dim),
                (
                    format!("{:>CONF_W$}", app.tier.glyph()),
                    tier_style(app.tier),
                ),
                ("  ".to_string(), Style::Dim),
                (self.bar(app.connections), Style::Good),
            ]);
        }

        lines
    }

    /// Plain text: what a pipe, a log file, or the GIF generator consumes.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(2048);
        for line in self.layout() {
            let text: String = line.into_iter().map(|(text, _)| text).collect();
            out.push_str(text.trim_end());
            out.push('\n');
        }
        out
    }

    /// The same layout, painted. Only used when stdout is a terminal.
    pub fn render_ansi(&self) -> String {
        let mut out = String::with_capacity(4096);
        for line in self.layout() {
            for (text, style) in line {
                let code = match style {
                    Style::Normal => "\x1b[0m",
                    Style::Dim => "\x1b[2m",
                    Style::Accent => "\x1b[1;33m",
                    Style::Danger => "\x1b[1;31m",
                    Style::Good => "\x1b[32m",
                };
                out.push_str(code);
                out.push_str(&text);
            }
            out.push_str("\x1b[0m\n");
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

/// The singular or plural form of a noun, so a count reads correctly.
fn noun(count: u64, singular: &str) -> String {
    if count == 1 {
        singular.to_string()
    } else {
        format!("{singular}s")
    }
}

fn tier_style(tier: Tier) -> Style {
    match tier {
        Tier::High | Tier::Exact => Style::Good,
        Tier::Probable => Style::Accent,
        Tier::Unknown => Style::Dim,
    }
}

/// Truncate to `width` characters, marking the cut so a clipped name is not
/// mistaken for the real one.
fn truncate(text: &str, width: usize) -> String {
    crate::commands::format::truncate(text, width)
}

/// Enable ANSI escape processing on the Windows console.
///
/// Windows does not interpret `\x1b[` sequences unless the program asks for it.
/// Without this the redraw codes print as literal text, so the previous version
/// was only ever "live" when its output was piped.
#[cfg(windows)]
fn enable_ansi() {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        STD_OUTPUT_HANDLE,
    };

    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() {
            return;
        }
        let mut mode = 0u32;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return;
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}

#[cfg(not(windows))]
fn enable_ansi() {}

/// Run the live view until Ctrl-C, or for a fixed time when not a terminal.
pub fn run<S, C, N>(mut watcher: Watcher<S, C, N>) -> anyhow::Result<Frame>
where
    S: Store + 'static,
    C: crate::watch::ConnectionSource,
    N: crate::watch::NameSource,
{
    let interactive = std::io::stdout().is_terminal();
    if interactive {
        enable_ansi();
    }

    let running = Arc::new(AtomicBool::new(true));
    {
        let flag = Arc::clone(&running);
        let _ = ctrlc::set_handler(move || flag.store(false, Ordering::SeqCst));
    }

    let started = Instant::now();
    let base = crate::now_unix();
    let deadline = if interactive {
        None
    } else {
        Some(PIPE_DURATION)
    };

    let mut history: Vec<u64> = Vec::with_capacity(HISTORY);
    let mut last = Frame {
        elapsed: Duration::ZERO,
        connections: 0,
        apps: Vec::new(),
        named: 0,
        total: 0,
        flagged: 0,
        history: Vec::new(),
    };

    if interactive {
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

            let mut frame = snapshot(&watcher, started.elapsed(), now)?;
            history.push(frame.connections as u64);
            if history.len() > HISTORY {
                history.remove(0);
            }
            frame.history = history.clone();
            last = frame;

            if interactive {
                // Home and clear rather than reprinting, so the table grows in
                // place instead of scrolling the terminal.
                print!("\x1b[H\x1b[2J");
                print!("{}", last.render_ansi());
                print!("\x1b[2m\n  ctrl-c to stop\x1b[0m\n");
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
        println!("{}", last.render());
    }

    // Flush what was collected even if the loop was interrupted.
    let _ = watcher.finish(crate::now_unix());
    result?;
    Ok(last)
}

/// Read the current numbers out of the store.
fn snapshot<S, C, N>(
    watcher: &Watcher<S, C, N>,
    elapsed: Duration,
    now: i64,
) -> anyhow::Result<Frame>
where
    S: Store,
    C: crate::watch::ConnectionSource,
    N: crate::watch::NameSource,
{
    let store = watcher.store();
    let apps = store.app_rows(now - WINDOW_SECONDS, MAX_ROWS)?;

    // Coverage comes from the same health rule the receipt uses, so the live
    // view and the receipt never disagree about how much is explained.
    let events = store.events(now - WINDOW_SECONDS, 20_000)?;
    let health = crate::health::assess(&events);

    Ok(Frame {
        elapsed,
        connections: apps.iter().map(|a| a.connections as usize).sum(),
        flagged: apps.iter().map(|a| a.tracked).sum(),
        named: health.named,
        total: health.total,
        apps,
        history: Vec::new(),
    })
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

    fn frame(apps: Vec<AppRow>) -> Frame {
        Frame {
            elapsed: Duration::from_secs(83),
            connections: apps.iter().map(|a| a.connections as usize).sum(),
            flagged: apps.iter().map(|a| a.tracked).sum(),
            named: 10,
            total: 14,
            apps,
            history: vec![1, 3, 2, 8, 5],
        }
    }

    fn strip_ansi(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for next in chars.by_ref() {
                    if next == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn the_clock_and_counts_are_on_the_first_two_lines() {
        let text = frame(vec![app("chrome.exe", 12, 3, Tier::High)]).render();
        let lines: Vec<&str> = text.lines().collect();

        assert!(
            lines[0].starts_with("tattletale  live  00:01:23"),
            "got {:?}",
            lines[0]
        );
        assert!(lines[1].contains("connections"), "got {:?}", lines[1]);
        assert!(lines[1].contains("flagged"), "got {:?}", lines[1]);
        assert!(lines[1].contains("named"), "got {:?}", lines[1]);
    }

    #[test]
    fn the_table_header_names_every_column() {
        let text = frame(vec![app("chrome.exe", 12, 3, Tier::High)]).render();
        let header = text
            .lines()
            .find(|l| l.contains("APP"))
            .expect("a header row");
        for column in ["CONNS", "SITES", "FLAGGED", "CONF", "LOAD"] {
            assert!(header.contains(column), "missing {column} in {header:?}");
        }
    }

    #[test]
    fn rows_carry_a_proportional_bar() {
        let text = frame(vec![
            app("chrome.exe", 12, 3, Tier::High),
            app("slack.exe", 6, 0, Tier::Unknown),
        ])
        .render();

        let chrome = text
            .lines()
            .find(|l| l.contains("chrome.exe"))
            .expect("chrome row");
        let slack = text
            .lines()
            .find(|l| l.contains("slack.exe"))
            .expect("slack row");
        let bars = |line: &str| line.chars().filter(|c| *c == BAR).count();

        assert!(
            bars(chrome) > bars(slack),
            "the busier app must have the longer bar"
        );
        assert!(
            bars(chrome) <= LOAD_W,
            "the bar is capped at the column width"
        );
    }

    #[test]
    fn the_sparkline_reflects_the_history() {
        let mut f = frame(vec![app("chrome.exe", 1, 0, Tier::High)]);
        f.history = vec![0, 4, 8];
        let text = f.render();
        let first = text.lines().next().expect("title line");

        assert!(
            first.contains(SPARK[0]),
            "a zero bucket uses the lowest glyph"
        );
        assert!(first.contains(SPARK[7]), "the peak uses the tallest glyph");
    }

    #[test]
    fn an_empty_frame_explains_what_to_do() {
        let mut f = frame(Vec::new());
        f.history.clear();
        let text = f.render();

        assert!(text.contains("Nothing yet"), "{text}");
        assert!(
            text.contains("tattle doctor"),
            "an empty view must offer a next step"
        );
        assert!(!text.contains("APP"), "no header when there are no rows");
    }

    #[test]
    fn the_ansi_rendering_carries_colour_and_the_plain_one_does_not() {
        let f = frame(vec![app("chrome.exe", 12, 3, Tier::High)]);

        let plain = f.render();
        assert!(
            !plain.contains('\x1b'),
            "a pipe must never receive escape codes"
        );

        let coloured = f.render_ansi();
        assert!(coloured.contains("\x1b[1;33m"), "the brand is styled");
        assert!(coloured.contains("\x1b[2m"), "labels are dimmed");
        assert_eq!(
            strip_ansi(&coloured).trim_end(),
            plain.trim_end(),
            "colour must not change the text"
        );
    }

    #[test]
    fn long_names_are_truncated_inside_their_column() {
        let long = "a-very-long-application-name-that-will-not-fit.exe";
        let text = frame(vec![app(long, 1, 0, Tier::High)]).render();
        let row = text
            .lines()
            .find(|l| l.contains("a-very-long"))
            .expect("row");

        assert!(row.contains('~'), "a clipped name must be marked: {row:?}");
    }

    #[test]
    fn the_closing_hint_offers_the_next_command() {
        let f = frame(vec![app("chrome.exe", 1, 0, Tier::High)]);
        assert!(f.closing_hint().contains("tattle report"));

        let empty = frame(Vec::new());
        assert!(empty.closing_hint().contains("doctor"));
    }

    #[test]
    fn the_weakest_tier_represents_the_table() {
        let f = frame(vec![
            app("a.exe", 1, 0, Tier::High),
            app("b.exe", 2, 0, Tier::Unknown),
        ]);
        assert_eq!(f.weakest_tier(), Tier::Unknown);
    }
}
