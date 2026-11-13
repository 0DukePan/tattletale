//! `tattle` — see every domain your apps phone home to.
//!
//! This file is the argument schema, the dispatch and the exit code. Everything
//! a command actually does lives in `tattletale::commands`, where it can be
//! tested without spawning a process.

use std::io::{BufReader, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use tattletale::commands::{self, RankBy};

/// Exit code used for runtime failures. Usage errors exit with 2 via clap.
const EXIT_FAILURE: u8 = 1;

#[derive(Debug, Parser)]
#[command(
    name = "tattle",
    version,
    about = "See every domain your apps phone home to",
    long_about = None,
    disable_help_subcommand = true
)]
struct Cli {
    /// Path to the database. Defaults to the per-user data directory.
    #[arg(long, global = true, value_name = "PATH")]
    db: Option<PathBuf>,

    /// Disable colour output.
    #[arg(long, global = true)]
    no_color: bool,

    /// Emit JSON on stdout instead of a table. Logs still go to stderr.
    #[arg(long, global = true)]
    json: bool,

    /// Name addresses by owner when no hostname explains them.
    ///
    /// This asks your resolver about addresses that bypassed it, which is
    /// information DNS over HTTPS was hiding. Off by default.
    #[arg(long, global = true)]
    reverse_dns: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write an HTML receipt for a time window.
    Report {
        /// Window to cover, e.g. `24h`, `7d`, `30m`.
        #[arg(long, default_value = "24h")]
        since: String,

        /// Where to write the receipt.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,

        /// Open the receipt when it is written.
        #[arg(long)]
        open: bool,
    },

    /// Record traffic for a while, then exit. Use this to fill a first receipt.
    Watch {
        /// How long to record, e.g. `60s`, `5m`, `1h`.
        #[arg(long, default_value = "60s")]
        duration: String,
    },

    /// Fill a database with a labelled synthetic scene, then render it.
    ///
    /// The receipt is stamped as synthetic. This exists so the tool can be seen
    /// before it has recorded anything.
    Demo {
        /// Where to write the receipt.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,

        /// Open the receipt when it is written.
        #[arg(long)]
        open: bool,
    },

    /// Inspect or refresh the tracker lists.
    Lists {
        #[command(subcommand)]
        action: ListsAction,
    },

    /// Print the busiest applications, sites or domains.
    Top {
        /// Window to cover, e.g. `24h`, `7d`.
        #[arg(long, default_value = "24h")]
        since: String,

        /// What to rank by.
        #[arg(long, value_enum, default_value = "apps")]
        by: RankBy,

        /// How many rows to print.
        #[arg(long, default_value = "10")]
        limit: usize,
    },

    /// Show one application's traffic.
    App {
        /// Part of the executable name, case-insensitive.
        name: String,

        /// Window to cover.
        #[arg(long, default_value = "24h")]
        since: String,
    },

    /// Turn flagged domains into a hosts-file fragment you can apply.
    Block {
        /// Window to cover.
        #[arg(long, default_value = "24h")]
        since: String,

        /// Write the fragment here instead of stdout.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,

        /// Append instead of overwriting. Never touches existing lines.
        #[arg(long)]
        append: bool,
    },

    /// Delete everything this tool has recorded.
    Purge {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },

    /// Check for a newer release, and optionally fetch it.
    ///
    /// This is the only command that talks to the internet on your behalf, and
    /// it only runs when you type it. Nothing is installed automatically.
    Update {
        /// Only report whether a newer release exists.
        #[arg(long)]
        check: bool,
    },

    /// Measure how often the attribution is right, against labelled scenarios.
    Bench,

    /// Print the environment and check that collection can work here.
    Doctor,
}

#[derive(Debug, Subcommand)]
enum ListsAction {
    /// Show which lists are loaded and how many rules they carry.
    Status,
    /// Download the public tracker lists. This is the only outbound request
    /// the tool ever makes, and it only happens when you ask for it.
    Update,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("tattle: {err:#}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut out = std::io::stdout();
    let db = cli.db.as_deref();
    let now = tattletale::now_unix();

    match cli.command {
        None => {
            commands::live::run(&mut out, db, cli.reverse_dns)?;
        }
        Some(Command::Report {
            since,
            out: target,
            open,
        }) => {
            let path = commands::report::run(&mut out, db, &since, target.as_deref(), now)?;
            if open {
                commands::report::open_in_browser(&path);
            }
        }
        Some(Command::Watch { duration }) => {
            commands::watch::run(&mut out, db, &duration, now, cli.reverse_dns)?;
        }
        Some(Command::Demo { out: target, open }) => {
            commands::demo::run(&mut out, target.as_deref(), now, open)?;
        }
        Some(Command::Top { since, by, limit }) => {
            commands::top::run(&mut out, db, &since, by, limit, cli.json, now)?;
        }
        Some(Command::App { name, since }) => {
            commands::app::run(&mut out, db, &name, &since, now)?;
        }
        Some(Command::Block {
            since,
            out: target,
            append,
        }) => {
            commands::block::run(&mut out, db, &since, target.as_deref(), append, now)?;
        }
        Some(Command::Purge { yes }) => {
            // The prompt has to go somewhere a user can see. When stdin is not
            // a terminal there is nobody to answer it, so refuse rather than
            // block forever or read a stray piped line as consent.
            if !yes && !std::io::stdin().is_terminal() {
                anyhow::bail!(
                    "refusing to delete without confirmation on a non-interactive stdin; \
                     pass --yes if that is what you mean"
                );
            }
            let mut input = BufReader::new(std::io::stdin());
            commands::purge::run(&mut out, &mut input, db, yes)?;
        }
        Some(Command::Update { check }) => {
            commands::update::run(&mut out, check, now)?;
        }
        Some(Command::Bench) => {
            commands::accuracy::run(&mut out)?;
        }
        Some(Command::Doctor) => {
            commands::doctor::run(&mut out, db, cli.no_color, now)?;
        }
        Some(Command::Lists { ref action }) => {
            let dir = tattletale::classify::lists_dir();
            match action {
                ListsAction::Status => commands::lists::status(&mut out, &dir)?,
                ListsAction::Update => {
                    commands::lists::update(&mut out, &dir)?;
                }
            }
        }
    }

    use std::io::Write as _;
    std::io::stdout().flush()?;
    Ok(())
}
