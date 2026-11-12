//! `tattle` — see every domain your apps phone home to.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

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
    db: Option<std::path::PathBuf>,

    /// Disable colour output.
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write an HTML receipt for a time window.
    Report {
        /// Window to cover, e.g. `24h`, `7d`, `2026-11-01`.
        #[arg(long, default_value = "24h")]
        since: String,

        /// Where to write the receipt.
        #[arg(long, value_name = "PATH")]
        out: Option<std::path::PathBuf>,

        /// Open the receipt when it is written.
        #[arg(long)]
        open: bool,
    },

    /// Print the environment and check that collection can work here.
    Doctor,
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
    match cli.command {
        None => {
            anyhow::bail!("live view is not wired up yet; run `tattle doctor`")
        }
        Some(Command::Report { since, out, .. }) => {
            anyhow::bail!("report is not wired up yet (requested window {since}, out {out:?})")
        }
        Some(Command::Doctor) => {
            doctor(&cli);
            Ok(())
        }
    }
}

/// Print the facts that decide whether attribution can work on this machine.
fn doctor(cli: &Cli) {
    println!("tattletale {}", tattletale::VERSION);
    println!("os           {}", std::env::consts::OS);
    println!("arch         {}", std::env::consts::ARCH);
    println!(
        "db           {}",
        cli.db
            .as_ref()
            .map_or_else(|| "<default>".to_string(), |p| p.display().to_string())
    );
    println!("colour       {}", if cli.no_color { "off" } else { "on" });
}
