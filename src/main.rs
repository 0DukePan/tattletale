//! `tattle`  -  see every domain your apps phone home to.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use tattletale::store::{sqlite::SqliteStore, Store};

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
        /// Window to cover, e.g. `24h`, `7d`, `30m`.
        #[arg(long, default_value = "24h")]
        since: String,

        /// Where to write the receipt.
        #[arg(long, value_name = "PATH")]
        out: Option<std::path::PathBuf>,

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
            anyhow::bail!("live view is not wired up yet; try `tattle report` or `tattle doctor`")
        }
        Some(Command::Report {
            ref since,
            ref out,
            open,
        }) => report(&cli, since, out.as_ref(), open),
        Some(Command::Watch { ref duration }) => watch(&cli, duration),
        Some(Command::Doctor) => {
            doctor(&cli);
            Ok(())
        }
    }
}

fn report(
    cli: &Cli,
    since: &str,
    out: Option<&std::path::PathBuf>,
    open: bool,
) -> anyhow::Result<()> {
    let window = parse_window(since)?;
    let now = unix_now();
    let db = cli.db.clone().unwrap_or_else(default_db_path);

    let store = SqliteStore::open(&db)?;
    let model =
        tattletale::report::build::build(&store as &dyn Store, now - window, now, machine_name())?;

    let html = tattletale::report::render(&model);
    let path = out.cloned().unwrap_or_else(default_report_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, html)?;

    println!("receipt written to {}", path.display());
    println!(
        "  {} connections  |  {} apps  |  {} sites  |  {:.0}% flagged",
        model.totals.connections,
        model.totals.apps,
        model.totals.sites,
        model.tracker_share()
    );

    if open {
        open_path(&path);
    }
    Ok(())
}

fn watch(cli: &Cli, duration: &str) -> anyhow::Result<()> {
    let span = parse_window(duration)?;
    let db = cli.db.clone().unwrap_or_else(default_db_path);
    if let Some(parent) = db.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let store = SqliteStore::open(&db)?;
    let mut watcher = tattletale::watch::Watcher::new(store);
    let started = unix_now();

    println!("recording for {duration} into {}", db.display());
    let mut last = tattletale::watch::TickStats::default();
    watcher.run(std::time::Duration::from_secs(span as u64), |stats| {
        last = stats;
    })?;
    watcher.finish(unix_now())?;

    println!(
        "done: {} connections in the last cycle, {} names in the resolver cache, {} attributed",
        last.connections, last.names, last.resolved
    );
    println!(
        "elapsed {}s; next: tattle report --since {}",
        unix_now() - started,
        duration
    );
    Ok(())
}

fn doctor(cli: &Cli) {
    println!("tattletale {}", tattletale::VERSION);
    println!("os           {}", std::env::consts::OS);
    println!("arch         {}", std::env::consts::ARCH);
    println!("now          {}", tattletale::report::clock(unix_now()));
    println!(
        "db           {}",
        cli.db.as_ref().map_or_else(
            || default_db_path().display().to_string(),
            |p| p.display().to_string()
        )
    );
    println!("colour       {}", if cli.no_color { "off" } else { "on" });

    #[cfg(windows)]
    {
        let mut collector = tattletale::platform::windows::Collector::new();
        match collector.tick(0) {
            Ok(samples) => println!("collector    ok ({} connections visible)", samples.len()),
            Err(err) => println!("collector    degraded: {err}"),
        }
        match tattletale::platform::windows::interface_addresses() {
            Ok(addrs) => println!("interfaces   {} addresses", addrs.len()),
            Err(err) => println!("interfaces   unavailable: {err}"),
        }
        println!("dns          ipconfig /displaydns (no elevation)");
        println!("mode         standard (no ETW, so no exact attribution)");
    }
}

/// Parse `24h`, `7d`, `30m`, `90s` into seconds.
fn parse_window(text: &str) -> anyhow::Result<i64> {
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

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn machine_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "this machine".to_string())
}

fn default_db_path() -> std::path::PathBuf {
    data_dir().join("tattletale.db")
}

fn default_report_path() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("receipt.html")
}

/// `%LOCALAPPDATA%\tattletale` on Windows, following the platform convention.
fn data_dir() -> std::path::PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("tattletale")
}

fn open_path(path: &std::path::Path) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(path)
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::parse_window;

    #[test]
    fn windows_parse_into_seconds() {
        assert_eq!(parse_window("24h").unwrap(), 86_400);
        assert_eq!(parse_window("7d").unwrap(), 604_800);
        assert_eq!(parse_window("30m").unwrap(), 1_800);
        assert_eq!(parse_window(" 24H ").unwrap(), 86_400);
    }

    #[test]
    fn nonsense_windows_are_rejected_with_a_usable_message() {
        let err = parse_window("24x").unwrap_err().to_string();
        assert!(err.contains("unknown unit"), "got: {err}");
        assert!(parse_window("0h").is_err());
        assert!(parse_window("abc").is_err());
        assert!(parse_window("").is_err());
    }
}
