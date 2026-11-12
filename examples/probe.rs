//! Gate G0 probe: prove that the Windows collectors see real traffic as a
//! standard user, with no elevation.
//!
//! Run with `cargo run --bin probe`. It is not part of the shipped binary.

#[cfg(windows)]
fn main() {
    use std::time::Instant;

    use tattletale::platform::windows::{is_routable, process_image, Collector};

    println!("tattletale probe - pid {}", std::process::id());

    let mut collector = Collector::new();

    let started = Instant::now();
    let rows = collector.raw_connections().expect("connection table");
    println!(
        "raw rows                  {} ({} ms)",
        rows.len(),
        started.elapsed().as_millis()
    );

    let tcp = rows
        .iter()
        .filter(|r| r.proto == tattletale::model::Proto::Tcp)
        .count();
    println!("  tcp                     {tcp}");
    println!("  udp                     {}", rows.len() - tcp);

    let mut pids: Vec<u32> = rows.iter().map(|r| r.pid).collect();
    pids.sort_unstable();
    pids.dedup();
    println!("distinct pids             {}", pids.len());

    let mut unresolved = 0;
    for pid in &pids {
        if process_image(*pid).is_none() {
            unresolved += 1;
        }
    }
    println!("pids with no image path   {unresolved} (protected processes)");

    let bad = rows.iter().filter(|r| !is_routable(&r.ip)).count();
    println!("non-routable rows kept    {bad} (must be 0)");

    println!("\n{:<7} {:<6} {:<40} REMOTE", "PID", "PROTO", "APP");
    for row in rows.iter().take(15) {
        let app = process_image(row.pid)
            .map(|p| p.name)
            .unwrap_or_else(|| "<unknown>".into());
        println!(
            "{:<7} {:<6} {:<40} {}:{}",
            row.pid, row.proto, app, row.ip, row.port
        );
    }

    // Two ticks 1 s apart: proves the poll cadence produces samples.
    let first = collector.tick(0).expect("tick 1");
    std::thread::sleep(std::time::Duration::from_millis(1000));
    let second = collector.tick(1).expect("tick 2");
    println!("\ntick 1 samples            {}", first.len());
    println!("tick 2 samples            {}", second.len());

    let t = Instant::now();
    let mut total = 0usize;
    for _ in 0..20 {
        total += collector.raw_connections().expect("connection table").len();
    }
    println!(
        "avg poll cost             {:.2} ms over 20 polls ({} rows seen)",
        t.elapsed().as_secs_f64() * 1000.0 / 20.0,
        total
    );
}

#[cfg(not(windows))]
fn main() {
    eprintln!("probe is Windows-only");
}
