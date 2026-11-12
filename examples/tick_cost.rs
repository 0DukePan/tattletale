//! Time a full collection tick, including pid resolution.
//!
//! `probe` reports the cost of reading the connection table, which is the cheap
//! half. This measures `tick`, which also resolves every pid to an image path —
//! and since correctness requires re-verifying the pid's creation time on each
//! lookup, that cost is the one worth knowing.

use std::time::Instant;

fn main() {
    let mut collector = tattletale::platform::windows::Collector::new();

    // Warm the caches so the first run does not dominate the average.
    let _ = collector.tick(0);

    const ROUNDS: u32 = 200;
    let mut total_samples = 0usize;
    let started = Instant::now();
    for i in 0..ROUNDS {
        let samples = collector.tick(i as i64).expect("tick");
        total_samples += samples.len();
    }
    let elapsed = started.elapsed();

    println!("rounds            {ROUNDS}");
    println!("samples total     {total_samples}");
    println!(
        "per tick          {:.3} ms",
        elapsed.as_secs_f64() * 1000.0 / ROUNDS as f64
    );
    println!(
        "cpu at 1 Hz       {:.3}% of one core",
        elapsed.as_secs_f64() / ROUNDS as f64 * 100.0
    );
}
