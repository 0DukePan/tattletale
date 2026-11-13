//! Hold TCP connections open, so the collector has time to see them.
//!
//! A measurement aid. Reverse DNS only helps if a connection is observable, and
//! a `curl` to a bare address closes before a one-second poller notices. This
//! opens the connections, holds them, and closes them.
//!
//! Connecting to a literal address is also exactly what a browser using DNS
//! over HTTPS looks like to this tool: a real connection whose name never
//! enters the system resolver cache.

use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let targets: Vec<String> = std::env::args().skip(1).collect();
    if targets.is_empty() {
        eprintln!("usage: hold_connections <ip>...");
        return;
    }

    let mut held = Vec::new();
    for target in &targets {
        let address = format!("{target}:443");
        let parsed: std::net::SocketAddr = match address.parse() {
            Ok(parsed) => parsed,
            Err(err) => {
                println!("bad address {address}: {err}");
                continue;
            }
        };
        match TcpStream::connect_timeout(&parsed, Duration::from_secs(3)) {
            Ok(stream) => {
                println!("connected to {address}");
                held.push(stream);
            }
            Err(err) => println!("failed     {address}: {err}"),
        }
    }

    // Long enough for several polls and one resolver round.
    std::thread::sleep(Duration::from_secs(6));
    println!("closing {} connection(s)", held.len());
}
