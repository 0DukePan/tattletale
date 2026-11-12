//! Render the live view as a sequence of frames, for building the README GIF.
//!
//! This is a documentation asset generator, not product behaviour. It exists so
//! the animated demo is produced by the same `Frame::render` that users see,
//! rather than by hand-written mock output that could drift from the real thing.
//!
//! The data is the `tattle demo` scene, compressed into a few seconds so the
//! table fills in at a watchable pace. Everything visible — the counts, the
//! confidence glyphs, the flagged column — is computed by the real store and
//! the real classifier.
//!
//! Run with `cargo run --example gif_frames > frames.txt`.

use std::time::Duration;

use tattletale::model::{DnsRecord, DnsSection, DnsSource, Proto, Sample};
use tattletale::store::{memory::MemoryStore, Store};

/// Frames to emit. One per simulated second.
const FRAMES: i64 = 12;

/// The scene, compressed: which app talks to which host, in tick order.
/// Hosts that the bundled list flags are marked so the demo shows the feature.
const SCENE: &[(&str, &str, &str, i64)] = &[
    ("chrome.exe", "github.com", "203.0.113.10", 1),
    ("chrome.exe", "www.google-analytics.com", "203.0.113.11", 2),
    ("slack.exe", "slack.com", "203.0.113.12", 3),
    ("chrome.exe", "doubleclick.net", "203.0.113.13", 4),
    ("chrome.exe", "i.ytimg.com", "203.0.113.14", 5),
    ("slack.exe", "segment.io", "203.0.113.15", 5),
    ("claude.exe", "api.anthropic.com", "203.0.113.16", 6),
    ("chrome.exe", "stats.g.doubleclick.net", "203.0.113.17", 6),
    ("spotify.exe", "spclient.wg.spotify.com", "203.0.113.18", 7),
    ("chrome.exe", "criteo.com", "203.0.113.19", 8),
    ("discord.exe", "discord.com", "203.0.113.20", 8),
    ("spotify.exe", "scorecardresearch.com", "203.0.113.21", 9),
    (
        "Code.exe",
        "update.code.visualstudio.com",
        "203.0.113.22",
        9,
    ),
    ("chrome.exe", "googlesyndication.com", "203.0.113.23", 10),
    ("cloudflared.exe", "cloudflare-dns.com", "203.0.113.24", 10),
    ("brave.exe", "doubleclick.net", "203.0.113.25", 11),
];

fn main() {
    // A fixed base time keeps the output byte-identical between runs, so the
    // GIF does not change just because it was rebuilt on another day.
    let base: i64 = 1_794_500_000;
    let mut store = MemoryStore::new();

    for tick in 1..=FRAMES {
        // One sample per still-open tuple per tick. A connection is "open" for
        // three ticks, so it persists across batches exactly as a real socket
        // does and counts once — putting all three polls in a single batch
        // would look like three reopens, because a tuple absent from the
        // previous batch is by definition a new open.
        let mut samples: Vec<Sample> = Vec::new();
        for (app, _, ip, _at) in SCENE
            .iter()
            .filter(|(_, _, _, at)| *at <= tick && tick < at + 3)
        {
            samples.push(Sample {
                at: base + tick,
                app_path: format!("C:\\Program Files\\Demo\\{app}"),
                app_name: (*app).to_string(),
                ip: (*ip).to_string(),
                port: 443,
                proto: Proto::Tcp,
            });
        }
        store.record(&samples).expect("record");

        // Resolve a second before each connection, as a real resolver would.
        let dns: Vec<DnsRecord> = SCENE
            .iter()
            .filter(|(_, _, _, at)| *at <= tick)
            .map(|(_, host, ip, at)| DnsRecord {
                host: (*host).to_string(),
                ip: (*ip).to_string(),
                rtype: 1,
                section: DnsSection::Answer,
                ttl: 300,
                first_seen: base + at - 1,
                last_seen: base + at,
                source: DnsSource::Replay,
            })
            .collect();
        store.record_dns(&dns).expect("record_dns");

        let now = base + tick;
        let pending = store.pending(256).expect("pending");
        if !pending.is_empty() {
            let observations = store.observations(now, 90).expect("observations");
            let decisions = tattletale::resolve::resolve(&pending, &observations);
            store.save_attributions(&decisions).expect("save");
        }

        let classifier =
            tattletale::classify::Classifier::load(Some(&tattletale::classify::lists_dir()));
        let mut apps = store.app_rows(now - 3600, 10).expect("app_rows");
        for app in &mut apps {
            for site in &mut app.top_sites {
                site.category = classifier.classify(&site.host);
            }
            app.tracked = app
                .top_sites
                .iter()
                .filter(|s| s.category.is_flagged())
                .map(|s| s.connections)
                .sum();
        }

        let events = store.events(now - 3600, 20_000).expect("events");
        let health = tattletale::health::assess(&events);

        let frame = tattletale::live::Frame {
            elapsed: Duration::from_secs(tick as u64),
            connections: apps.iter().map(|a| a.connections as usize).sum(),
            flagged: apps.iter().map(|a| a.tracked).sum(),
            named: health.named,
            total: health.total,
            apps,
        };

        println!("<<<FRAME>>>");
        print!("{}", frame.render());
    }

    // The closing lines are typed after the table, so the GIF can end on the
    // command a viewer should run next.
    println!("<<<FRAME>>>");
    println!("  ctrl-c to stop");
    println!("<<<FRAME>>>");
    print!("$ tattle report --open\n\n  receipt written to receipt.html\n");
}
