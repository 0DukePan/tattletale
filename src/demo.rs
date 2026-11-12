//! Synthetic scenes for the demo and for the golden tests.
//!
//! A receipt needs a full day of traffic to look like anything, and a new user
//! installing the tool has an empty database. `tattle demo` fills one with a
//! plausible, labelled scene so the receipt can be seen — and recorded for the
//! README — before a single real packet has been observed.
//!
//! A scene is **explicitly** synthetic. Every command that uses one says so in
//! the output and stamps the receipt, because a fabricated screenshot presented
//! as real would be the one unforgivable thing a privacy tool could do.

use crate::model::{DnsRecord, DnsSection, DnsSource, Proto, Sample};

/// One synthetic scene: names resolved, connections opened.
#[derive(Debug, Clone)]
pub struct Scene {
    pub name: &'static str,
    pub host: &'static str,
    pub port: u16,
    /// Domains the app resolved and contacted, in order.
    pub contacts: &'static [(&'static str, &'static str)],
}

/// A working-day browsing scene: a browser, a chat client, a music player, and
/// an editor's updater. The tracker contacts are real domains from the seed
/// list, so the chips in the receipt are genuine classifications of genuine
/// names — only the timing is invented.
pub const BROWSING: &[Scene] = &[
    Scene {
        name: "chrome.exe",
        host: "142.250.75.238",
        port: 443,
        contacts: &[
            ("github.com", "140.82.114.25"),
            ("www.google-analytics.com", "142.250.190.78"),
            ("doubleclick.net", "142.250.191.102"),
            ("stats.g.doubleclick.net", "142.250.191.110"),
            ("googlesyndication.com", "142.250.191.130"),
            ("youtube.com", "142.250.190.46"),
            ("i.ytimg.com", "142.251.148.6"),
            ("scorecardresearch.com", "23.43.121.68"),
            ("criteo.com", "178.250.10.25"),
            ("taboola.com", "191.101.209.10"),
        ],
    },
    Scene {
        name: "slack.exe",
        host: "52.1.2.3",
        port: 443,
        contacts: &[
            ("slack.com", "52.1.2.3"),
            ("wss-primary.slack.com", "52.1.2.4"),
            ("segment.io", "52.22.18.9"),
            ("sentry.io", "35.186.224.47"),
        ],
    },
    Scene {
        name: "spotify.exe",
        host: "35.186.224.25",
        port: 443,
        contacts: &[
            ("spotify.com", "35.186.224.25"),
            ("spclient.wg.spotify.com", "35.186.224.30"),
            ("scorecardresearch.com", "23.43.121.69"),
            ("doubleclick.net", "142.250.191.103"),
        ],
    },
    Scene {
        name: "Discord.exe",
        host: "162.159.135.234",
        port: 443,
        contacts: &[
            ("discord.com", "162.159.135.234"),
            ("cdn.discordapp.com", "162.159.136.1"),
        ],
    },
    Scene {
        name: "Code.exe",
        host: "20.42.65.82",
        port: 443,
        contacts: &[
            ("vscode-update.azurewebsites.net", "20.42.65.82"),
            ("marketplace.visualstudio.com", "20.42.128.1"),
        ],
    },
];

/// Night traffic: things that run while the machine is idle. This is the part
/// of a receipt that surprises people, so the demo scene includes it.
pub const NIGHT: &[Scene] = &[
    Scene {
        name: "svchost.exe",
        host: "13.107.4.50",
        port: 443,
        contacts: &[("settings-win.data.microsoft.com", "13.107.4.50")],
    },
    Scene {
        name: "OneDrive.exe",
        host: "13.107.136.9",
        port: 443,
        contacts: &[("storage.live.com", "13.107.136.9")],
    },
    Scene {
        name: "Spotify.exe",
        host: "35.186.224.26",
        port: 443,
        contacts: &[("spclient.wg.spotify.com", "35.186.224.26")],
    },
];

/// Expand a scene into samples and DNS observations for a window ending at
/// `now`, spread across `hours` with a believable daily shape.
///
/// The shape matters: a flat line across 24 hours is obviously fake, and the
/// receipt's whole visual point is the shape of a day.
pub fn materialise(
    scenes: &[Scene],
    since: i64,
    now: i64,
    hours: i64,
) -> (Vec<Sample>, Vec<DnsRecord>) {
    spread(scenes, since, now, hours, 8, 20, 0)
}

/// Expand the night scene, placing every contact between 01:00 and 06:00.
///
/// Separate from [`materialise`] because a scene that claims to show what ran
/// while the machine was idle has to actually be in those hours. Spreading it
/// over the whole day produced a receipt that said "while you were asleep: ...
/// chrome.exe", which is incoherent on its face.
pub fn materialise_night(
    scenes: &[Scene],
    since: i64,
    now: i64,
    hours: i64,
) -> (Vec<Sample>, Vec<DnsRecord>) {
    spread(scenes, since, now, hours, 1, 6, 0)
}

/// Place a scene's contacts between two local hours of the day.
#[allow(clippy::too_many_arguments)]
fn spread(
    scenes: &[Scene],
    since: i64,
    now: i64,
    hours: i64,
    first_hour: i64,
    last_hour: i64,
    seed_offset: i64,
) -> (Vec<Sample>, Vec<DnsRecord>) {
    use crate::report::build::hour_of_day;

    let mut samples = Vec::new();
    let mut records = Vec::new();

    // Collect every instant in the window whose local hour is inside the band.
    let band_seconds = ((last_hour - first_hour).max(1)) * 3600;
    let mut day_starts = Vec::new();
    let mut at = since;
    while at < now {
        if hour_of_day(at) == first_hour as u32 {
            day_starts.push(at);
            at += band_seconds.max(3600);
        } else {
            at += 900;
        }
    }
    if day_starts.is_empty() {
        day_starts.push(since);
    }

    let total_contacts: usize = scenes
        .iter()
        .map(|s| s.contacts.len())
        .max()
        .unwrap_or(1)
        .max(1);

    for (index, scene) in scenes.iter().enumerate() {
        for (contact_index, (host, ip)) in scene.contacts.iter().enumerate() {
            // Distribute contacts across the band and across days, so a 24-hour
            // window shows a few points in each night rather than one burst.
            let day = day_starts[(index + seed_offset as usize) % day_starts.len()];
            let slot = (contact_index * band_seconds as usize) / total_contacts;
            let opened_at = day + slot as i64 + (index as i64 * 61);

            if opened_at < since || opened_at > now {
                continue;
            }

            // The resolver answers a second or two before the connection.
            records.push(DnsRecord {
                host: (*host).to_string(),
                ip: (*ip).to_string(),
                rtype: 1,
                section: DnsSection::Answer,
                ttl: 300,
                first_seen: opened_at - 2,
                last_seen: opened_at,
                source: DnsSource::Replay,
            });

            // A few reopens, so the "connections" column is not always 1.
            let opens = 1 + (index as u64 + contact_index as u64) % 4;
            for open_index in 0..opens {
                let opened = opened_at + open_index as i64 * 41;
                // A connection is observed for three polls, so the last one
                // must still fit inside the window.
                if opened + 2 > now {
                    break;
                }
                for poll in 0..3 {
                    samples.push(Sample {
                        at: opened + poll,
                        app_path: format!("C:\\Program Files\\Synthetic\\{0}", scene.name),
                        app_name: scene.name.to_string(),
                        ip: (*ip).to_string(),
                        port: scene.port,
                        proto: Proto::Tcp,
                    });
                }
            }
        }
        let _ = scene.host;
    }
    let _ = hours;

    samples.sort_by_key(|s| s.at);
    records.sort_by_key(|r| r.first_seen);
    (samples, records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scene_produces_samples_and_names() {
        let since = 1_700_000_000;
        let now = since + 86_400;
        let (samples, records) = materialise(BROWSING, since, now, 24);
        assert!(!samples.is_empty());
        assert!(!records.is_empty());
    }

    #[test]
    fn every_name_is_resolved_before_it_is_contacted() {
        let since = 1_700_000_000;
        let now = since + 86_400;
        let (samples, records) = materialise(BROWSING, since, now, 24);
        for sample in &samples {
            let resolved = records
                .iter()
                .filter(|r| r.ip == sample.ip)
                .any(|r| r.first_seen <= sample.at);
            assert!(
                resolved,
                "{} at {} has no name resolved before it",
                sample.ip, sample.at
            );
        }
    }

    #[test]
    fn diag_window() {
        let since = 1_700_000_000i64;
        let now = since + 6 * 3600;
        let (s, r) = materialise(BROWSING, since, now, 6);
        let bad: Vec<_> = s.iter().filter(|x| x.at < since || x.at > now).collect();
        println!(
            "since={since} now={now} samples={} bad={}",
            s.len(),
            bad.len()
        );
        for b in bad.iter().take(3) {
            println!("  at={} (now+{})", b.at, b.at - now);
        }
        let rb: Vec<_> = r.iter().filter(|x| x.first_seen < since).collect();
        println!("records={} bad_records={}", r.len(), rb.len());
        for b in rb.iter().take(3) {
            println!(
                "  first_seen={} (since-{})",
                b.first_seen,
                since - b.first_seen
            );
        }
    }
    #[test]
    fn everything_stays_inside_the_window() {
        let since = 1_700_000_000;
        let now = since + 6 * 3600;
        let (samples, records) = materialise(BROWSING, since, now, 6);
        assert!(
            samples.iter().all(|s| s.at >= since && s.at <= now),
            "a sample escaped the window"
        );
        // A name may be resolved a moment *before* the window opens: that
        // resolution is exactly what explains a connection at the first second.
        assert!(
            records.iter().all(|r| r.first_seen >= since - 5),
            "a name predates the window by more than the resolution lead time"
        );
    }

    #[test]
    fn the_scene_contains_domains_the_classifier_will_flag() {
        // The demo is worthless if the chips never appear.
        let classifier = crate::classify::Classifier::seed();
        let flagged = BROWSING
            .iter()
            .flat_map(|s| s.contacts.iter())
            .filter(|(host, _)| classifier.is_flagged(host))
            .count();
        assert!(
            flagged >= 5,
            "only {flagged} flagged domains in the demo scene"
        );
    }
}
