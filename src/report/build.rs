//! Building a receipt from a store.

use std::collections::BTreeSet;

use crate::model::Tier;
use crate::report::{NightSummary, ReportModel};
use crate::store::Store;

/// Hours that count as "while you were asleep". Local time, not UTC: the point
/// is to show the user what ran while *they* were in bed.
const NIGHT_START_HOUR: u32 = 0;
const NIGHT_END_HOUR: u32 = 7;

/// A connection as the aggregation needs it: who, when, and how sure we are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub app: String,
    pub site: Option<String>,
    pub at: i64,
    pub tier: Tier,
    /// The address dialled. Needed to recognise resolver endpoints, which is
    /// how the receipt knows to disclose a DNS over HTTPS blind spot.
    pub ip: String,
    pub port: u16,
}

/// Assemble the model for a window ending at `now`.
///
/// Everything here is derived from the store; the renderer decides only
/// presentation. That split is what lets the golden test pin a model and get
/// byte-identical HTML.
pub fn build(
    store: &dyn Store,
    since: i64,
    now: i64,
    machine: String,
) -> anyhow::Result<ReportModel> {
    let totals = store.totals(since)?;
    let apps = store.app_rows(since, 20)?;
    let sites = store.site_rows(since, 20)?;
    let events = store.events(since, 50_000)?;
    let health = crate::health::assess(&events);

    Ok(ReportModel {
        generated_at: now,
        since,
        machine,
        totals,
        night: night_summary(&events),
        hourly: hourly_histogram(&events),
        apps,
        sites,
        caveats: health.caveats.clone(),
        coverage: health.coverage(),
        named: health.named,
    })
}

/// Count connections per hour **of the day**, always 24 buckets.
///
/// The chart answers "what time of day is my machine busiest", not "what
/// happened in each 5-minute slice of the window". Bucketing by window position
/// produced a single towering bar for a short recording, which is a chart that
/// says nothing; bucketing by clock hour is comparable across days and makes
/// the night band meaningful.
fn hourly_histogram(events: &[Event]) -> Vec<u64> {
    let mut buckets = vec![0u64; 24];
    for event in events {
        let hour = hour_of_day(event.at) as usize;
        if let Some(bucket) = buckets.get_mut(hour) {
            *bucket += 1;
        }
    }
    buckets
}

/// What happened between midnight and 07:00.
fn night_summary(events: &[Event]) -> NightSummary {
    let mut connections = 0u64;
    let mut app_names = BTreeSet::new();

    for event in events {
        let hour = hour_of_day(event.at);
        if (NIGHT_START_HOUR..NIGHT_END_HOUR).contains(&hour) {
            connections += 1;
            app_names.insert(event.app.clone());
        }
    }

    // A receipt that lists twenty applications is noise; the point is the
    // count and a couple of names.
    let apps: Vec<String> = app_names.iter().take(3).cloned().collect();
    NightSummary { connections, apps }
}

/// Hour of the day in local time.
pub fn hour_of_day(unix: i64) -> u32 {
    let local = unix + local_offset_seconds();
    (local.rem_euclid(86_400) / 3600) as u32
}

#[cfg(windows)]
fn local_offset_seconds() -> i64 {
    use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};

    /// `TIME_ZONE_ID_DAYLIGHT`, from `winnt.h`. The binding crate exports the
    /// struct and the function but not this constant.
    const TIME_ZONE_ID_DAYLIGHT: u32 = 2;

    unsafe {
        let mut tz: TIME_ZONE_INFORMATION = std::mem::zeroed();
        let result = GetTimeZoneInformation(&mut tz);
        // `Bias` is minutes *west* of UTC, so the local offset subtracts it.
        let mut bias = tz.Bias as i64;
        if result == TIME_ZONE_ID_DAYLIGHT {
            bias += tz.DaylightBias as i64;
        }
        -(bias * 60)
    }
}

#[cfg(not(windows))]
fn local_offset_seconds() -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(at: i64, app: &str) -> Event {
        Event {
            app: app.into(),
            site: Some("example.com".into()),
            at,
            tier: Tier::High,
            ip: "1.2.3.4".into(),
            port: 443,
        }
    }

    #[test]
    fn histogram_always_has_24_buckets() {
        let buckets = hourly_histogram(&[]);
        assert_eq!(buckets.len(), 24);
        assert!(buckets.iter().all(|b| *b == 0));
    }

    #[test]
    fn histogram_buckets_by_hour_of_day() {
        // Find instants at known local hours, then check each lands in its own
        // bucket. Deriving them from `hour_of_day` keeps this correct in any
        // timezone the test runs in.
        let mut events = Vec::new();
        let mut wanted = vec![3u32, 9, 14, 22];
        let mut at = 1_700_000_000i64;
        while !wanted.is_empty() && at < 1_700_000_000 + 3 * 86_400 {
            let hour = hour_of_day(at);
            if let Some(pos) = wanted.iter().position(|w| *w == hour) {
                events.push(event(at, "a"));
                wanted.remove(pos);
            }
            at += 60;
        }
        assert!(wanted.is_empty(), "could not find all target hours");

        let buckets = hourly_histogram(&events);
        assert_eq!(buckets.iter().sum::<u64>(), 4);
        assert_eq!(buckets[3], 1);
        assert_eq!(buckets[9], 1);
        assert_eq!(buckets[14], 1);
        assert_eq!(buckets[22], 1);
    }

    #[test]
    fn histogram_accumulates_events_in_the_same_hour() {
        // Two connections a minute apart in the same hour share one bar.
        let base = 1_700_000_000i64;
        let first = (0..10_000)
            .map(|i| base + i * 60)
            .find(|t| hour_of_day(*t) == 12)
            .expect("an hour-12 instant");
        let events = vec![event(first, "a"), event(first + 60, "b")];
        let buckets = hourly_histogram(&events);
        assert_eq!(buckets.iter().sum::<u64>(), 2);
        assert_eq!(buckets[12], 2, "same hour, same bar");
    }

    #[test]
    fn night_summary_is_bounded_to_three_names() {
        // Pick instants whose local hour is inside the night band regardless of
        // the machine's timezone, by deriving them from `hour_of_day` itself.
        let mut events = Vec::new();
        let mut at = 1_700_000_000;
        let mut found = 0;
        while found < 10 && events.len() < 200_000 {
            if hour_of_day(at) < NIGHT_END_HOUR {
                events.push(event(at, &format!("app{found}.exe")));
                found += 1;
            }
            at += 300;
        }
        assert_eq!(events.len(), 10);
        let summary = night_summary(&events);
        assert_eq!(summary.connections, 10);
        assert_eq!(
            summary.apps.len(),
            3,
            "a receipt lists a few names, not all of them"
        );
    }

    #[test]
    fn night_summary_excludes_daytime() {
        let mut events = Vec::new();
        let mut at = 1_700_000_000;
        let mut found = 0;
        while found < 3 && events.len() < 200_000 {
            let hour = hour_of_day(at);
            if (12..18).contains(&hour) {
                events.push(event(at, "chrome.exe"));
                found += 1;
            }
            at += 300;
        }
        let summary = night_summary(&events);
        assert_eq!(
            summary.connections, 0,
            "daytime connections are not night activity"
        );
    }

    #[test]
    fn hour_of_day_is_within_a_day() {
        for unix in [0, 1_794_509_596, 1_700_000_000] {
            assert!(hour_of_day(unix) < 24);
        }
    }
}
