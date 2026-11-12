//! The attribution engine: deciding which domain a connection belongs to.
//!
//! This is the part of the product that can be wrong, so it is written to be
//! *auditable* rather than clever. Every decision produces a [`Tier`] and a
//! `method` string that is stored with the attribution and shown in the UI when
//! the user asks "how do you know?".
//!
//! The rules, in order:
//!
//! 1. No candidate resolved for this address in the window → `Unknown`, and the
//!    UI shows the address with no name. Never guess.
//! 2. Exactly one candidate resolved within the window → `High`.
//! 3. Several candidates, or the same address already claimed by another app in
//!    the same window → `Probable`, and every candidate is kept so the verify
//!    panel can list them.
//! 4. A candidate whose resolution is older than the window → not a candidate
//!    at all. A name resolved an hour ago explains nothing about a connection
//!    opening now.
//!
//! There is deliberately no `Exact` tier in standard mode: `Exact` requires a
//! DNS event carrying the requesting process id, which needs ETW and therefore
//! administrator rights. [`Tier::Exact`] exists for that future path and is
//! never produced by [`resolve`].

use std::collections::HashMap;

use crate::dns::site_of;
use crate::model::{Attribution, DnsRecord, Tier};

/// How far back a resolution may be and still explain a connection.
///
/// 90 seconds is chosen from the shape of the cache rather than from taste:
/// browsers resolve immediately before connecting, and a slower flow (an app
/// that resolves at start-up and connects later) still lands inside it, while
/// a name resolved minutes ago belongs to some earlier, unrelated connection.
pub const WINDOW_SECONDS: i64 = 90;

/// A resolution slightly *after* the connection is possible, because the
/// connection table and the resolver cache are polled at different moments.
/// This is the only forward tolerance allowed.
pub const FORWARD_SLACK_SECONDS: i64 = 3;

/// How many candidate names are kept for one connection. More than a handful
/// means the address is shared by a CDN and the answer is "we do not know which
/// one", which the UI states.
pub const MAX_CANDIDATES: usize = 3;

/// One connection waiting to be attributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub conn_id: i64,
    pub app_id: i64,
    pub ip: String,
    /// Unix seconds when this connection was first seen.
    pub at: i64,
}

/// The decision for one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub conn_id: i64,
    pub tier: Tier,
    pub method: String,
    /// Unix seconds of the open this decision explains. Stored with the
    /// decision so a later pass can tell "already resolved" from "reopened
    /// since", including for `Unknown` results that have no attributions.
    pub at: i64,
    /// Best-first candidates. Empty when `tier` is `Unknown`.
    pub attributions: Vec<Attribution>,
}

/// Resolve pending connections against the DNS observations.
///
/// `observations` must contain every record currently held by the tracker. The
/// engine is stateless on purpose: given the same inputs it returns the same
/// decisions, which is what makes the tests meaningful and the UI explainable.
pub fn resolve(pending: &[Pending], observations: &[DnsRecord]) -> Vec<Decision> {
    // Index observations by address once: resolving a batch of connections
    // against a flat list would be quadratic, and the cache holds thousands of
    // records on a busy machine.
    let mut by_ip: HashMap<&str, Vec<&DnsRecord>> = HashMap::new();
    for record in observations {
        if !record.is_address() {
            continue;
        }
        by_ip.entry(record.ip.as_str()).or_default().push(record);
    }

    // Tracks which application claimed an address inside the window, so a
    // shared CDN address used by two apps is not reported as a confident match
    // for either of them.
    let mut claimed: HashMap<(&str, i64), i64> = HashMap::new();

    let mut decisions = Vec::with_capacity(pending.len());

    for conn in pending {
        let candidates = candidates_for(conn, by_ip.get(conn.ip.as_str()));

        if candidates.is_empty() {
            decisions.push(Decision {
                conn_id: conn.conn_id,
                tier: Tier::Unknown,
                method: "no-dns-observation".to_string(),
                at: conn.at,
                attributions: Vec::new(),
            });
            continue;
        }

        // Did another application resolve this address in the same window?
        let bucket = conn.at / WINDOW_SECONDS;
        let contended = claimed
            .get(&(conn.ip.as_str(), bucket))
            .is_some_and(|owner| *owner != conn.app_id);
        claimed
            .entry((conn.ip.as_str(), bucket))
            .or_insert(conn.app_id);

        let (tier, method) = match (candidates.len(), contended) {
            (1, false) => (Tier::High, "single-candidate"),
            (1, true) => (Tier::Probable, "address-shared-between-apps"),
            (_, false) => (Tier::Probable, "multiple-candidates"),
            (_, true) => (Tier::Probable, "multiple-candidates-shared-between-apps"),
        };

        let attributions = candidates
            .iter()
            .take(MAX_CANDIDATES)
            .map(|record| Attribution {
                conn_id: conn.conn_id,
                host: record.host.clone(),
                site: site_of(&record.host),
                tier,
                method: method.to_string(),
                at: conn.at,
            })
            .collect();

        decisions.push(Decision {
            conn_id: conn.conn_id,
            tier,
            method: method.to_string(),
            at: conn.at,
            attributions,
        });
    }

    decisions
}

/// The candidate names for one connection, best first.
fn candidates_for<'a>(
    conn: &Pending,
    observations: Option<&Vec<&'a DnsRecord>>,
) -> Vec<&'a DnsRecord> {
    let Some(observations) = observations else {
        return Vec::new();
    };

    let mut hits: Vec<&DnsRecord> = observations
        .iter()
        .copied()
        .filter(|record| {
            record.first_seen <= conn.at + FORWARD_SLACK_SECONDS
                && record.first_seen >= conn.at - WINDOW_SECONDS
        })
        .collect();

    // Most recent resolution first; an answer-section record outranks an
    // additional-section one resolved at the same moment.
    hits.sort_by(|a, b| {
        b.first_seen
            .cmp(&a.first_seen)
            .then(b.section.cmp(&a.section))
    });
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsSection, DnsSource};

    fn obs(host: &str, ip: &str, first_seen: i64) -> DnsRecord {
        DnsRecord {
            host: host.into(),
            ip: ip.into(),
            rtype: 1,
            section: DnsSection::Answer,
            ttl: 60,
            first_seen,
            last_seen: first_seen,
            source: DnsSource::Ipconfig,
        }
    }

    fn conn(id: i64, app_id: i64, ip: &str, at: i64) -> Pending {
        Pending {
            conn_id: id,
            app_id,
            ip: ip.into(),
            at,
        }
    }

    #[test]
    fn a_single_recent_resolution_is_high_confidence() {
        let observations = vec![obs("api.example.com", "1.2.3.4", 1000)];
        let decisions = resolve(&[conn(1, 7, "1.2.3.4", 1030)], &observations);
        assert_eq!(decisions[0].tier, Tier::High);
        assert_eq!(decisions[0].method, "single-candidate");
        assert_eq!(decisions[0].attributions.len(), 1);
        assert_eq!(decisions[0].attributions[0].host, "api.example.com");
        assert_eq!(decisions[0].attributions[0].site, "example.com");
    }

    #[test]
    fn no_observation_means_unknown_and_no_guess() {
        let decisions = resolve(&[conn(1, 7, "8.8.8.8", 1000)], &[]);
        assert_eq!(decisions[0].tier, Tier::Unknown);
        assert!(decisions[0].attributions.is_empty(), "never invent a name");
    }

    #[test]
    fn a_resolution_outside_the_window_does_not_count() {
        // Resolved 91 s before the connection opened: outside the window.
        let observations = vec![obs("stale.example.com", "1.2.3.4", 1000)];
        let decisions = resolve(&[conn(1, 7, "1.2.3.4", 1091)], &observations);
        assert_eq!(decisions[0].tier, Tier::Unknown);

        // 90 s before is still inside it.
        let observations = vec![obs("fresh.example.com", "1.2.3.4", 1000)];
        let decisions = resolve(&[conn(1, 7, "1.2.3.4", 1090)], &observations);
        assert_eq!(decisions[0].tier, Tier::High);
    }

    #[test]
    fn a_connection_can_happen_just_before_the_cache_is_polled() {
        // The resolver answered 2 s after the connection table was polled.
        let observations = vec![obs("api.example.com", "1.2.3.4", 1002)];
        let decisions = resolve(&[conn(1, 7, "1.2.3.4", 1000)], &observations);
        assert_eq!(decisions[0].tier, Tier::High);

        // Four seconds later is too far forward: that is a different connection.
        let observations = vec![obs("api.example.com", "1.2.3.4", 1004)];
        let decisions = resolve(&[conn(1, 7, "1.2.3.4", 1000)], &observations);
        assert_eq!(decisions[0].tier, Tier::Unknown);
    }

    #[test]
    fn several_candidates_are_probable_and_all_are_kept() {
        let observations = vec![
            obs("a.cdn.example", "1.2.3.4", 1000),
            obs("b.cdn.example", "1.2.3.4", 1001),
        ];
        let decisions = resolve(&[conn(1, 7, "1.2.3.4", 1010)], &observations);
        assert_eq!(decisions[0].tier, Tier::Probable);
        assert_eq!(
            decisions[0].attributions.len(),
            2,
            "the verify panel needs both"
        );
        assert_eq!(
            decisions[0].attributions[0].host, "b.cdn.example",
            "most recent first"
        );
    }

    #[test]
    fn candidates_are_capped() {
        let observations: Vec<DnsRecord> = (0..10)
            .map(|i| obs(&format!("h{i}.cdn.example"), "1.2.3.4", 1000 + i as i64))
            .collect();
        let decisions = resolve(&[conn(1, 7, "1.2.3.4", 1020)], &observations);
        assert_eq!(decisions[0].attributions.len(), MAX_CANDIDATES);
        assert_eq!(decisions[0].tier, Tier::Probable);
    }

    #[test]
    fn an_address_used_by_two_apps_is_not_confidently_attributed() {
        let observations = vec![obs("shared.example", "1.2.3.4", 1000)];
        // Two different apps connect to the same address in the same window.
        let decisions = resolve(
            &[conn(1, 7, "1.2.3.4", 1001), conn(2, 9, "1.2.3.4", 1002)],
            &observations,
        );
        assert_eq!(
            decisions[0].tier,
            Tier::High,
            "the first claim is unopposed"
        );
        assert_eq!(
            decisions[1].tier,
            Tier::Probable,
            "the second app shares an address"
        );
        assert_eq!(decisions[1].method, "address-shared-between-apps");
    }

    #[test]
    fn the_same_app_reusing_an_address_stays_confident() {
        let observations = vec![obs("api.example.com", "1.2.3.4", 1000)];
        let decisions = resolve(
            &[conn(1, 7, "1.2.3.4", 1001), conn(2, 7, "1.2.3.4", 1002)],
            &observations,
        );
        assert_eq!(decisions[0].tier, Tier::High);
        assert_eq!(
            decisions[1].tier,
            Tier::High,
            "one app, one address, no ambiguity"
        );
    }

    #[test]
    fn only_address_records_become_candidates() {
        let mut txt = obs("example.com", "1.2.3.4", 1000);
        txt.rtype = 12;
        let decisions = resolve(&[conn(1, 7, "1.2.3.4", 1010)], &[txt]);
        assert_eq!(
            decisions[0].tier,
            Tier::Unknown,
            "a PTR record is not an address answer"
        );
    }

    #[test]
    fn exact_is_never_produced_in_standard_mode() {
        let observations = vec![obs("api.example.com", "1.2.3.4", 1000)];
        let decisions = resolve(
            &[conn(1, 7, "1.2.3.4", 1000), conn(2, 8, "1.2.3.4", 1000)],
            &observations,
        );
        assert!(decisions.iter().all(|d| d.tier != Tier::Exact));
    }

    #[test]
    fn resolution_is_deterministic() {
        let observations = vec![
            obs("a.example", "1.2.3.4", 1000),
            obs("b.example", "1.2.3.4", 1000),
        ];
        let pending = vec![conn(1, 7, "1.2.3.4", 1010)];
        let first = resolve(&pending, &observations);
        let second = resolve(&pending, &observations);
        assert_eq!(first, second);
    }
}
