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

    // Reverse-DNS answers are indexed separately. They name whoever owns the
    // address, not the site the application asked for, so they are a weaker
    // tier and must never outrank a real hostname.
    let mut ptr_by_ip: HashMap<&str, Vec<&DnsRecord>> = HashMap::new();
    for record in observations {
        if record.rtype == crate::dns::TYPE_PTR {
            ptr_by_ip
                .entry(record.ip.as_str())
                .or_default()
                .push(record);
        }
    }

    // Every (time, app) that claimed an address, so contention is judged
    // against the actual window rather than against a fixed bucket.
    let mut claimed: HashMap<&str, Vec<(i64, i64, i64)>> = HashMap::new();

    let mut decisions = Vec::with_capacity(pending.len());

    for conn in pending {
        let candidates = candidates_for(conn, by_ip.get(conn.ip.as_str()));

        if candidates.is_empty() {
            // No hostname was resolved. Before giving up, fall back to whoever
            // owns the address: that is what reverse DNS knows, and it is the
            // only evidence available for traffic that bypassed the resolver.
            let owners = ptr_by_ip.get(conn.ip.as_str());
            let attributions: Vec<Attribution> = owners
                .map(|records| {
                    records
                        .iter()
                        .take(MAX_CANDIDATES)
                        .map(|record| Attribution {
                            conn_id: conn.conn_id,
                            host: record.host.clone(),
                            site: site_of(&record.host),
                            tier: Tier::Probable,
                            method: "reverse-dns-owner".to_string(),
                            at: conn.at,
                        })
                        .collect()
                })
                .unwrap_or_default();

            let (tier, method) = if attributions.is_empty() {
                (Tier::Unknown, "no-dns-observation")
            } else {
                // The owner is known; the specific site is not. Probable is the
                // honest tier: this says "Google", never "google.com".
                (Tier::Probable, "reverse-dns-owner")
            };

            decisions.push(Decision {
                conn_id: conn.conn_id,
                tier,
                method: method.to_string(),
                at: conn.at,
                attributions,
            });
            continue;
        }

        // Did another application use this address within one window of now?
        //
        // Fixed time buckets were wrong at their boundaries: two apps
        // connecting to the same CDN address a second apart could land in
        // different buckets and both be reported `High`, which is exactly the
        // shared-address case the tier exists to catch.
        //
        // Contention is two-sided. The first claimant used to stay `High` and
        // only the second was demoted, which is incoherent: the name does not
        // say *which* application it was for, so neither of them knows. Both
        // are reported `Probable`, and the first is corrected when the second
        // arrives.
        let claims = claimed.entry(conn.ip.as_str()).or_default();
        let contended = claims
            .iter()
            .any(|(at, app, _)| *app != conn.app_id && (at - conn.at).abs() <= WINDOW_SECONDS);

        if contended && !claims.is_empty() && candidates.len() == 1 {
            // Demote the claim already recorded, if this is a genuine contest
            // over one name. A record with several candidates was never `High`
            // to begin with.
            let earlier: Vec<i64> = claims
                .iter()
                .filter(|(_, app, _)| *app != conn.app_id)
                .map(|(_, _, id)| *id)
                .collect();
            for conn_id in earlier {
                if let Some(previous) = decisions
                    .iter_mut()
                    .find(|d: &&mut Decision| d.conn_id == conn_id)
                {
                    if previous.tier == Tier::High {
                        previous.tier = Tier::Probable;
                        previous.method = "address-shared-between-apps".to_string();
                        for attribution in &mut previous.attributions {
                            attribution.tier = Tier::Probable;
                            attribution.method = "address-shared-between-apps".to_string();
                        }
                    }
                }
            }
        }

        claims.push((conn.at, conn.app_id, conn.conn_id));

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
        // Contention is two-sided: the name does not say which application it
        // was for, so neither of them may claim `high`.
        assert_eq!(
            decisions[0].tier,
            Tier::Probable,
            "the first claim is demoted once a second app is seen"
        );
        assert_eq!(
            decisions[1].tier,
            Tier::Probable,
            "the second app shares an address"
        );
        assert_eq!(decisions[1].method, "address-shared-between-apps");
    }

    #[test]
    fn a_shared_address_across_a_bucket_boundary_is_still_shared() {
        // 89 and 91 straddle the 90-second boundary the previous implementation
        // bucketed on, so the two connections used to land in different buckets
        // and both be reported `High` despite sharing one CDN address.
        let observations = vec![obs("shared.example", "1.2.3.4", 60)];
        let decisions = resolve(
            &[conn(1, 7, "1.2.3.4", 89), conn(2, 9, "1.2.3.4", 91)],
            &observations,
        );
        assert_eq!(
            decisions[0].tier,
            Tier::Probable,
            "the first claim is demoted once the second app is seen"
        );
        assert_eq!(
            decisions[1].tier,
            Tier::Probable,
            "one second apart is still one address in use by two applications"
        );
        assert_eq!(decisions[1].method, "address-shared-between-apps");
    }

    #[test]
    fn an_address_reused_long_afterwards_is_not_contended() {
        // Two apps using the same address an hour apart is not a shared
        // address; collapsing that to `Probable` would understate confidence
        // for the most common case of all, a CDN endpoint reused all day.
        let observations = vec![
            obs("shared.example", "1.2.3.4", 58),
            obs("shared.example", "1.2.3.4", 598),
        ];
        let decisions = resolve(
            &[conn(1, 7, "1.2.3.4", 60), conn(2, 9, "1.2.3.4", 600)],
            &observations,
        );
        assert_eq!(decisions[0].tier, Tier::High);
        assert_eq!(decisions[1].tier, Tier::High, "an hour apart is unrelated");
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
    fn a_reverse_lookup_names_the_owner_but_never_as_confidently_as_a_hostname() {
        // A PTR answer says who owns the address, not which site the app asked
        // for. It is a fallback for traffic that bypassed the resolver, and it
        // must never reach `High`: that would claim knowledge we do not have.
        let mut ptr = obs("xx.1e100.net", "1.2.3.4", 1000);
        ptr.rtype = 12;

        let decisions = resolve(&[conn(1, 7, "1.2.3.4", 1010)], &[ptr]);
        assert_eq!(decisions[0].tier, Tier::Probable);
        assert_eq!(decisions[0].method, "reverse-dns-owner");
        assert_eq!(decisions[0].attributions[0].host, "xx.1e100.net");
        assert_eq!(decisions[0].attributions[0].site, "1e100.net");
    }

    #[test]
    fn a_real_hostname_outranks_a_reverse_lookup() {
        // When both exist, the name the resolver actually saw wins, and the
        // reverse answer is not offered as a second candidate.
        let mut ptr = obs("xx.1e100.net", "1.2.3.4", 999);
        ptr.rtype = 12;
        let hostname = obs("api.example.com", "1.2.3.4", 1000);

        let decisions = resolve(&[conn(1, 7, "1.2.3.4", 1010)], &[hostname, ptr]);
        assert_eq!(decisions[0].tier, Tier::High);
        assert_eq!(
            decisions[0].attributions.len(),
            1,
            "only the hostname is offered"
        );
        assert_eq!(decisions[0].attributions[0].host, "api.example.com");
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
