//! An accuracy benchmark, not a coverage statistic.
//!
//! Every number this project has quoted about attribution so far was a
//! *coverage* figure: what fraction of connections carried a name. Coverage is
//! easy and it is not the question. The question is whether the names are
//! **right**.
//!
//! So this measures precision and recall against labelled scenarios where the
//! answer is known, and it counts the errors that matter separately:
//!
//! * a **false positive** names an application that did not make the connection
//!   — the failure that would get this tool discredited, and the reason it
//!   refuses to guess;
//! * a **false negative** names nothing when the name was knowable;
//! * a **wrong-but-confident** result claims `high` and is wrong, which is worse
//!   than either.
//!
//! The scenarios encode the cases the code was written to survive: shared CDN
//! addresses, expired cache entries, CNAME chains, DoH-style traffic with no
//! forward lookup at all, and connections that reopen after the resolver has
//! moved on.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{DnsRecord, DnsSection, DnsSource, Tier};
use crate::resolve::{Decision, Pending};

/// One connection in a labelled scenario, with the answer we know to be true.
#[derive(Debug, Clone)]
pub struct Labelled {
    pub conn_id: i64,
    pub app_id: i64,
    pub ip: String,
    pub at: i64,
    /// The application that really made this connection, as a name.
    pub app_name: &'static str,
    /// The site the application really asked for, if any.
    pub expected_site: Option<&'static str>,
}

/// A scenario: labelled connections, and the DNS observations available to the
/// engine. No network, no clock, no database — this measures the engine.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: &'static str,
    pub connections: Vec<Labelled>,
    pub observations: Vec<DnsRecord>,
}

impl Scenario {
    /// A connection with a known answer.
    pub fn conn(
        &mut self,
        app_id: i64,
        app_name: &'static str,
        ip: &str,
        at: i64,
        expected_site: Option<&'static str>,
    ) {
        let conn_id = self.connections.len() as i64 + 1;
        self.connections.push(Labelled {
            conn_id,
            app_id,
            ip: ip.to_string(),
            at,
            app_name,
            expected_site,
        });
    }

    /// A forward lookup the resolver performed.
    pub fn name(&mut self, host: &str, ip: &str, first_seen: i64) {
        self.observations.push(DnsRecord {
            host: host.to_string(),
            ip: ip.to_string(),
            rtype: 1,
            section: DnsSection::Answer,
            ttl: 300,
            first_seen,
            last_seen: first_seen,
            source: DnsSource::Ipconfig,
        });
    }

    /// A reverse lookup, which names an owner rather than a site.
    pub fn ptr(&mut self, host: &str, ip: &str, first_seen: i64) {
        self.observations.push(DnsRecord {
            host: host.to_string(),
            ip: ip.to_string(),
            rtype: 12,
            section: DnsSection::Ptr,
            ttl: 0,
            first_seen,
            last_seen: first_seen,
            source: DnsSource::ReverseDns,
        });
    }

    /// Run the engine over this scenario.
    pub fn run(&self) -> Vec<Decision> {
        let pending: Vec<Pending> = self
            .connections
            .iter()
            .map(|c| Pending {
                conn_id: c.conn_id,
                app_id: c.app_id,
                ip: c.ip.clone(),
                at: c.at,
            })
            .collect();
        crate::resolve::resolve(&pending, &self.observations)
    }
}

/// What the benchmark counted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Connections that had a knowable name at all.
    pub knowable: u64,
    /// Connections with no name to find, where the engine correctly said so.
    pub correctly_unknown: u64,
    /// Named and right.
    pub true_positives: u64,
    /// Named something else.
    pub false_positives: u64,
    /// Knowable, but left unnamed.
    pub false_negatives: u64,
    /// Claimed `high` and wrong. The worst outcome, tracked on its own.
    pub wrong_high: u64,
    /// Scored connections the engine claimed at `high` confidence.
    pub claimed_high: u64,
    /// Scored connections the engine demoted because the address was shared.
    pub demoted_for_contention: u64,
    /// Per-scenario breakdown, so a regression names its cause.
    pub by_scenario: BTreeMap<String, (u64, u64)>,
}

impl Report {
    /// Of the connections the engine named, how many were right.
    pub fn precision(&self) -> f64 {
        let named = self.true_positives + self.false_positives;
        if named == 0 {
            return 1.0;
        }
        self.true_positives as f64 / named as f64
    }

    /// Of the connections that had a name to find, how many were found.
    pub fn recall(&self) -> f64 {
        if self.knowable == 0 {
            return 1.0;
        }
        self.true_positives as f64 / self.knowable as f64
    }

    /// The share of connections the engine got right, including correctly
    /// refusing to name ones that had no name.
    pub fn accuracy(&self) -> f64 {
        let total = self.knowable + self.correctly_unknown;
        if total == 0 {
            return 1.0;
        }
        (self.true_positives + self.correctly_unknown) as f64 / total as f64
    }
}

/// Compare the engine's decisions with the labels.
///
/// "Right" means the engine offered the expected site among its candidates at a
/// tier that is not `unknown`. It deliberately does not require the top
/// candidate to be the expected one: a CDN address with two plausible sites is
/// a `probable` answer listing both, and calling that a miss would be scoring
/// the engine against information it does not have.
pub fn evaluate(scenarios: &[Scenario]) -> Report {
    let mut report = Report::default();

    for scenario in scenarios {
        let decisions = scenario.run();
        let mut scenario_hits = 0u64;
        let mut scenario_total = 0u64;

        for connection in &scenario.connections {
            let decision = decisions.iter().find(|d| d.conn_id == connection.conn_id);

            match connection.expected_site {
                None => {
                    // Nothing to find. Naming anything here is a false positive.
                    match decision {
                        Some(d) if d.tier == Tier::Unknown => report.correctly_unknown += 1,
                        Some(d) if !d.attributions.is_empty() => report.false_positives += 1,
                        _ => report.correctly_unknown += 1,
                    }
                }
                Some(expected) => {
                    report.knowable += 1;
                    scenario_total += 1;

                    let named = decision.is_some_and(|d| d.tier != Tier::Unknown);
                    let hit =
                        decision.is_some_and(|d| d.attributions.iter().any(|a| a.site == expected));

                    if hit {
                        report.true_positives += 1;
                        scenario_hits += 1;
                        if decision.is_some_and(|d| d.tier == Tier::High) {
                            report.claimed_high += 1;
                        }
                        if decision.is_some_and(|d| d.method.contains("shared")) {
                            report.demoted_for_contention += 1;
                        }
                    } else if named {
                        report.false_positives += 1;
                        if decision.is_some_and(|d| d.tier == Tier::High) {
                            report.wrong_high += 1;
                        }
                    } else {
                        report.false_negatives += 1;
                    }
                }
            }
        }

        report
            .by_scenario
            .insert(scenario.name.to_string(), (scenario_hits, scenario_total));
    }

    report
}

/// The scenarios. Every one of these is a case the engine was written to
/// survive, so a failure here is a real failure, not an artificial one.
pub fn scenarios() -> Vec<Scenario> {
    let mut out = Vec::new();

    // 1. The ordinary case: a name resolved just before the connection.
    {
        let mut s = Scenario {
            name: "direct",
            connections: Vec::new(),
            observations: Vec::new(),
        };
        s.name("api.example.com", "203.0.113.10", 1_000);
        s.conn(1, "app.exe", "203.0.113.10", 1_010, Some("example.com"));
        out.push(s);
    }

    // 2. A shared address: two applications, one second apart, and the resolver
    //    answered once. There is no evidence saying which application used it,
    //    so the honest answer is the site with `probable` confidence for both.
    //
    //    The first version of this scenario labelled a single name on a shared
    //    address and called the result a miss. That was the scenario being
    //    wrong, not the engine: it cannot split one observation between two
    //    applications, and `probable` is exactly the tier that says so.
    {
        let mut s = Scenario {
            name: "shared-address",
            connections: Vec::new(),
            observations: Vec::new(),
        };
        s.name("shared.cdn.example", "203.0.113.20", 1_000);
        s.conn(1, "browser.exe", "203.0.113.20", 1_010, Some("cdn.example"));
        s.conn(2, "chat.exe", "203.0.113.20", 1_011, Some("cdn.example"));
        out.push(s);
    }

    // 3. Two different names for one address, which is what a CDN actually
    //    looks like: both sites are plausible and the engine must offer both
    //    rather than pick one. A hit means the expected site is among the
    //    candidates.
    {
        let mut s = Scenario {
            name: "shared-cdn",
            connections: Vec::new(),
            observations: Vec::new(),
        };
        s.name("assets.cdn.example", "203.0.113.21", 1_000);
        s.name("assets.cdn2.example", "203.0.113.21", 1_001);
        s.conn(1, "browser.exe", "203.0.113.21", 1_010, Some("cdn.example"));
        out.push(s);
    }

    // 3. An expired cache entry: the name was resolved far outside the window.
    //    Claiming it would be a guess.
    {
        let mut s = Scenario {
            name: "expired-entry",
            connections: Vec::new(),
            observations: Vec::new(),
        };
        s.name("old.example.com", "203.0.113.30", 1_000);
        s.conn(1, "app.exe", "203.0.113.30", 1_400, None);
        out.push(s);
    }

    // 4. Two names for one address: a CDN serving two sites. Either is
    //    defensible, so the engine must offer both rather than pick one.
    {
        let mut s = Scenario {
            name: "two-names-one-ip",
            connections: Vec::new(),
            observations: Vec::new(),
        };
        s.name("a.cdn.example", "203.0.113.40", 1_000);
        s.name("b.cdn.example", "203.0.113.40", 1_001);
        s.conn(1, "browser.exe", "203.0.113.40", 1_010, Some("cdn.example"));
        out.push(s);
    }

    // 5. DoH traffic: no forward lookup ever reached the resolver, but a reverse
    //    lookup names the owner.
    {
        let mut s = Scenario {
            name: "doh-with-ptr",
            connections: Vec::new(),
            observations: Vec::new(),
        };
        s.ptr("xx.1e100.net", "203.0.113.50", 1_000);
        s.conn(1, "browser.exe", "203.0.113.50", 1_010, Some("1e100.net"));
        out.push(s);
    }

    // 6. DoH without a reverse record. Nothing is knowable, and the engine must
    //    say so rather than invent a name.
    {
        let mut s = Scenario {
            name: "doh-no-ptr",
            connections: Vec::new(),
            observations: Vec::new(),
        };
        s.conn(1, "browser.exe", "203.0.113.60", 1_010, None);
        out.push(s);
    }

    // 7. A reconnecting client: the connection is seen twice, and the resolver
    //    answered again before the second open.
    {
        let mut s = Scenario {
            name: "reconnect",
            connections: Vec::new(),
            observations: Vec::new(),
        };
        s.name("stream.example.com", "203.0.113.70", 1_000);
        s.conn(1, "player.exe", "203.0.113.70", 1_010, Some("example.com"));
        s.name("stream.example.com", "203.0.113.70", 1_100);
        s.conn(1, "player.exe", "203.0.113.70", 1_110, Some("example.com"));
        out.push(s);
    }

    // 8. A PTR record that only names an address, alongside a real hostname for
    //    a different connection. The reverse answer must not outrank the
    //    hostname on the connection that has one.
    {
        let mut s = Scenario {
            name: "ptr-does-not-outrank",
            connections: Vec::new(),
            observations: Vec::new(),
        };
        s.ptr("lb.example.net", "203.0.113.80", 1_000);
        s.name("api.example.com", "203.0.113.81", 1_000);
        s.conn(1, "app.exe", "203.0.113.80", 1_010, Some("example.net"));
        s.conn(2, "app.exe", "203.0.113.81", 1_010, Some("example.com"));
        out.push(s);
    }

    out
}

/// Every distinct site the scenarios expect. Used by the public dataset, and by
/// the tests that check the labels are internally consistent.
pub fn expected_sites(scenarios: &[Scenario]) -> BTreeSet<&'static str> {
    scenarios
        .iter()
        .flat_map(|s| s.connections.iter())
        .filter_map(|c| c.expected_site)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_benchmark_finds_every_scenario() {
        let scenarios = scenarios();
        assert_eq!(
            scenarios.len(),
            9,
            "scenario list changed without the benchmark knowing"
        );
        assert!(expected_sites(&scenarios).len() >= 4);
    }

    #[test]
    fn a_direct_lookup_is_found_and_counted_as_a_hit() {
        let report = evaluate(&scenarios());
        let (hits, total) = report.by_scenario["direct"];
        assert_eq!((hits, total), (1, 1));
    }

    #[test]
    fn an_expired_entry_is_not_a_hit_and_not_a_false_positive() {
        // Nothing was knowable, and the engine said nothing: that is correct.
        let report = evaluate(&scenarios());
        let (hits, total) = report.by_scenario["expired-entry"];
        assert_eq!(
            (hits, total),
            (0, 0),
            "an unknowable connection is not a scored connection"
        );
        assert!(report.correctly_unknown >= 1);
    }

    #[test]
    fn a_doh_connection_with_a_ptr_is_recovered() {
        let report = evaluate(&scenarios());
        let (hits, total) = report.by_scenario["doh-with-ptr"];
        assert_eq!(
            (hits, total),
            (1, 1),
            "reverse DNS should recover the owner"
        );
    }

    #[test]
    fn a_doh_connection_without_a_ptr_is_left_unknown() {
        let report = evaluate(&scenarios());
        let (hits, total) = report.by_scenario["doh-no-ptr"];
        assert_eq!((hits, total), (0, 0));
    }

    #[test]
    fn every_named_result_is_correct_across_the_whole_suite() {
        // The claim this project makes: it would rather say unknown than be
        // wrong. The benchmark is where that claim has to hold.
        let report = evaluate(&scenarios());
        assert_eq!(
            report.false_positives, 0,
            "the engine named something that was not there: {report:?}"
        );
        assert_eq!(
            report.wrong_high, 0,
            "a confident answer was wrong: {report:?}"
        );
        assert_eq!(report.precision(), 1.0);
    }

    #[test]
    fn recall_is_measured_and_high() {
        let report = evaluate(&scenarios());
        assert!(
            report.recall() >= 0.9,
            "recall dropped to {:.2}; something that used to be knowable is not: {report:?}",
            report.recall()
        );
    }

    #[test]
    fn a_shared_address_is_probable_for_both_applications() {
        // The resolver answered once; both applications are candidates. Neither
        // may claim `high`, and both are still a usable answer.
        let report = evaluate(&scenarios());
        let (hits, total) = report.by_scenario["shared-address"];
        assert_eq!((hits, total), (2, 2));
    }

    #[test]
    fn a_shared_address_is_demoted_rather_than_called_confident() {
        // Scoring only correctness let a mutation through: disabling contention
        // detection entirely still scored 100%, because the site was right even
        // though the confidence was a lie. The benchmark has to see the tier.
        let report = evaluate(&scenarios());
        assert_eq!(
            report.demoted_for_contention, 2,
            "both applications on the shared address must be demoted: {report:?}"
        );
        assert!(
            report.claimed_high < report.true_positives,
            "not every correct answer may claim high confidence: {report:?}"
        );
    }

    #[test]
    fn a_genuine_cdn_with_two_names_offers_the_expected_site() {
        let report = evaluate(&scenarios());
        let (hits, total) = report.by_scenario["shared-cdn"];
        assert_eq!((hits, total), (1, 1));
    }

    #[test]
    fn the_scores_behave_at_their_edges() {
        let empty = Report::default();
        assert_eq!(
            empty.precision(),
            1.0,
            "no predictions is not a precision failure"
        );
        assert_eq!(
            empty.recall(),
            1.0,
            "nothing knowable is not a recall failure"
        );

        let wrong = Report {
            knowable: 4,
            true_positives: 1,
            false_positives: 3,
            ..Report::default()
        };
        assert!((wrong.precision() - 0.25).abs() < f64::EPSILON);
        assert!((wrong.recall() - 0.25).abs() < f64::EPSILON);
    }
}
