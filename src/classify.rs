//! Tracker classification: a domain is flagged only if a list says so.
//!
//! The rule this module exists to enforce: **never infer a category**. A domain
//! is flagged when a list names it or a parent suffix of it. Nothing is flagged
//! because it "looks like" an ad server, because it resolved alongside one, or
//! because an application is disliked. One false accusation in a screenshot and
//! the tool's credibility is gone.
//!
//! Matching walks the domain from most to least specific:
//! `a.b.example.com` checks `a.b.example.com`, `b.example.com`, `example.com`.
//! The first hit wins, which lets a specific rule override a broader one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::model::Category;

/// A compiled set of domain rules, ready for lookup.
#[derive(Debug, Default, Clone)]
pub struct Classifier {
    rules: HashMap<String, Category>,
    /// Number of rules loaded, for `tattle lists status`.
    loaded: usize,
    /// Where the rules came from, for disclosure.
    source: String,
}

/// What a list file's lines look like once normalised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub domain: String,
    pub category: Category,
}

impl Classifier {
    /// An empty classifier: everything is `Unknown`, nothing is flagged.
    pub fn empty() -> Self {
        Self {
            rules: HashMap::new(),
            loaded: 0,
            source: "none".to_string(),
        }
    }

    /// Build from in-memory rules.
    pub fn from_rules(rules: impl IntoIterator<Item = Rule>, source: &str) -> Self {
        let mut map = HashMap::new();
        for rule in rules {
            map.insert(normalise(&rule.domain), rule.category);
        }
        Self {
            loaded: map.len(),
            rules: map,
            source: source.to_string(),
        }
    }

    /// Load the classifier for this machine: the bundled seed list plus any
    /// downloaded lists, with downloaded rules taking precedence.
    pub fn load(lists_dir: Option<&Path>) -> Self {
        let mut rules = parse_seed(CATEGORY_SEED);
        let mut source = "bundled seed".to_string();

        if let Some(lists) = lists_dir {
            let mut found = Vec::new();
            if let Ok(entries) = std::fs::read_dir(lists) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "txt") {
                        found.push(path);
                    }
                }
            }
            for path in found {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    // Downloaded lists are "domain" or "0.0.0.0 domain" lines,
                    // which is the format every blocklist uses.
                    rules.extend(parse_blocklist(&text, Category::Tracker));
                    source = format!("{source} + {} downloaded", lists.display());
                }
            }
        }

        Self::from_rules(rules, &source)
    }

    /// Load only the bundled seed. Used by the demo and by tests.
    pub fn seed() -> Self {
        Self::from_rules(parse_seed(CATEGORY_SEED), "bundled seed")
    }

    pub fn len(&self) -> usize {
        self.loaded
    }

    pub fn is_empty(&self) -> bool {
        self.loaded == 0
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// Classify a hostname.
    ///
    /// `example.com` and `a.b.example.com` both match a rule for `example.com`.
    /// The most specific matching rule wins.
    pub fn classify(&self, host: &str) -> Category {
        if self.rules.is_empty() {
            return Category::Unknown;
        }
        let host = normalise(host);
        if host.is_empty() {
            return Category::Unknown;
        }

        // Walk the labels from most specific to least.
        let mut candidate = host.as_str();
        loop {
            if let Some(category) = self.rules.get(candidate) {
                return *category;
            }
            match candidate.split_once('.') {
                Some((_, rest)) if rest.contains('.') => candidate = rest,
                _ => return Category::Unknown,
            }
        }
    }

    /// Whether a host should be flagged in the UI.
    pub fn is_flagged(&self, host: &str) -> bool {
        self.classify(host).is_flagged()
    }
}

/// Lowercase, strip a trailing dot, strip a leading `www.` so `www.example.com`
/// and `example.com` agree. `www.` is safe to strip because no real list
/// distinguishes them in a way that matters here.
fn normalise(domain: &str) -> String {
    let mut host = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(stripped) = host.strip_prefix("www.") {
        host = stripped.to_string();
    }
    host
}

/// Parse a simple `domain,category` list, the format of [`CATEGORY_SEED`].
pub fn parse_seed(text: &str) -> Vec<Rule> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (domain, category) = match line.split_once(',') {
            Some((d, c)) => (d.trim(), Category::parse(c)),
            None => (line, Category::Tracker),
        };
        if domain.contains('.') && !domain.contains(' ') {
            out.push(Rule {
                domain: domain.to_string(),
                category,
            });
        }
    }
    out
}

/// Parse a hosts-format blocklist: `0.0.0.0 domain`, `127.0.0.1 domain`, or a
/// bare `domain`.
pub fn parse_blocklist(text: &str, category: Category) -> Vec<Rule> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        let domain = match line.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["0.0.0.0", rest @ ..] => rest.join(" "),
            ["127.0.0.1", rest @ ..] => rest.join(" "),
            [single] => (*single).to_string(),
            _ => continue,
        };
        // OISD and similar lists write a bare domain and a leading `*.` for
        // "this domain and its subdomains". Since matching already walks parent
        // labels, `*.example.com` is exactly the rule `example.com`.
        let domain = domain.trim().trim_start_matches("*.");
        // Skip anything that is not a plain domain: a wildcard in the middle
        // or a path cannot be represented as a domain-level verdict.
        if domain.is_empty()
            || domain.contains(' ')
            || domain.contains('/')
            || domain.contains('*')
            || domain == "localhost"
            || !domain.contains('.')
        {
            continue;
        }
        out.push(Rule {
            domain: normalise(domain),
            category,
        });
    }
    out
}

/// Where downloaded lists live for this user.
pub fn lists_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("tattletale").join("lists")
}

/// The bundled seed list.
///
/// Hand-written and deliberately small. Every entry here is a domain whose
/// primary business is advertising, analytics, or cross-site tracking, and each
/// is stable enough that citing it in a screenshot will not embarrass the user.
/// This is the list that makes the tool useful offline; third-party lists are
/// downloaded on demand rather than vendored, so their licences stay out of
/// this repository and the binary.
const CATEGORY_SEED: &str = "\
# --- advertising exchanges and networks ---
doubleclick.net,ads
googlesyndication.com,ads
googleadservices.com,ads
adnxs.com,ads
adsrvr.org,ads
rubiconproject.com,ads
pubmatic.com,ads
openx.net,ads
casalemedia.com,ads
criteo.com,ads
criteo.net,ads
taboola.com,ads
outbrain.com,ads
media.net,ads
smartadserver.com,ads
adform.net,ads
yieldmo.com,ads
sharethrough.com,ads
teads.tv,ads
spotxchange.com,ads
appnexus.com,ads
indexww.com,ads
33across.com,ads
amazon-adsystem.com,ads
moatads.com,ads
serving-sys.com,ads
adcolony.com,ads
unityads.unity3d.com,ads
applovin.com,ads
ironsrc.com,ads
chartboost.com,ads
vungle.com,ads
inmobi.com,ads
mopub.com,ads

# --- analytics and measurement ---
google-analytics.com,analytics
googletagmanager.com,analytics
scorecardresearch.com,analytics
quantserve.com,analytics
quantcount.com,analytics
imrworldwide.com,analytics
nielsen.com,analytics
comscore.com,analytics
mixpanel.com,analytics
amplitude.com,analytics
segment.io,analytics
segment.com,analytics
heapanalytics.com,analytics
fullstory.com,analytics
hotjar.com,analytics
hotjar.io,analytics
mouseflow.com,analytics
crazyegg.com,analytics
optimizely.com,analytics
newrelic.com,analytics
nr-data.net,analytics
sentry.io,analytics
bugsnag.com,analytics
datadoghq.com,analytics
kissmetrics.com,analytics
chartbeat.com,analytics
parsely.com,analytics
statcounter.com,analytics
clicky.com,analytics
plausible.io,analytics
matomo.cloud,analytics

# --- cross-site tracking and identity ---
demdex.net,tracker
omtrdc.net,tracker
everesttech.net,tracker
krxd.net,tracker
bluekai.com,tracker
exelator.com,tracker
rlcdn.com,tracker
agkn.com,tracker
tapad.com,tracker
liadm.com,tracker
adsymptotic.com,tracker
tidaltv.com,tracker
zemanta.com,tracker
turn.com,tracker
mathtag.com,tracker
simpli.fi,tracker
crwdcntrl.net,tracker
bidswitch.net,tracker
liveramp.com,tracker
id5-sync.com,tracker
thetradedesk.com,tracker
adsrvr.com,tracker
sitescout.com,tracker
yieldlab.net,tracker
smartclip.net,tracker

# --- social and platform tracking beacons ---
connect.facebook.net,tracker
facebook.net,tracker
fbcdn.net,tracker
analytics.twitter.com,tracker
t.co,analytics
ads.linkedin.com,tracker
snap.licdn.com,tracker
px.ads.linkedin.com,tracker
ads.pinterest.com,tracker
ct.pinterest.com,tracker
ads.tiktok.com,tracker
analytics.tiktok.com,tracker

# --- session replay and fingerprinting ---
mouseflow.io,tracker
inspectlet.com,tracker
smartlook.com,tracker
luckyorange.com,tracker
sessioncam.com,tracker
decibelinsight.net,tracker
contentsquare.net,tracker
clarity.ms,analytics
";

/// A public blocklist the user can pull on demand.
///
/// These are **not** vendored into the repository or the binary. Their licences
/// (CC BY-SA, GPL-family) would otherwise attach to this project's MIT source,
/// and the lists are large enough that shipping them would be rude anyway.
/// Downloading them into the user's own data directory keeps the licence
/// obligations with the user, who is the one receiving the data.
#[derive(Debug, Clone, Copy)]
pub struct Source {
    pub name: &'static str,
    pub url: &'static str,
    /// Recorded in `meta.txt` next to the list, so provenance is never a
    /// mystery when someone asks where a red chip came from.
    pub licence: &'static str,
}

/// The lists `tattle lists update` can fetch.
pub const SOURCES: &[Source] = &[
    Source {
        name: "oisd-small",
        url: "https://small.oisd.nl/domainswild",
        licence: "CC BY-SA 4.0, oisd.nl",
    },
    Source {
        name: "easylist-ads",
        url: "https://easylist.to/easylist/easylist.txt",
        licence: "CC BY-SA 3.0 / GPLv3, EasyList",
    },
];

/// Download one list and write it as a plain domain-per-line file.
///
/// Parsing happens here rather than at read time so a corrupt or hostile
/// download is rejected before it can reach the classifier, and so the stored
/// file is small.
pub fn download(source: &Source, dir: &Path) -> anyhow::Result<usize> {
    let body = http_get(source.url)?;
    let rules = if source.name.starts_with("easylist") {
        parse_adblock(&body)
    } else {
        parse_blocklist(&body, Category::Tracker)
    };

    if rules.len() < 100 {
        anyhow::bail!(
            "only {} rules parsed; the list format may have changed",
            rules.len()
        );
    }

    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.txt", source.name));
    let mut out = String::with_capacity(rules.len() * 24);
    out.push_str(&format!(
        "# {}\n# {}\n# {}\n",
        source.name, source.url, source.licence
    ));
    for rule in &rules {
        out.push_str(&rule.domain);
        out.push('\n');
    }
    std::fs::write(&path, out)?;

    // Provenance, alongside the data it describes.
    let meta = dir.join(format!("{}.meta", source.name));
    std::fs::write(
        meta,
        format!(
            "name={}\nurl={}\nlicence={}\nrules={}\n",
            source.name,
            source.url,
            source.licence,
            rules.len()
        ),
    )?;

    Ok(rules.len())
}

/// Minimal HTTP GET. No redirects beyond one hop, no retries, a hard timeout.
///
/// A tracker-list refresh is a background convenience, not a critical path, so
/// this deliberately avoids pulling in a TLS stack heavier than the binary.
fn http_get(url: &str) -> anyhow::Result<String> {
    let response = ureq::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!("tattletale/", env!("CARGO_PKG_VERSION")))
        .build()
        .get(url)
        .call()?;
    Ok(response.into_string()?)
}

/// Parse EasyList's adblock syntax into plain domains.
///
/// Only the forms that map to a whole domain are kept: `||example.com^`.
/// Element-hiding rules, regex rules and path rules are dropped, because a
/// domain-level verdict cannot honestly represent them.
pub fn parse_adblock(text: &str) -> Vec<Rule> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // `||domain^` is the "block this domain" form.
        let Some(rest) = line.strip_prefix("||") else {
            continue;
        };
        let Some(domain) = rest.split('^').next() else {
            continue;
        };
        if domain.is_empty()
            || domain.contains('*')
            || domain.contains('/')
            || domain.contains('$')
            || !domain.contains('.')
        {
            continue;
        }
        out.push(Rule {
            domain: normalise(domain),
            category: Category::Tracker,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> Classifier {
        Classifier::seed()
    }

    #[test]
    fn a_listed_domain_is_flagged() {
        let c = classifier();
        assert_eq!(c.classify("doubleclick.net"), Category::Ads);
        assert_eq!(c.classify("google-analytics.com"), Category::Analytics);
        assert_eq!(c.classify("scorecardresearch.com"), Category::Analytics);
        assert!(c.is_flagged("doubleclick.net"));
    }

    #[test]
    fn a_subdomain_inherits_its_parent_rule() {
        let c = classifier();
        // This is the common case: the actual request goes to a subdomain.
        assert_eq!(c.classify("stats.g.doubleclick.net"), Category::Ads);
        assert_eq!(c.classify("www.google-analytics.com"), Category::Analytics);
        assert_eq!(c.classify("sentry.io"), Category::Analytics);
        assert_eq!(c.classify("o1234.ingest.sentry.io"), Category::Analytics);
    }

    #[test]
    fn an_unlisted_domain_is_not_flagged() {
        let c = classifier();
        for clean in [
            "github.com",
            "example.com",
            "slack.com",
            "spotify.com",
            "discord.com",
        ] {
            assert_eq!(
                c.classify(clean),
                Category::Unknown,
                "{clean} must not be flagged"
            );
            assert!(!c.is_flagged(clean));
        }
    }

    #[test]
    fn a_lookalike_domain_is_not_flagged() {
        // The test that protects the product from an embarrassing screenshot.
        let c = classifier();
        for lookalike in [
            "notdoubleclick.net",
            "doubleclick.net.evil.com",
            "mygoogle-analytics.com",
            "facebook.net.example.org",
        ] {
            assert!(
                !c.is_flagged(lookalike),
                "{lookalike} merely resembles a listed domain and must not be flagged"
            );
        }
    }

    #[test]
    fn matching_is_case_and_dot_insensitive() {
        let c = classifier();
        assert_eq!(c.classify("DOUBLECLICK.NET"), Category::Ads);
        assert_eq!(c.classify("DoubleClick.Net."), Category::Ads);
        assert_eq!(c.classify("www.DoubleClick.net"), Category::Ads);
    }

    #[test]
    fn the_most_specific_rule_wins() {
        let c = Classifier::from_rules(
            vec![
                Rule {
                    domain: "example.com".into(),
                    category: Category::Ads,
                },
                Rule {
                    domain: "safe.example.com".into(),
                    category: Category::Clean,
                },
            ],
            "test",
        );
        assert_eq!(c.classify("ads.example.com"), Category::Ads);
        assert_eq!(c.classify("safe.example.com"), Category::Clean);
    }

    #[test]
    fn an_empty_classifier_flags_nothing() {
        let c = Classifier::empty();
        assert!(c.is_empty());
        assert_eq!(c.classify("doubleclick.net"), Category::Unknown);
        assert!(!c.is_flagged("doubleclick.net"));
    }

    #[test]
    fn handles_empty_and_malformed_input() {
        let c = classifier();
        assert_eq!(c.classify(""), Category::Unknown);
        assert_eq!(c.classify("."), Category::Unknown);
        assert_eq!(c.classify("localhost"), Category::Unknown);
        assert_eq!(c.classify("   "), Category::Unknown);
    }

    #[test]
    fn seed_parsing_skips_comments_and_blank_lines() {
        let rules = parse_seed("# comment\n\ndoubleclick.net,ads\nexample.org\n");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].category, Category::Ads);
        assert_eq!(
            rules[1].category,
            Category::Tracker,
            "a bare line defaults to tracker"
        );
    }

    #[test]
    fn blocklist_parsing_handles_hosts_format() {
        let text = "\
# blocklist
0.0.0.0 tracker.example.com
127.0.0.1 ads.example.org
bare.example.net
! comment
0.0.0.0 localhost
";
        let rules = parse_blocklist(text, Category::Tracker);
        assert_eq!(rules.len(), 3, "localhost and comments are skipped");
        assert_eq!(rules[0].domain, "tracker.example.com");
        assert_eq!(rules[2].domain, "bare.example.net");
    }

    #[test]
    fn oisd_wildcard_lines_become_domain_rules() {
        // OISD writes "*.example.com" for "this domain and its subdomains".
        let text = "*.tracker.example\nplain.example.net\n# comment\n";
        let rules = parse_blocklist(text, Category::Tracker);
        assert_eq!(rules.len(), 2, "the wildcard line must survive: {rules:?}");
        assert_eq!(rules[0].domain, "tracker.example");
        assert_eq!(rules[1].domain, "plain.example.net");
    }

    #[test]
    fn a_mid_domain_wildcard_is_rejected() {
        // "ads.*.example.com" cannot be honestly represented as a domain rule.
        let rules = parse_blocklist("ads.*.example.com\n", Category::Tracker);
        assert!(rules.is_empty());
    }

    #[test]
    fn the_seed_list_is_not_trivial() {
        let c = classifier();
        assert!(
            c.len() > 100,
            "a seed list of {} rules is not worth bundling",
            c.len()
        );
    }

    #[test]
    fn every_seed_rule_is_a_plausible_domain() {
        for rule in parse_seed(CATEGORY_SEED) {
            assert!(rule.domain.contains('.'), "{} is not a domain", rule.domain);
            assert!(
                !rule.domain.contains(' '),
                "{} contains a space",
                rule.domain
            );
            assert_eq!(
                rule.domain,
                rule.domain.to_ascii_lowercase(),
                "{} must be lowercase",
                rule.domain
            );
            assert!(
                rule.category.is_flagged(),
                "{} is in the seed but has category {}",
                rule.domain,
                rule.category
            );
        }
    }
}
