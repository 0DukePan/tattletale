//! Plain data types shared by the collector, the store and the UI.
//!
//! Nothing here touches the operating system or the database. Keeping the
//! vocabulary in one module is what lets the attribution tests run without a
//! network stack and the report tests run without a database.

use std::fmt;

/// How sure we are that a domain belongs to a connection.
///
/// The ordering matters: `Exact` is best, `Unknown` is worst. Comparisons are
/// used when a connection gathers several candidate domains and we keep the
/// strongest one for the headline.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Tier {
    /// No candidate domain at all. We show the address and admit we do not know.
    Unknown = 0,
    /// More than one plausible candidate, or a shared address.
    Probable = 1,
    /// A single candidate inside the correlation window.
    High = 2,
    /// The DNS event carried the requesting process id (ETW, admin only).
    Exact = 3,
}

impl Tier {
    /// Value stored in SQLite. Never renumber without a migration.
    pub fn as_int(self) -> i64 {
        self as i64
    }

    pub fn from_int(value: i64) -> Self {
        match value {
            3 => Tier::Exact,
            2 => Tier::High,
            1 => Tier::Probable,
            _ => Tier::Unknown,
        }
    }

    /// The glyph shown in the TUI and the receipt legend.
    pub fn glyph(self) -> &'static str {
        match self {
            Tier::Exact => "●●●",
            Tier::High => "●●○",
            Tier::Probable => "●○○",
            Tier::Unknown => "○○○",
        }
    }

    /// Short human label used in the report.
    pub fn label(self) -> &'static str {
        match self {
            Tier::Exact => "exact",
            Tier::High => "high",
            Tier::Probable => "probable",
            Tier::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Transport protocol of a connection. QUIC is UDP, so it lands in [`Proto::Udp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" => Some(Proto::Tcp),
            "udp" => Some(Proto::Udp),
            _ => None,
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a tracker list says about a domain. `Clean` is not "safe", it is
/// "no list flagged this", which the report states explicitly.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Category {
    Clean,
    Unknown,
    Analytics,
    Ads,
    Tracker,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Clean => "clean",
            Category::Unknown => "unknown",
            Category::Analytics => "analytics",
            Category::Ads => "ads",
            Category::Tracker => "tracker",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "clean" => Category::Clean,
            "analytics" => Category::Analytics,
            "ads" => Category::Ads,
            "tracker" => Category::Tracker,
            _ => Category::Unknown,
        }
    }

    /// Whether this category earns the warning glyph in the UI.
    pub fn is_flagged(self) -> bool {
        matches!(
            self,
            Category::Tracker | Category::Ads | Category::Analytics
        )
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A process that opened connections, normalised to one identity per image path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct App {
    /// Surrogate key from the store; `0` for a not-yet-persisted record.
    pub id: i64,
    /// Full image path, e.g. `C:\Program Files\Google\Chrome\Application\chrome.exe`.
    pub path: String,
    /// File name as the OS reports it, e.g. `chrome.exe`.
    pub name: String,
    /// Presentation name, e.g. `Chrome`. Falls back to `name`.
    pub friendly: String,
}

impl App {
    pub fn new(
        path: impl Into<String>,
        name: impl Into<String>,
        friendly: impl Into<String>,
    ) -> Self {
        Self {
            id: 0,
            path: path.into(),
            name: name.into(),
            friendly: friendly.into(),
        }
    }

    /// The label the UI shows. Never empty, never a bare path.
    pub fn display(&self) -> &str {
        if self.friendly.is_empty() {
            &self.name
        } else {
            &self.friendly
        }
    }
}

/// The identity of a connection: who, where, how. Re-seeing the same tuple
/// means the same logical connection, not a new one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ConnKey {
    pub app_id: i64,
    pub ip: String,
    pub port: u16,
    pub proto: Proto,
}

/// A connection as stored, with the counters the receipt needs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Connection {
    pub id: i64,
    pub app_id: i64,
    pub ip: String,
    pub port: u16,
    pub proto: Proto,
    /// Unix seconds of the first poll that saw this tuple.
    pub first_at: i64,
    /// Unix seconds of the most recent poll that saw this tuple.
    pub last_at: i64,
    /// How many times the tuple disappeared and came back. This is the number
    /// the receipt calls "connections".
    pub opens: u32,
}

/// A name/address pair observed in the system DNS cache.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DnsRecord {
    /// The queried name, e.g. `a.b.example.com`.
    pub host: String,
    /// The answer, e.g. `142.250.75.238`.
    pub ip: String,
    /// DNS record type: 1 = A, 28 = AAAA, 12 = PTR.
    pub rtype: u16,
    /// Which section of the answer the record came from.
    pub section: DnsSection,
    /// Remaining lifetime the resolver reported. An increase between polls is
    /// the only signal that a name was resolved again, which is how the tracker
    /// keeps first-seen times honest.
    pub ttl: u32,
    /// When the resolver first produced this pair, in unix seconds.
    pub first_seen: i64,
    pub last_seen: i64,
    /// Where the observation came from, so the UI can disclose it.
    pub source: DnsSource,
}

impl DnsRecord {
    /// Only address records can be joined against a connection's address.
    pub fn is_address(&self) -> bool {
        matches!(self.rtype, 1 | 28)
    }
}

/// DNS answers arrive in sections that are not equally trustworthy: a name in
/// the answer section belongs to the query, a name in the additional section
/// may have been volunteered for an unrelated reason.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum DnsSection {
    /// Reverse lookups. Useful as a hint, never as attribution.
    Ptr = 0,
    Additional = 1,
    Answer = 2,
}

impl DnsSection {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsSection::Ptr => "ptr",
            DnsSection::Additional => "additional",
            DnsSection::Answer => "answer",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "answer" => DnsSection::Answer,
            "additional" => DnsSection::Additional,
            _ => DnsSection::Ptr,
        }
    }
}

/// Which mechanism produced a DNS observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DnsSource {
    /// `ipconfig /displaydns`. No process id. Standard mode.
    Ipconfig,
    /// Event Tracing for Windows. Carries the requesting pid. Admin only.
    Etw,
    /// A recorded fixture replayed by `tattle replay`.
    Replay,
}

impl DnsSource {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsSource::Ipconfig => "ipconfig",
            DnsSource::Etw => "etw",
            DnsSource::Replay => "replay",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "etw" => DnsSource::Etw,
            "replay" => DnsSource::Replay,
            _ => DnsSource::Ipconfig,
        }
    }
}

/// One candidate domain for one connection, as produced by the attribution
/// engine and stored for the UI to explain itself later.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attribution {
    pub conn_id: i64,
    pub host: String,
    pub site: String,
    pub tier: Tier,
    /// Why this candidate won: `single-candidate`, `shared-ip`, `stale-entry`, …
    pub method: String,
    pub at: i64,
}

/// A single observation from one polling tick, before it is merged into the
/// store. This is the only shape the collector and the replay reader produce.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sample {
    pub at: i64,
    pub app_path: String,
    pub app_name: String,
    pub ip: String,
    pub port: u16,
    pub proto: Proto,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_roundtrips_through_int() {
        for tier in [Tier::Unknown, Tier::Probable, Tier::High, Tier::Exact] {
            assert_eq!(Tier::from_int(tier.as_int()), tier);
        }
        assert_eq!(
            Tier::from_int(99),
            Tier::Unknown,
            "unknown values must degrade safely"
        );
    }

    #[test]
    fn tier_orders_from_unknown_to_exact() {
        assert!(Tier::Exact > Tier::High);
        assert!(Tier::High > Tier::Probable);
        assert!(Tier::Probable > Tier::Unknown);
    }

    #[test]
    fn category_flags_only_surveillance_categories() {
        assert!(Category::Tracker.is_flagged());
        assert!(Category::Ads.is_flagged());
        assert!(Category::Analytics.is_flagged());
        assert!(!Category::Clean.is_flagged());
        assert!(!Category::Unknown.is_flagged());
    }

    #[test]
    fn proto_parsing_is_case_insensitive_and_rejects_junk() {
        assert_eq!(Proto::parse("TCP"), Some(Proto::Tcp));
        assert_eq!(Proto::parse(" udp "), Some(Proto::Udp));
        assert_eq!(Proto::parse("sctp"), None);
    }

    #[test]
    fn app_display_falls_back_to_binary_name() {
        let app = App::new("C:\\x\\chrome.exe", "chrome.exe", "");
        assert_eq!(app.display(), "chrome.exe");
        let app = App::new("C:\\x\\chrome.exe", "chrome.exe", "Chrome");
        assert_eq!(app.display(), "Chrome");
    }

    #[test]
    fn only_address_records_join() {
        let base = DnsRecord {
            host: "example.com".into(),
            ip: "93.184.216.34".into(),
            rtype: 1,
            section: DnsSection::Answer,
            ttl: 60,
            first_seen: 0,
            last_seen: 0,
            source: DnsSource::Ipconfig,
        };
        assert!(base.is_address());
        assert!(!DnsRecord {
            rtype: 12,
            ..base.clone()
        }
        .is_address());
    }
}
