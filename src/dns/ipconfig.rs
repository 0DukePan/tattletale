//! Parser for `ipconfig /displaydns`.
//!
//! The output is localised and column-aligned with runs of dots, so the parser
//! never depends on label text or on column positions. It recognises fields by
//! their *value* shape:
//!
//! * `Record Type : 1` â€” a number, one of the few we care about
//! * `A (Host) Record : 41.201.164.20` â€” the field name is followed by an address
//! * `Record Name : <name>` â€” the right-hand side is a hostname
//!
//! That makes the parser survive a machine set to French or Arabic, where the
//! labels change but the values do not. Fixtures for three locales live in
//! `fixtures/` and are exercised by `tests/dns_ipconfig.rs`.

use std::net::IpAddr;

use crate::dns::{is_local_name, TYPE_AAAA, TYPE_CNAME, TYPE_PTR};
use crate::model::{DnsRecord, DnsSection, DnsSource};

/// One parsed block from the cache, before it becomes a [`DnsRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub host: String,
    pub rtype: u16,
    pub ttl: u32,
    pub section: DnsSection,
    /// The address this record holds, for A and AAAA records.
    pub address: Option<String>,
    /// The canonical name, for CNAME records.
    pub cname: Option<String>,
    /// The name this record points at, for PTR records.
    pub ptr: Option<String>,
    /// Whether the TTL field has been filled in yet.
    ttl_set: bool,
}

impl Entry {
    fn new(host: String) -> Self {
        Self {
            host,
            rtype: 0,
            ttl: 0,
            section: DnsSection::Answer,
            address: None,
            cname: None,
            ptr: None,
            ttl_set: false,
        }
    }
}

/// Parse a full `ipconfig /displaydns` dump.
///
/// `now` is the unix time of the dump: the cache does not report when a name
/// was resolved, so each record starts its life at the moment we first see it.
/// [`crate::dns::cache`] keeps the earliest sighting across dumps, which is
/// what makes the correlation window meaningful.
pub fn parse(text: &str) -> Vec<DnsRecord> {
    parse_entries(text)
        .into_iter()
        .flat_map(|entry| to_records(entry, 0))
        .collect()
}

/// Parse with an explicit injection time, used by tests and by replay.
pub fn parse_at(text: &str, now: i64) -> Vec<DnsRecord> {
    parse_entries(text)
        .into_iter()
        .flat_map(|entry| to_records(entry, now))
        .collect()
}

/// The block-level parse, exposed so the tests can assert on raw entries
/// without the record-type filtering that [`parse`] applies.
pub fn parse_entries(text: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut current: Option<Entry> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            // A blank line ends a block. `ipconfig` separates records with two
            // blank lines; the second one is simply ignored.
            if let Some(entry) = current.take() {
                if is_complete(&entry) {
                    entries.push(entry);
                }
            }
            continue;
        }

        // The block header is the bare query name above a row of dashes.
        if is_separator(line) {
            continue;
        }

        let Some((label, value)) = split_field(line) else {
            // Not a `Field : value` line. If it looks like a name and we are
            // not inside a block, it is the header line that precedes one.
            if current.is_none() && looks_like_name(line) && !line.contains(':') {
                current = Some(Entry::new(line.trim_end_matches('.').to_string()));
            }
            continue;
        };

        // A new `Record Name` starts a new record inside the same query block
        // (a CNAME chain, or several addresses for one name).
        if is_record_name(&label) {
            let name = value.trim_end_matches('.').to_string();
            if let Some(mut entry) = current.take() {
                if is_complete(&entry) {
                    // The previous record kept the header name; carry it over
                    // only if the block header was missing.
                    if entry.host.is_empty() {
                        entry.host = name.clone();
                    }
                    entries.push(entry);
                }
            }
            let mut entry = Entry::new(name.clone());
            // A block whose header was the query name keeps that as the host;
            // a bare record list uses the record name.
            entry.host = name;
            current = Some(entry);
            continue;
        }

        let Some(entry) = current.as_mut() else {
            continue;
        };

        // Field labels are localised ("Time To Live" in English, "Durée de
        // vie" in French), so the *value shape* decides what a line is, not
        // the label text. The one label that must be recognised by meaning is
        // the TTL, because a bare number is ambiguous: it could be a record
        // type, a TTL, or a data length. Order matters: the address and
        // section checks are unambiguous, so they come first.
        if let Some(ip) = parse_ip(&value) {
            entry.address = Some(ip);
        } else if label.to_ascii_lowercase().contains("section") {
            entry.section = DnsSection::parse(&value);
        } else if is_ttl_label(&label) {
            if let Ok(ttl) = value.parse::<u32>() {
                entry.ttl = ttl;
                entry.ttl_set = true;
            }
        } else if is_type_label(&label) {
            if let Ok(rtype) = value.parse::<u16>() {
                entry.rtype = rtype;
            }
        } else if entry.rtype == TYPE_CNAME || label.to_ascii_lowercase().contains("cname") {
            entry.cname = Some(value.trim_end_matches('.').to_string());
        } else if entry.rtype == TYPE_PTR || label.to_ascii_lowercase().contains("ptr") {
            entry.ptr = Some(value.trim_end_matches('.').to_string());
        }
    }

    if let Some(entry) = current.take() {
        if is_complete(&entry) {
            entries.push(entry);
        }
    }

    entries
}

/// Turn one parsed block into the address records the engine can join on.
///
/// A CNAME block contributes nothing on its own: the chain resolves into a
/// separate A block that carries the address, and that block is what gets
/// joined against a connection.
fn to_records(entry: Entry, now: i64) -> Vec<DnsRecord> {
    let mut out = Vec::new();
    let (Some(address), true) = (entry.address.clone(), matches!(entry.rtype, 1 | TYPE_AAAA))
    else {
        return out;
    };
    if is_local_name(&entry.host) {
        return out;
    }
    out.push(DnsRecord {
        host: entry.host,
        ip: address,
        rtype: entry.rtype,
        section: entry.section,
        ttl: entry.ttl,
        first_seen: now,
        last_seen: now,
        source: DnsSource::Ipconfig,
    });
    out
}

/// A block is complete once it has a type and something to say.
fn is_complete(entry: &Entry) -> bool {
    entry.rtype != 0 && (entry.address.is_some() || entry.cname.is_some() || entry.ptr.is_some())
}

fn is_separator(line: &str) -> bool {
    line.len() >= 4 && line.chars().all(|c| c == '-' || c == '=')
}

fn is_record_name(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    lower.contains("record name") || lower == "name"
}

/// Recognise the TTL field without depending on the English spelling.
///
/// English Windows writes "Time To Live", which contains no "ttl" substring at
/// all — the abbreviation only exists in the docs. Match the words as well as
/// the abbreviation so both forms work.
fn is_ttl_label(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    lower.contains("ttl")
        || lower.contains("time to live")
        || lower.contains("durée de vie")
        || lower.contains("duree de vie")
        || lower.contains("tiempo de vida")
}

fn is_type_label(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    lower.contains("type") || lower.contains("typ")
}

/// Split `Label . . . : value` without trusting the label text.
///
/// The value is everything after the first colon that is followed by a space
/// or is at the end; the label is everything before it, dots and spaces
/// stripped.
fn split_field(line: &str) -> Option<(String, String)> {
    let colon = line.find(':')?;
    let (label, rest) = line.split_at(colon);
    let value = rest[1..].trim().to_string();
    if value.is_empty() {
        return None;
    }
    // A URL-like value contains `:` in the middle; a field label never does.
    if label.contains(':') {
        return None;
    }
    let label = label
        .trim_end_matches('.')
        .trim_end_matches(' ')
        .trim()
        .to_string();
    if label.is_empty() {
        return None;
    }
    Some((label, value))
}

fn parse_ip(value: &str) -> Option<String> {
    // Values can carry a trailing comment in some locales; take the first token.
    let token = value.split_whitespace().next()?;
    token.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

fn looks_like_name(line: &str) -> bool {
    if line.len() > 255 || line.contains(' ') {
        return false;
    }
    line.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && line.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
Windows IP Configuration

    rr8---sn-5abxgpxuxaxjvh-5aby.googlevideo.com
    ----------------------------------------
    Record Name . . . . . : rr8---sn-5abxgpxuxaxjvh-5aby.googlevideo.com
    Record Type . . . . . : 5
    Time To Live  . . . . : 709
    Data Length . . . . . : 8
    Section . . . . . . . : Answer
    CNAME Record  . . . . : rr8.sn-5abxgpxuxaxjvh-5aby.googlevideo.com


    Record Name . . . . . : rr8.sn-5abxgpxuxaxjvh-5aby.googlevideo.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 709
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 41.201.164.20
"#;

    #[test]
    fn parses_a_record_after_a_cname_chain() {
        let records = parse_at(SAMPLE, 1_700_000_000);
        assert_eq!(records.len(), 1, "only the A record carries an address");
        let record = &records[0];
        assert_eq!(record.host, "rr8.sn-5abxgpxuxaxjvh-5aby.googlevideo.com");
        assert_eq!(record.ip, "41.201.164.20");
        assert_eq!(record.rtype, 1);
        assert_eq!(record.section, DnsSection::Answer);
        assert_eq!(record.first_seen, 1_700_000_000);
    }

    #[test]
    fn parses_multiple_addresses_for_one_name() {
        let text = r#"
    example.com
    ----------------------------------------
    Record Name . . . . . : example.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 60
    Section . . . . . . . : Answer
    A (Host) Record . . . : 93.184.216.34

    Record Name . . . . . : example.com
    Record Type . . . . . : 28
    Time To Live  . . . . : 60
    Section . . . . . . . : Answer
    AAAA Record . . . . . : 2606:2800:220:1:248:1893:25c8:1946
"#;
        let records = parse_at(text, 5);
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .any(|r| r.ip == "93.184.216.34" && r.rtype == 1));
        assert!(records.iter().any(|r| r.rtype == TYPE_AAAA));
    }

    #[test]
    fn keeps_the_section_so_additional_answers_rank_lower() {
        let text = r#"
    tracker.example
    ----------------------------------------
    Record Name . . . . . : tracker.example
    Record Type . . . . . : 1
    Time To Live  . . . . : 60
    Section . . . . . . . : Additional
    A (Host) Record . . . : 1.2.3.4
"#;
        let records = parse_at(text, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].section, DnsSection::Additional);
    }

    #[test]
    fn drops_reverse_lookups_and_neighbours() {
        let text = r#"
    202.43.168.192.in-addr.arpa
    ----------------------------------------
    Record Name . . . . . : 202.43.168.192.in-addr.arpa.
    Record Type . . . . . : 1
    Time To Live  . . . . : 60
    Section . . . . . . . : Answer
    A (Host) Record . . . : 8.8.8.8

    printer.local
    ----------------------------------------
    Record Name . . . . . : printer.local
    Record Type . . . . . : 1
    Time To Live  . . . . : 60
    Section . . . . . . . : Answer
    A (Host) Record . . . : 192.168.1.9
"#;
        assert!(
            parse_at(text, 0).is_empty(),
            "local names must not become records"
        );
    }

    #[test]
    fn survives_localised_labels() {
        // French Windows: the field names translate, the values do not.
        let text = r#"
    exemple.fr
    ----------------------------------------
    Nom d'enregistrement  : exemple.fr
    Type d'enregistrement : 1
    DurÃ©e de vie  . . . . : 120
    Section . . . . . . . : RÃ©ponse
    Enregistrement A  . . : 93.184.216.34
"#;
        let records = parse_at(text, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].host, "exemple.fr");
        assert_eq!(records[0].ip, "93.184.216.34");
    }

    #[test]
    fn ignores_cname_and_ptr_records_as_addresses() {
        let text = r#"
    www.example.com
    ----------------------------------------
    Record Name . . . . . : www.example.com
    Record Type . . . . . : 5
    Time To Live  . . . . : 60
    Section . . . . . . . : Answer
    CNAME Record  . . . . : example.com
"#;
        assert!(
            parse_at(text, 0).is_empty(),
            "a CNAME carries no address to join on"
        );
    }

    #[test]
    fn handles_empty_and_garbage_input() {
        assert!(parse("").is_empty());
        assert!(parse("\n\n\n").is_empty());
        assert!(parse("this is not ipconfig output").is_empty());
        assert!(parse("Record Name : \nRecord Type : \n").is_empty());
    }

    #[test]
    fn record_type_is_read_from_the_value_not_the_label() {
        let text = r#"
    example.com
    ----------------------------------------
    Record Name : example.com
    Record Type : 28
    Section : Answer
    Whatever This Label Is : 2606:4700:4700::1111
"#;
        let records = parse_at(text, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rtype, TYPE_AAAA);
        assert_eq!(records[0].ip, "2606:4700:4700::1111");
    }
}
