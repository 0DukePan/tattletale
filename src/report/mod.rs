//! HTML receipt rendering.
//!
//! The receipt is the product's only distribution mechanism: it is what a user
//! screenshots and posts. It is therefore a *pure function* of a report model,
//! with no database access and no clock of its own, so the golden tests can
//! pin both the data and the time.
//!
//! Constraints that shape the output:
//!
//! * One file. No external CSS, JS, fonts, or images. It must open from a USB
//!   stick with no network.
//! * Print-friendly. A receipt that cannot be printed is not a receipt.
//! * Escaped everywhere. Hostnames come from the network and are untrusted;
//!   a domain containing `<script>` must render as text.
//! * Honest. Every number has a legend, and the footer states what the tool
//!   cannot see.

use std::fmt::Write as _;

use crate::model::{Category, Tier};
use crate::store::{AppRow, SiteRow, Totals};

pub mod build;

/// The bundled stylesheet. Inlined so the receipt stays a single file.
const STYLESHEET: &str = include_str!("receipt.css");

/// Everything the receipt needs, already computed.
#[derive(Debug, Clone)]
pub struct ReportModel {
    /// When the receipt was generated, unix seconds.
    pub generated_at: i64,
    /// Start of the window covered, unix seconds.
    pub since: i64,
    /// Machine label, e.g. the computer name. Never a username.
    pub machine: String,
    pub totals: Totals,
    pub apps: Vec<AppRow>,
    pub sites: Vec<SiteRow>,
    /// Connections that happened while the user was asleep (00:00-07:00 local).
    pub night: NightSummary,
    /// Hourly connection counts, 24 entries, for the inline chart.
    pub hourly: Vec<u64>,
    /// Caveats that must be shown, e.g. DoH detected.
    pub caveats: Vec<String>,
    /// Fraction of connections that carry a domain name, 0.0 to 1.0.
    pub coverage: f64,
    /// How many connections could be named.
    pub named: u64,
    /// True when the data is a synthetic demo scene. The receipt says so in
    /// large letters: a fabricated screenshot must never pass as real.
    pub synthetic: bool,
}

/// What happened while the machine was supposed to be idle.
#[derive(Debug, Clone, Default)]
pub struct NightSummary {
    pub connections: u64,
    pub apps: Vec<String>,
}

impl ReportModel {
    /// The shareable number: what fraction of traffic hit a flagged domain.
    pub fn tracker_share(&self) -> f64 {
        if self.totals.connections == 0 {
            return 0.0;
        }
        self.totals.tracked as f64 / self.totals.connections as f64 * 100.0
    }
}

/// Render the receipt.
pub fn render(model: &ReportModel) -> String {
    let mut out = String::with_capacity(16 * 1024);

    out.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    let _ = writeln!(
        out,
        "<title>tattletale receipt - {}</title>",
        esc(&model.machine)
    );
    out.push_str("<style>\n");
    out.push_str(STYLESHEET);
    out.push_str("</style>\n</head>\n<body>\n<main class=\"receipt\">\n");

    if model.synthetic {
        out.push_str("<div class=\"synthetic\">Synthetic demo data &mdash; not a record of this machine</div>\n");
    }
    header(&mut out, model);
    headline(&mut out, model);
    night(&mut out, model);
    chart(&mut out, model);
    talkers(&mut out, model);
    app_cards(&mut out, model);
    footer(&mut out, model);

    out.push_str("</main>\n</body>\n</html>\n");
    out
}

fn header(out: &mut String, model: &ReportModel) {
    out.push_str("<header class=\"masthead\">\n");
    out.push_str("<div class=\"brand\">tattletale</div>\n");
    out.push_str("<div class=\"meta\">\n");
    let _ = writeln!(
        out,
        "<span class=\"machine\">{}</span>",
        esc(&model.machine)
    );
    let _ = writeln!(
        out,
        "<span class=\"window\">{}</span>",
        esc(&window_label(model.since, model.generated_at))
    );
    out.push_str("</div>\n</header>\n");
}

fn headline(out: &mut String, model: &ReportModel) {
    out.push_str("<section class=\"headline\">\n");
    stat(out, &model.totals.connections.to_string(), "connections");
    stat(out, &model.totals.apps.to_string(), "apps");
    stat(out, &model.totals.sites.to_string(), "sites");
    let share = model.tracker_share();
    let class = if share >= 10.0 {
        "stat flagged"
    } else {
        "stat"
    };
    let _ = writeln!(
        out,
        "<div class=\"{class}\"><b>{share:.0}%</b><span>flagged</span></div>"
    );
    // Coverage sits next to the headline numbers on purpose: a reader must see
    // how much of the traffic was explained before trusting the rest.
    if model.named > 0 {
        let coverage = model.coverage * 100.0;
        let class = if coverage < 50.0 {
            "stat partial"
        } else {
            "stat"
        };
        let _ = writeln!(
            out,
            "<div class=\"{class}\" title=\"connections that carry a domain name\"><b>{coverage:.0}%</b><span>named</span></div>"
        );
    }
    out.push_str("</section>\n");
}

fn stat(out: &mut String, value: &str, label: &str) {
    let _ = writeln!(
        out,
        "<div class=\"stat\"><b>{}</b><span>{}</span></div>",
        esc(value),
        esc(label)
    );
}

fn night(out: &mut String, model: &ReportModel) {
    if model.night.connections == 0 {
        return;
    }
    out.push_str("<section class=\"night\">\n<h2>While you were asleep</h2>\n");
    let _ = writeln!(
        out,
        "<p><b>{}</b> connections between 00:00 and 07:00, from {}.</p>",
        model.night.connections,
        if model.night.apps.is_empty() {
            "no application".to_string()
        } else {
            esc(&model.night.apps.join(", "))
        }
    );
    out.push_str("</section>\n");
}

fn chart(out: &mut String, model: &ReportModel) {
    if model.hourly.is_empty() {
        return;
    }
    let peak = model.hourly.iter().copied().max().unwrap_or(1).max(1) as f64;
    let width = 12.0;
    let gap = 2.0;
    let height = 48.0;
    let total_width = (width + gap) * model.hourly.len() as f64;

    out.push_str("<section class=\"chart\">\n<h2>By hour</h2>\n");
    let _ = writeln!(
        out,
        "<svg viewBox=\"0 0 {total_width:.0} {height:.0}\" role=\"img\" aria-label=\"connections per hour\">"
    );

    for (hour, count) in model.hourly.iter().enumerate() {
        let bar = (*count as f64 / peak) * height;
        let x = hour as f64 * (width + gap);
        let y = height - bar;
        // The night band is highlighted: that is the part that surprises people.
        let class = if hour < 7 { "bar night" } else { "bar" };
        let _ = writeln!(
            out,
            "<rect class=\"{class}\" x=\"{x:.1}\" y=\"{y:.1}\" width=\"{width:.0}\" height=\"{bar:.1}\"><title>{hour:02}:00 - {count}</title></rect>"
        );
    }

    out.push_str("</svg>\n");
    out.push_str("<div class=\"axis\"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div>\n");
    out.push_str("</section>\n");
}

fn talkers(out: &mut String, model: &ReportModel) {
    if model.apps.is_empty() {
        out.push_str("<section class=\"empty\">\n");
        out.push_str("<h2>Nothing recorded yet</h2>\n");
        out.push_str(
            "<p>Run <code>tattle</code> to start watching, then build the receipt again.</p>\n",
        );
        out.push_str("</section>\n");
        return;
    }

    out.push_str("<section class=\"talkers\">\n<h2>Top talkers</h2>\n<table>\n");
    out.push_str("<thead><tr><th>app</th><th class=\"num\">conns</th><th class=\"num\">sites</th><th class=\"num\">flagged</th></tr></thead>\n<tbody>\n");
    for row in model.apps.iter().take(12) {
        let flagged = if row.tracked > 0 {
            " class=\"flagged\""
        } else {
            ""
        };
        let _ = writeln!(
            out,
            "<tr><td><span class=\"app\">{}</span><span class=\"tier\" title=\"{}\">{}</span></td><td class=\"num\">{}</td><td class=\"num\">{}</td><td class=\"num\"{flagged}>{}</td></tr>",
            esc(row.app.display()),
            esc(row.tier.label()),
            row.tier.glyph(),
            row.connections,
            row.sites,
            row.tracked,
        );
    }
    out.push_str("</tbody>\n</table>\n</section>\n");
}

fn app_cards(out: &mut String, model: &ReportModel) {
    if model.apps.is_empty() {
        return;
    }
    out.push_str("<section class=\"cards\">\n<h2>By app</h2>\n<div class=\"grid\">\n");

    for row in model.apps.iter().take(6) {
        out.push_str("<article class=\"card\">\n");
        let _ = writeln!(
            out,
            "<h3>{}</h3><div class=\"sub\">{} / {}</div>",
            esc(row.app.display()),
            plural(row.connections as usize, "connection"),
            plural(row.sites as usize, "site")
        );
        if row.top_sites.is_empty() {
            out.push_str("<p class=\"muted\">No domain resolved for these connections.</p>\n");
        } else {
            out.push_str("<ul class=\"sites\">\n");
            for site in row.top_sites.iter() {
                let chip = category_chip(site.category);
                let _ = writeln!(
                    out,
                    "<li><span class=\"site\">{}</span>{}<span class=\"n\">{}</span></li>",
                    esc(&site.site),
                    chip,
                    site.connections
                );
            }
            out.push_str("</ul>\n");
        }
        out.push_str("</article>\n");
    }

    out.push_str("</div>\n</section>\n");
}

/// Pluralise a noun. Cheap grammar that stops "1 connections" reaching a
/// screenshot, which is where it would be seen a hundred times.
fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

fn category_chip(category: Category) -> String {
    match category {
        Category::Clean | Category::Unknown => String::new(),
        other => format!(
            "<span class=\"chip {}\">{}</span>",
            other.as_str(),
            other.as_str()
        ),
    }
}

fn footer(out: &mut String, model: &ReportModel) {
    out.push_str("<footer>\n");
    out.push_str("<div class=\"legend\">\n");
    out.push_str("<span><b>confidence</b></span>");
    for tier in [Tier::Exact, Tier::High, Tier::Probable, Tier::Unknown] {
        let _ = writeln!(
            out,
            "<span><span class=\"tier\">{}</span> {}</span>",
            tier.glyph(),
            esc(&tier_explanation(tier))
        );
    }
    out.push_str("</div>\n");

    for caveat in &model.caveats {
        let _ = writeln!(out, "<p class=\"caveat\">{}</p>", esc(caveat));
    }

    let _ = writeln!(
        out,
        "<p class=\"privacy\">Nothing in this report left this machine. Generated by tattletale {} at {}.</p>",
        esc(crate::VERSION),
        esc(&clock(model.generated_at))
    );
    out.push_str("</footer>\n");
}

fn tier_explanation(tier: Tier) -> String {
    match tier {
        Tier::Exact => "the name carried the requesting process".to_string(),
        Tier::High => "one name resolved just before the connection".to_string(),
        Tier::Probable => "several names, or a shared address".to_string(),
        Tier::Unknown => "no name resolved; the address is shown as-is".to_string(),
    }
}

fn window_label(since: i64, until: i64) -> String {
    let hours = ((until - since).max(0)) as f64 / 3600.0;
    if hours >= 47.0 {
        format!("last {:.0} days", hours / 24.0)
    } else if hours >= 1.5 {
        format!("last {:.0} hours", hours)
    } else {
        "last hour".to_string()
    }
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM` in UTC.
///
/// No timezone database: a receipt that says "04:12" without a zone would be
/// worse than one that says `04:12 UTC`.
pub fn clock(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// Howard Hinnant's days-to-civil algorithm. Kept here rather than pulling in
/// a date library for one formatted field.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Escape text for HTML.
///
/// Hostnames come from the network and are attacker-controlled, so this is
/// applied to every value that reaches the output, without exception.
pub fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_hostile_hostnames() {
        let hostile = r#"<script>alert("x")</script>"#;
        let escaped = esc(hostile);
        assert!(!escaped.contains("<script>"));
        assert!(!escaped.contains('"'));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    #[test]
    fn escapes_ampersands() {
        assert_eq!(esc("a&b<c"), "a&amp;b&lt;c");
    }

    #[test]
    fn window_label_reads_naturally() {
        assert_eq!(window_label(0, 3600), "last hour");
        assert_eq!(window_label(0, 6 * 3600), "last 6 hours");
        assert_eq!(window_label(0, 48 * 3600), "last 2 days");
    }

    #[test]
    fn tracker_share_is_bounded_and_zero_safe() {
        let model = ReportModel {
            generated_at: 0,
            since: 0,
            machine: "pc".into(),
            totals: Totals::default(),
            apps: vec![],
            sites: vec![],
            night: NightSummary::default(),
            hourly: vec![],
            caveats: vec![],
            coverage: 0.0,
            named: 0,
            synthetic: false,
        };
        assert_eq!(
            model.tracker_share(),
            0.0,
            "no traffic must not divide by zero"
        );
    }

    #[test]
    fn clock_formats_a_known_instant() {
        // 2026-11-12T18:53:16Z, the moment this was written.
        assert_eq!(clock(1_794_509_596), "2026-11-12 18:53 UTC");
        assert_eq!(clock(0), "1970-01-01 00:00 UTC");
    }

    #[test]
    fn clock_handles_leap_years() {
        // 2024-02-29T12:00:00Z
        assert_eq!(clock(1_709_208_000), "2024-02-29 12:00 UTC");
    }
}
