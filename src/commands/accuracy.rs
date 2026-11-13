//! `tattle bench` — measure how often the attribution is *right*.

use std::io::Write;

use crate::bench;

/// Run the labelled scenarios and print precision, recall and accuracy.
///
/// This exists because every accuracy number this project quoted before was a
/// coverage figure. "85% unnamed" says nothing about whether the other 15% were
/// correct, and those are different questions.
pub fn run(out: &mut dyn Write) -> anyhow::Result<bench::Report> {
    let scenarios = bench::scenarios();
    let report = bench::evaluate(&scenarios);

    writeln!(out, "attribution accuracy")?;
    writeln!(out, "  scenarios        {}", scenarios.len())?;
    writeln!(
        out,
        "  scored           {} connections with a knowable name",
        report.knowable
    )?;
    writeln!(out, "  correctly blank  {}", report.correctly_unknown)?;
    writeln!(out)?;

    writeln!(
        out,
        "  precision        {:.1}%   of the names offered, how many were right",
        report.precision() * 100.0
    )?;
    writeln!(
        out,
        "  recall           {:.1}%   of the names knowable, how many were found",
        report.recall() * 100.0
    )?;
    writeln!(
        out,
        "  accuracy         {:.1}%   of all connections, including correctly blank",
        report.accuracy() * 100.0
    )?;
    writeln!(out)?;

    writeln!(out, "  true positives   {}", report.true_positives)?;
    writeln!(
        out,
        "  false positives  {}   {}",
        report.false_positives,
        if report.false_positives == 0 {
            "none: the tool never named something that was not there"
        } else {
            "REGRESSION"
        }
    )?;
    writeln!(
        out,
        "  false negatives  {}   names that were knowable and were missed",
        report.false_negatives
    )?;
    writeln!(
        out,
        "  wrong but high   {}   {}",
        report.wrong_high,
        if report.wrong_high == 0 {
            "no confident answer was wrong"
        } else {
            "REGRESSION"
        }
    )?;
    writeln!(out)?;

    writeln!(out, "  {:<22} {:>6} {:>6}", "SCENARIO", "HITS", "OF")?;
    for (name, (hits, total)) in &report.by_scenario {
        let mark = if *total > 0 && hits == total {
            "ok"
        } else if *total == 0 {
            "-"
        } else {
            "MISS"
        };
        writeln!(out, "  {name:<22} {:>6} {:>6}  {mark}", hits, total)?;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_names_the_numbers_that_matter() {
        let mut sink = Vec::new();
        run(&mut sink).expect("bench");
        let text = String::from_utf8(sink).unwrap();

        for field in [
            "precision",
            "recall",
            "accuracy",
            "false positives",
            "wrong but high",
        ] {
            assert!(text.contains(field), "the report must show {field}: {text}");
        }
        assert!(
            text.contains("SCENARIO"),
            "the per-scenario table is the useful part"
        );
        assert!(!text.contains("MISS"), "every scenario should pass: {text}");
    }

    #[test]
    fn the_numbers_are_internally_consistent() {
        let mut sink = Vec::new();
        let report = run(&mut sink).expect("bench");

        assert_eq!(
            report.true_positives + report.false_positives,
            report.knowable - report.false_negatives,
            "every scored connection is either named or not"
        );
        assert!(report.accuracy() >= report.recall() || report.correctly_unknown == 0);
    }
}
