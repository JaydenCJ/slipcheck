//! Output rendering: aligned human text and a hand-rolled JSON document
//! (std-only, so the escaper lives here too). Rendering is pure —
//! everything returns `String`s the CLI prints.

use crate::findings::Severity;
use crate::scan::ArchiveReport;
use crate::VERSION;

/// One archive that failed to scan at all (I/O or parse error).
#[derive(Debug)]
pub struct ScanFailure {
    pub path: String,
    pub error: String,
}

/// `1 warning` / `3 warnings` — count plus a regular noun, pluralized.
fn counted(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("{n} {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Render one archive's report as human-readable lines.
pub fn human(report: &ArchiveReport) -> String {
    let critical = report.count(Severity::Critical);
    let warnings = report.count(Severity::Warning);
    let verdict = if critical > 0 {
        format!("{critical} critical, {}", counted(warnings, "warning"))
    } else if warnings > 0 {
        counted(warnings, "warning")
    } else {
        "clean".to_string()
    };
    let mut out = format!(
        "{}: {}, {} entr{}, {}\n",
        report.path,
        report.format.label(),
        report.entries,
        if report.entries == 1 { "y" } else { "ies" },
        verdict
    );
    for finding in &report.findings {
        let severity = match finding.severity {
            Severity::Critical => "CRITICAL",
            Severity::Warning => "warning ",
        };
        out.push_str(&format!(
            "  {severity} {:<16} {} — {}\n",
            finding.check.id(),
            finding.path,
            finding.detail
        ));
    }
    out
}

/// Render the closing summary line across all archives.
pub fn summary(reports: &[ArchiveReport], failures: &[ScanFailure]) -> String {
    let critical: usize = reports.iter().map(|r| r.count(Severity::Critical)).sum();
    let warnings: usize = reports.iter().map(|r| r.count(Severity::Warning)).sum();
    let mut line = format!(
        "{} scanned: {} critical, {}",
        counted(reports.len(), "archive"),
        critical,
        counted(warnings, "warning")
    );
    if !failures.is_empty() {
        line.push_str(&format!(", {}", counted(failures.len(), "error")));
    }
    line
}

/// Escape a string for a JSON string literal.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Render the whole run as a JSON document.
pub fn json(reports: &[ArchiveReport], failures: &[ScanFailure]) -> String {
    let mut out = String::from("{\n");
    out.push_str(&format!("  \"slipcheck\": \"{}\",\n", json_escape(VERSION)));
    out.push_str("  \"archives\": [\n");
    for (i, report) in reports.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!(
            "      \"path\": \"{}\",\n",
            json_escape(&report.path)
        ));
        out.push_str(&format!(
            "      \"format\": \"{}\",\n",
            report.format.label()
        ));
        out.push_str(&format!("      \"entries\": {},\n", report.entries));
        out.push_str(&format!(
            "      \"critical\": {},\n",
            report.count(Severity::Critical)
        ));
        out.push_str(&format!(
            "      \"warnings\": {},\n",
            report.count(Severity::Warning)
        ));
        out.push_str("      \"findings\": [\n");
        for (j, finding) in report.findings.iter().enumerate() {
            out.push_str(&format!(
                "        {{\"check\": \"{}\", \"severity\": \"{}\", \"path\": \"{}\", \"detail\": \"{}\"}}{}\n",
                finding.check.id(),
                finding.severity.label(),
                json_escape(&finding.path),
                json_escape(&finding.detail),
                if j + 1 < report.findings.len() { "," } else { "" }
            ));
        }
        out.push_str("      ]\n");
        out.push_str(&format!(
            "    }}{}\n",
            if i + 1 < reports.len() { "," } else { "" }
        ));
    }
    out.push_str("  ],\n");
    out.push_str("  \"errors\": [\n");
    for (i, failure) in failures.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"path\": \"{}\", \"error\": \"{}\"}}{}\n",
            json_escape(&failure.path),
            json_escape(&failure.error),
            if i + 1 < failures.len() { "," } else { "" }
        ));
    }
    out.push_str("  ],\n");
    let critical: usize = reports.iter().map(|r| r.count(Severity::Critical)).sum();
    let warnings: usize = reports.iter().map(|r| r.count(Severity::Warning)).sum();
    out.push_str(&format!("  \"critical\": {critical},\n"));
    out.push_str(&format!("  \"warnings\": {warnings}\n"));
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Check, Finding};
    use crate::format::Format;

    fn sample_report() -> ArchiveReport {
        ArchiveReport {
            path: "evil.tar".to_string(),
            format: Format::Tar,
            entries: 3,
            findings: vec![
                Finding::critical(Check::Traversal, "../x", "climbs above the root"),
                Finding::warning(Check::DuplicatePath, "a/b", "appears twice"),
            ],
        }
    }

    #[test]
    fn human_output_shows_verdict_and_findings() {
        let text = human(&sample_report());
        assert!(text.starts_with("evil.tar: tar, 3 entries, 1 critical, 1 warning\n"));
        assert!(text.contains("CRITICAL traversal"));
        assert!(text.contains("warning  duplicate-path"));
        let clean = ArchiveReport {
            path: "ok.zip".into(),
            format: Format::Zip,
            entries: 1,
            findings: vec![],
        };
        assert!(human(&clean).contains("1 entry, clean"));
    }

    #[test]
    fn summary_line_pluralizes_archives_warnings_and_errors() {
        // Singular vs. plural on both sides of the boundary — "1 warnings"
        // in a security report reads as carelessness.
        let one = [sample_report()];
        assert_eq!(
            summary(&one, &[]),
            "1 archive scanned: 1 critical, 1 warning"
        );
        let two = [sample_report(), sample_report()];
        let failures = [ScanFailure {
            path: "broken.zip".into(),
            error: "no EOCD".into(),
        }];
        assert_eq!(
            summary(&two, &failures),
            "2 archives scanned: 2 critical, 2 warnings, 1 error"
        );
    }

    #[test]
    fn json_escape_handles_quotes_backslashes_and_control_bytes() {
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("line\nbreak\ttab"), "line\\nbreak\\ttab");
        assert_eq!(json_escape("bell\u{7}"), "bell\\u0007");
        // Archive names are attacker-controlled: escaping must be total.
        assert_eq!(json_escape("..\\..\\evil"), "..\\\\..\\\\evil");
    }

    #[test]
    fn json_document_totals_and_structure() {
        let doc = json(
            &[sample_report()],
            &[ScanFailure {
                path: "broken.zip".into(),
                error: "no EOCD".into(),
            }],
        );
        assert!(doc.contains("\"critical\": 1"));
        assert!(doc.contains("\"warnings\": 1"));
        assert!(doc.contains("\"check\": \"traversal\""));
        assert!(doc.contains("\"error\": \"no EOCD\""));
        // Must be balanced enough for a strict parser: same count of
        // braces/brackets both ways.
        assert_eq!(doc.matches('{').count(), doc.matches('}').count());
        assert_eq!(doc.matches('[').count(), doc.matches(']').count());
    }
}
