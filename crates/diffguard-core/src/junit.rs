//! JUnit XML output renderer.
//!
//! Converts CheckReceipt to JUnit XML format for integration with
//! CI systems that support JUnit test result reporting.

use std::collections::BTreeMap;

use diffguard_types::{CheckReceipt, Finding, Severity};

/// Renders a CheckReceipt as a JUnit XML report.
///
/// The structure is:
/// - `<testsuites>` - root element, one per receipt
/// - `<testsuite>` - one per unique rule_id
/// - `<testcase>` - one per finding
/// - `<failure>` - present for error/warn severity findings
pub fn render_junit_for_receipt(receipt: &CheckReceipt) -> String {
    let mut out = String::new();

    // XML declaration
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

    // Group findings by rule_id using BTreeMap for deterministic ordering
    let mut suites: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in &receipt.findings {
        suites.entry(f.rule_id.clone()).or_default().push(f);
    }

    // Calculate totals
    let total_tests = receipt.findings.len();
    let total_failures = receipt
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Error | Severity::Warn))
        .count();

    // Root element
    out.push_str(&format!(
        "<testsuites name=\"diffguard\" tests=\"{}\" failures=\"{}\" errors=\"0\">\n",
        total_tests, total_failures
    ));

    // Emit a testsuite per rule_id
    for (rule_id, findings) in &suites {
        let suite_failures = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Error | Severity::Warn))
            .count();

        out.push_str(&format!(
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"0\">\n",
            escape_xml(rule_id),
            findings.len(),
            suite_failures
        ));

        // Emit a testcase per finding
        for f in findings {
            let classname = escape_xml(&f.path);
            let name = format!("{}:{}", f.path, f.line);

            out.push_str(&format!(
                "    <testcase classname=\"{}\" name=\"{}\">\n",
                classname,
                escape_xml(&name)
            ));

            // Add failure element for non-info severity
            if matches!(f.severity, Severity::Error | Severity::Warn) {
                let failure_type = match f.severity {
                    Severity::Error => "error",
                    Severity::Warn => "warning",
                    Severity::Info => "info",
                };

                out.push_str(&format!(
                    "      <failure type=\"{}\" message=\"{}\">\n",
                    failure_type,
                    escape_xml(&f.message)
                ));
                out.push_str(&format!(
                    "Rule: {}\nFile: {}\nLine: {}\nSnippet: {}\n",
                    f.rule_id, f.path, f.line, f.snippet
                ));
                out.push_str("      </failure>\n");
            }

            out.push_str("    </testcase>\n");
        }

        out.push_str("  </testsuite>\n");
    }

    // If no findings, emit an empty pass testsuite
    if receipt.findings.is_empty() {
        out.push_str("  <testsuite name=\"diffguard\" tests=\"1\" failures=\"0\" errors=\"0\">\n");
        out.push_str("    <testcase classname=\"diffguard\" name=\"no_findings\">\n");
        out.push_str("    </testcase>\n");
        out.push_str("  </testsuite>\n");
    }

    out.push_str("</testsuites>\n");
    out
}

/// Escapes special XML characters in a string.
fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::{
        CheckReceipt, DiffMeta, Finding, Scope, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
        CHECK_SCHEMA_V1,
    };

    fn create_test_receipt_with_findings() -> CheckReceipt {
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 3,
                lines_scanned: 42,
            },
            findings: vec![
                Finding {
                    rule_id: "rust.no_unwrap".to_string(),
                    severity: Severity::Error,
                    message: "Avoid unwrap/expect in production code.".to_string(),
                    path: "src/lib.rs".to_string(),
                    line: 15,
                    column: Some(10),
                    match_text: ".unwrap()".to_string(),
                    snippet: "let value = result.unwrap();".to_string(),
                },
                Finding {
                    rule_id: "rust.no_dbg".to_string(),
                    severity: Severity::Warn,
                    message: "Remove dbg!/println! before merging.".to_string(),
                    path: "src/main.rs".to_string(),
                    line: 23,
                    column: Some(5),
                    match_text: "dbg!".to_string(),
                    snippet: "    dbg!(config);".to_string(),
                },
                Finding {
                    rule_id: "rust.no_unwrap".to_string(),
                    severity: Severity::Error,
                    message: "Avoid unwrap/expect in production code.".to_string(),
                    path: "src/other.rs".to_string(),
                    line: 8,
                    column: None,
                    match_text: ".unwrap()".to_string(),
                    snippet: "x.unwrap()".to_string(),
                },
            ],
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 2,
                    ..Default::default()
                },
                reasons: vec![
                    "2 error-level findings".to_string(),
                    "1 warning-level finding".to_string(),
                ],
            },
            timing: None,
        }
    }

    fn create_test_receipt_empty() -> CheckReceipt {
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 5,
                lines_scanned: 120,
            },
            findings: vec![],
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: VerdictCounts::default(),
                reasons: vec![],
            },
            timing: None,
        }
    }

    #[test]
    fn junit_xml_declaration() {
        let receipt = create_test_receipt_empty();
        let xml = render_junit_for_receipt(&receipt);
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    }

    #[test]
    fn junit_has_testsuites_root() {
        let receipt = create_test_receipt_with_findings();
        let xml = render_junit_for_receipt(&receipt);
        assert!(xml.contains("<testsuites name=\"diffguard\""));
        assert!(xml.contains("</testsuites>"));
    }

    #[test]
    fn junit_groups_by_rule_id() {
        let receipt = create_test_receipt_with_findings();
        let xml = render_junit_for_receipt(&receipt);
        // Should have 2 testsuites (rust.no_dbg and rust.no_unwrap)
        assert!(xml.contains("<testsuite name=\"rust.no_dbg\""));
        assert!(xml.contains("<testsuite name=\"rust.no_unwrap\""));
    }

    #[test]
    fn junit_has_correct_test_count() {
        let receipt = create_test_receipt_with_findings();
        let xml = render_junit_for_receipt(&receipt);
        // Total tests should be 3
        assert!(xml.contains("tests=\"3\""));
    }

    #[test]
    fn junit_has_correct_failure_count() {
        let receipt = create_test_receipt_with_findings();
        let xml = render_junit_for_receipt(&receipt);
        // All 3 findings are errors/warnings, so 3 failures
        assert!(xml.contains("failures=\"3\""));
    }

    #[test]
    fn junit_empty_receipt_has_pass_testcase() {
        let receipt = create_test_receipt_empty();
        let xml = render_junit_for_receipt(&receipt);
        assert!(xml.contains("tests=\"1\""));
        assert!(xml.contains("failures=\"0\""));
        assert!(xml.contains("name=\"no_findings\""));
    }

    #[test]
    fn junit_escapes_xml_special_chars() {
        let mut receipt = create_test_receipt_with_findings();
        receipt.findings[0].message = "Test <special> & \"chars\"".to_string();
        let xml = render_junit_for_receipt(&receipt);
        assert!(xml.contains("&lt;special&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;"));
    }

    #[test]
    fn junit_failure_includes_details() {
        let receipt = create_test_receipt_with_findings();
        let xml = render_junit_for_receipt(&receipt);
        assert!(xml.contains("<failure type=\"error\""));
        assert!(xml.contains("<failure type=\"warning\""));
        assert!(xml.contains("Rule: rust.no_unwrap"));
        assert!(xml.contains("File: src/lib.rs"));
        assert!(xml.contains("Line: 15"));
    }

    /// Snapshot test for JUnit XML output with findings.
    #[test]
    fn snapshot_junit_with_findings() {
        let receipt = create_test_receipt_with_findings();
        let xml = render_junit_for_receipt(&receipt);
        insta::assert_snapshot!(xml);
    }

    /// Snapshot test for JUnit XML output with no findings.
    #[test]
    fn snapshot_junit_no_findings() {
        let receipt = create_test_receipt_empty();
        let xml = render_junit_for_receipt(&receipt);
        insta::assert_snapshot!(xml);
    }

    #[test]
    fn escape_xml_handles_all_special_chars() {
        assert_eq!(escape_xml("&"), "&amp;");
        assert_eq!(escape_xml("<"), "&lt;");
        assert_eq!(escape_xml(">"), "&gt;");
        assert_eq!(escape_xml("\""), "&quot;");
        assert_eq!(escape_xml("'"), "&apos;");
        assert_eq!(escape_xml("normal text"), "normal text");
        assert_eq!(escape_xml("<a & b>"), "&lt;a &amp; b&gt;");
    }
}
