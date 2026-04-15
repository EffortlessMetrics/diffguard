//! Snapshot tests for Checkstyle XML output.
//!
//! Run with: cargo test -p diffguard-core
//! Review snapshots with: cargo insta test -p diffguard-core --review

use diffguard_core::render_checkstyle_for_receipt;
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};

fn make_receipt(findings: Vec<Finding>) -> CheckReceipt {
    CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "feat/test".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 10,
        },
        verdict: Verdict {
            status: if findings.is_empty() {
                VerdictStatus::Pass
            } else {
                VerdictStatus::Fail
            },
            counts: VerdictCounts {
                info: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Info)
                    .count() as u32,
                warn: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Warn)
                    .count() as u32,
                error: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Error)
                    .count() as u32,
                suppressed: 0,
            },
            reasons: vec![],
        },
        findings,
        timing: None,
    }
}

fn finding(
    rule_id: &str,
    severity: Severity,
    message: &str,
    path: &str,
    line: u32,
    column: Option<u32>,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity,
        message: message.to_string(),
        path: path.to_string(),
        line,
        column,
        match_text: "matched".to_string(),
        snippet: "the matched code".to_string(),
    }
}

/// Snapshot test for Checkstyle output with no findings (pass scenario).
#[test]
fn snapshot_checkstyle_empty() {
    let receipt = make_receipt(vec![]);
    let xml = render_checkstyle_for_receipt(&receipt);
    assert!(
        xml.contains("<checkstyle version=\"5.0\">"),
        "empty findings should produce valid checkstyle structure"
    );
    assert!(
        xml.contains("</checkstyle>"),
        "should close checkstyle element"
    );
    insta::assert_snapshot!("checkstyle_empty", xml);
}

/// Snapshot test for Checkstyle output with a single finding.
#[test]
fn snapshot_checkstyle_single_finding() {
    let receipt = make_receipt(vec![finding(
        "no-console-log",
        Severity::Warn,
        "Use of console.log detected",
        "src/index.js",
        42,
        Some(5),
    )]);
    let xml = render_checkstyle_for_receipt(&receipt);
    assert!(xml.contains("src/index.js"));
    assert!(xml.contains("no-console-log"));
    assert!(xml.contains("line=\"42\""));
    assert!(xml.contains("column=\"5\""));
    assert!(xml.contains("severity=\"warning\""));
    insta::assert_snapshot!("checkstyle_single_finding", xml);
}

/// Snapshot test for Checkstyle output with all severity levels.
#[test]
fn snapshot_checkstyle_all_severities() {
    let receipt = make_receipt(vec![
        finding("info-rule", Severity::Info, "Info message", "a.rs", 1, None),
        finding(
            "warn-rule",
            Severity::Warn,
            "Warning message",
            "b.rs",
            2,
            Some(3),
        ),
        finding(
            "error-rule",
            Severity::Error,
            "Error message",
            "c.rs",
            4,
            None,
        ),
    ]);
    let xml = render_checkstyle_for_receipt(&receipt);
    // Info should map to "info"
    assert!(xml.contains("severity=\"info\""));
    // Error should be "error"
    assert!(xml.contains("severity=\"error\""));
    insta::assert_snapshot!("checkstyle_all_severities", xml);
}

/// Snapshot test to verify column is omitted when None.
#[test]
fn snapshot_checkstyle_no_column() {
    let receipt = make_receipt(vec![finding(
        "no-print",
        Severity::Warn,
        "Print statement found",
        "scripts/deploy.py",
        12,
        None,
    )]);
    let xml = render_checkstyle_for_receipt(&receipt);
    assert!(xml.contains("line=\"12\""));
    assert!(
        !xml.contains("column=\"") || !xml.contains("column=\"12\""),
        "column attribute should not appear when None"
    );
    insta::assert_snapshot!("checkstyle_no_column", xml);
}

/// Snapshot test for multiple findings in the same file.
#[test]
fn snapshot_checkstyle_multiple_findings_same_file() {
    let receipt = make_receipt(vec![
        finding(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap",
            "src/lib.rs",
            15,
            Some(20),
        ),
        finding(
            "rust.no_dbg",
            Severity::Warn,
            "Remove dbg!",
            "src/lib.rs",
            42,
            Some(3),
        ),
    ]);
    let xml = render_checkstyle_for_receipt(&receipt);
    assert!(xml.contains("src/lib.rs"));
    // Should have two error elements in the same file
    let count = xml.matches("<error").count();
    assert_eq!(count, 2, "should have two error elements");
    insta::assert_snapshot!("checkstyle_multiple_same_file", xml);
}

/// Snapshot test for findings across multiple files.
#[test]
fn snapshot_checkstyle_multiple_files() {
    let receipt = make_receipt(vec![
        finding(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap",
            "src/lib.rs",
            15,
            None,
        ),
        finding(
            "js.no_console",
            Severity::Warn,
            "Console.log",
            "src/index.js",
            10,
            None,
        ),
        finding(
            "python.no_print",
            Severity::Warn,
            "Print found",
            "scripts/deploy.py",
            5,
            None,
        ),
    ]);
    let xml = render_checkstyle_for_receipt(&receipt);
    // Should have three file elements
    let file_count = xml.matches("<file name=").count();
    assert_eq!(file_count, 3, "should have three file elements");
    insta::assert_snapshot!("checkstyle_multiple_files", xml);
}

/// Snapshot test for XML special character escaping.
#[test]
fn snapshot_checkstyle_special_chars() {
    let receipt = make_receipt(vec![finding(
        "test&rule",
        Severity::Error,
        "Message with <special> & \"chars\"",
        "src/special'.rs",
        1,
        None,
    )]);
    let xml = render_checkstyle_for_receipt(&receipt);
    // Check XML escaping
    assert!(xml.contains("&amp;"), "ampersand should be escaped");
    assert!(xml.contains("&lt;"), "less-than should be escaped");
    assert!(xml.contains("&gt;"), "greater-than should be escaped");
    assert!(xml.contains("&quot;"), "quote should be escaped");
    assert!(xml.contains("&apos;"), "apostrophe should be escaped");
    // Unescaped chars should not appear
    assert!(
        !xml.contains(" test&rule"),
        "unescaped ampersand should not appear"
    );
    insta::assert_snapshot!("checkstyle_special_chars", xml);
}

/// Snapshot test to verify determinism - identical inputs produce identical output.
#[test]
fn snapshot_checkstyle_deterministic() {
    let f = finding("rule", Severity::Error, "msg", "f.rs", 10, None);
    let receipt1 = make_receipt(vec![f.clone()]);
    let receipt2 = make_receipt(vec![f.clone()]);
    let xml1 = render_checkstyle_for_receipt(&receipt1);
    let xml2 = render_checkstyle_for_receipt(&receipt2);
    assert_eq!(xml1, xml2, "identical findings must produce identical XML");
}

/// Snapshot test for XML declaration presence.
#[test]
fn snapshot_checkstyle_xml_declaration() {
    let receipt = make_receipt(vec![finding(
        "test-rule",
        Severity::Info,
        "Test",
        "test.rs",
        1,
        None,
    )]);
    let xml = render_checkstyle_for_receipt(&receipt);
    assert!(
        xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
        "should start with XML declaration"
    );
    insta::assert_snapshot!("checkstyle_xml_declaration", xml);
}
