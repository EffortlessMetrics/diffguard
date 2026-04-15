//! Tests for correct Checkstyle severity mapping for Severity::Info
//!
//! These tests verify that Severity::Info maps to "info" in Checkstyle XML output,
//! as documented in CHANGELOG.md line 57: "Severity mapping: Error→error, Warn→warning, Info→info"
//!
//! These tests SHOULD FAIL if Severity::Info is incorrectly mapped to "warning".
//! They SHOULD PASS once the fix is applied.

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
            status: VerdictStatus::Fail,
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

fn info_finding(rule_id: &str, message: &str, path: &str, line: u32) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Info,
        message: message.to_string(),
        path: path.to_string(),
        line,
        column: None,
        match_text: "matched".to_string(),
        snippet: "the matched code".to_string(),
    }
}

/// Test that Severity::Info maps to "info" in Checkstyle XML output.
/// This is the CORRECT behavior per CHANGELOG.md line 57.
///
/// This test SHOULD FAIL if Info maps to "warning" (bug).
/// This test SHOULD PASS when Info correctly maps to "info".
#[test]
fn test_info_severity_maps_to_info_not_warning() {
    let findings = vec![info_finding("info-rule", "Info message", "src/lib.rs", 10)];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Info should map to "info" in Checkstyle XML (per CHANGELOG.md)
    assert!(
        xml.contains("severity=\"info\""),
        "Severity::Info should produce severity=\"info\" in Checkstyle XML, but got: {}",
        xml
    );

    // Info should NOT produce severity="warning" (that is for Warn)
    assert!(
        !xml.contains("severity=\"warning\""),
        "Severity::Info should NOT produce severity=\"warning\" in Checkstyle XML. Found 'warning' in: {}",
        xml
    );
}

/// Test that when a receipt contains ONLY Info-severity findings,
/// the Checkstyle output has severity="info" (not "warning").
///
/// This verifies no cross-contamination between Warn and Info severities.
#[test]
fn test_info_only_finding_renders_as_info_severity() {
    let findings = vec![
        info_finding("todo-comment", "TODO found", "src/main.rs", 42),
        info_finding("debug-print", "debug print found", "src/main.rs", 100),
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Both findings should have severity="info"
    assert!(
        xml.contains("severity=\"info\""),
        "Info findings should have severity=\"info\" in Checkstyle XML"
    );

    // Neither should have severity="warning" (that's for Warn severity)
    let warning_count = xml.matches("severity=\"warning\"").count();
    assert_eq!(
        warning_count, 0,
        "Info findings should not produce severity=\"warning\", but found {} occurrences in: {}",
        warning_count, xml
    );
}

/// Test that Info and Warn findings are distinct in Checkstyle XML output.
/// Warn → "warning", Info → "info"
///
/// This test SHOULD FAIL if Info incorrectly maps to "warning".
#[test]
fn test_info_and_warn_produce_different_severities() {
    let findings = vec![
        Finding {
            rule_id: "info-rule".to_string(),
            severity: Severity::Info,
            message: "Info message".to_string(),
            path: "src/lib.rs".to_string(),
            line: 10,
            column: None,
            match_text: "matched".to_string(),
            snippet: "the matched code".to_string(),
        },
        Finding {
            rule_id: "warn-rule".to_string(),
            severity: Severity::Warn,
            message: "Warn message".to_string(),
            path: "src/lib.rs".to_string(),
            line: 20,
            column: None,
            match_text: "matched".to_string(),
            snippet: "the matched code".to_string(),
        },
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Both severities should appear
    assert!(
        xml.contains("severity=\"info\""),
        "Info finding should produce severity=\"info\""
    );
    assert!(
        xml.contains("severity=\"warning\""),
        "Warn finding should produce severity=\"warning\""
    );

    // They should be different values - no confusion
    // Info should NOT be "warning" and Warn should NOT be "info"
    assert!(
        xml.contains("source=\"info-rule\""),
        "info-rule should appear in the XML"
    );
    assert!(
        xml.contains("source=\"warn-rule\""),
        "warn-rule should appear in the XML"
    );
}
