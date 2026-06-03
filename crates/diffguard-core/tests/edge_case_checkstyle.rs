//! Edge case tests for Checkstyle XML output.
//!
//! These tests cover boundary conditions, unusual inputs, and interactions
//! not covered by the standard unit tests or property-based tests.
//!
//! The core issue (Severity::Info mapping to "info" not "warning") is tested
//! in the inline unit tests within checkstyle.rs.

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

// =============================================================================
// Edge Case: All three severities in a single receipt
// =============================================================================

/// Test that all three severity levels can coexist in a single receipt
/// and each produces the correct Checkstyle XML attribute.
#[test]
fn all_three_severities_in_single_receipt() {
    let findings = vec![
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
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // All three severities must appear with correct values
    assert!(
        xml.contains("severity=\"info\""),
        "Info severity should map to 'info': {}",
        xml
    );
    assert!(
        xml.contains("severity=\"warning\""),
        "Warn severity should map to 'warning': {}",
        xml
    );
    assert!(
        xml.contains("severity=\"error\""),
        "Error severity should map to 'error': {}",
        xml
    );
}

// =============================================================================
// Edge Case: Multiple findings same file, different severities
// =============================================================================

/// Test that multiple findings in the same file with different severities
/// each produce the correct severity attribute.
#[test]
fn same_file_different_severities() {
    let findings = vec![
        finding(
            "no-console",
            Severity::Error,
            "Console.log found",
            "src/index.js",
            10,
            Some(5),
        ),
        finding(
            "no-debug",
            Severity::Warn,
            "Debug statement",
            "src/index.js",
            20,
            Some(3),
        ),
        finding(
            "todo-comment",
            Severity::Info,
            "TODO found",
            "src/index.js",
            30,
            None,
        ),
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Same file should have 3 error elements
    let error_count = xml.matches("<error ").count();
    assert_eq!(error_count, 3, "Should have 3 error elements: {}", xml);

    // Each severity should appear exactly once
    assert!(
        xml.contains("severity=\"error\""),
        "Should contain error severity: {}",
        xml
    );
    assert!(
        xml.contains("severity=\"warning\""),
        "Should contain warning severity: {}",
        xml
    );
    assert!(
        xml.contains("severity=\"info\""),
        "Should contain info severity: {}",
        xml
    );
}

// =============================================================================
// Edge Case: Same rule_id multiple lines
// =============================================================================

/// Test that the same rule_id can appear on multiple lines and each
/// produces a separate error element with correct line number.
#[test]
fn same_rule_id_multiple_lines() {
    let findings = vec![
        finding(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap",
            "src/lib.rs",
            10,
            Some(5),
        ),
        finding(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap",
            "src/lib.rs",
            25,
            Some(12),
        ),
        finding(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap",
            "src/lib.rs",
            42,
            None,
        ),
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Should have 3 error elements
    let error_count = xml.matches("<error ").count();
    assert_eq!(error_count, 3, "Should have 3 error elements: {}", xml);

    // Each line number should appear
    assert!(
        xml.contains("line=\"10\""),
        "Should contain line 10: {}",
        xml
    );
    assert!(
        xml.contains("line=\"25\""),
        "Should contain line 25: {}",
        xml
    );
    assert!(
        xml.contains("line=\"42\""),
        "Should contain line 42: {}",
        xml
    );
}

// =============================================================================
// Edge Case: Boundary line numbers
// =============================================================================

/// Test that line number 1 (minimum) works correctly.
#[test]
fn line_number_minimum() {
    let findings = vec![finding(
        "first-line",
        Severity::Error,
        "Error on first line",
        "src/main.rs",
        1,
        Some(1),
    )];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("line=\"1\""),
        "Line 1 should appear in XML: {}",
        xml
    );
}

/// Test that large line numbers work correctly.
#[test]
fn line_number_large() {
    let findings = vec![finding(
        "large-line",
        Severity::Warn,
        "Warning at large line",
        "src/main.rs",
        999_999,
        None,
    )];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("line=\"999999\""),
        "Large line number should appear: {}",
        xml
    );
}

// =============================================================================
// Edge Case: Unicode in messages and paths
// =============================================================================

/// Test that Unicode characters in messages are properly handled.
#[test]
fn unicode_message() {
    let findings = vec![finding(
        "unicode-rule",
        Severity::Warn,
        "Message with émoji 🎉 and unicode: 你好",
        "src/main.rs",
        1,
        None,
    )];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // The XML should contain the message (possibly escaped)
    // Unicode chars should not cause XML parsing issues
    assert!(
        xml.contains("unicode-rule"),
        "Rule ID should appear: {}",
        xml
    );
    assert!(xml.contains("line=\"1\""), "Line should appear: {}", xml);
}

/// Test that Unicode characters in file paths are handled.
#[test]
fn unicode_path() {
    let findings = vec![finding(
        "test-rule",
        Severity::Info,
        "Test message",
        "src/日本語.rs",
        10,
        None,
    )];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Should contain the file element with the path
    assert!(
        xml.contains("src/日本語.rs") || xml.contains("&#"),
        "Unicode path should appear (possibly escaped): {}",
        xml
    );
}

// =============================================================================
// Edge Case: Empty-ish strings (single char when non-empty required)
// =============================================================================

/// Test that a single-character rule_id works.
#[test]
fn single_char_rule_id() {
    let findings = vec![finding(
        "x",
        Severity::Info,
        "Single char rule",
        "a.rs",
        1,
        None,
    )];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("source=\"x\""),
        "Single char rule_id should appear: {}",
        xml
    );
}

// =============================================================================
// Edge Case: Maximum column value
// =============================================================================

/// Test that large column numbers work correctly.
#[test]
fn large_column_number() {
    let findings = vec![finding(
        "long-line",
        Severity::Warn,
        "Warning at large column",
        "src/main.rs",
        1,
        Some(5000),
    )];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("column=\"5000\""),
        "Large column number should appear: {}",
        xml
    );
}

// =============================================================================
// Edge Case: Special characters in rule_id
// =============================================================================

/// Test that dots and hyphens in rule_id are preserved in output.
#[test]
fn rule_id_with_dots_and_hyphens() {
    let findings = vec![finding(
        "rust.no-unwrap.v2",
        Severity::Error,
        "Avoid unwrap",
        "src/lib.rs",
        10,
        None,
    )];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("source=\"rust.no-unwrap.v2\""),
        "Rule ID with dots and hyphens should appear: {}",
        xml
    );
}

// =============================================================================
// Edge Case: File path with directory traversal
// =============================================================================

/// Test that paths with slashes render correctly.
#[test]
fn nested_path() {
    let findings = vec![finding(
        "deep-rule",
        Severity::Info,
        "Deep path",
        "src/a/b/c/d.rs",
        1,
        None,
    )];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("src/a/b/c/d.rs") || xml.contains("src/a/b/c/d"),
        "Nested path should appear: {}",
        xml
    );
}

// =============================================================================
// Red Tests: Severity::Info mapping verification
// These tests verify the original bug (Issue #289) is fixed.
// =============================================================================

/// Test that Severity::Info maps to "info" in Checkstyle XML output.
/// This is the CORRECT behavior per CHANGELOG.md line 57.
///
/// This test SHOULD FAIL if Info maps to "warning" (bug).
/// This test SHOULD PASS when Info correctly maps to "info".
#[test]
fn red_test_info_maps_to_info_not_warning() {
    let findings = vec![finding(
        "info-rule",
        Severity::Info,
        "Info message",
        "src/lib.rs",
        10,
        None,
    )];
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
fn red_test_info_only_no_warning() {
    let findings = vec![
        finding(
            "todo-comment",
            Severity::Info,
            "TODO found",
            "src/main.rs",
            42,
            None,
        ),
        finding(
            "debug-print",
            Severity::Info,
            "debug print found",
            "src/main.rs",
            100,
            None,
        ),
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Both findings should have severity="info"
    assert!(
        xml.contains("severity=\"info\""),
        "Info findings should have severity=\"info\" in Checkstyle XML"
    );

    // Neither should have severity="warning"
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
fn red_test_info_and_warn_different() {
    let findings = vec![
        finding(
            "info-rule",
            Severity::Info,
            "Info message",
            "src/lib.rs",
            10,
            None,
        ),
        finding(
            "warn-rule",
            Severity::Warn,
            "Warn message",
            "src/lib.rs",
            20,
            None,
        ),
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

    // They should be different values
    assert!(
        xml.contains("source=\"info-rule\""),
        "info-rule should appear in the XML"
    );
    assert!(
        xml.contains("source=\"warn-rule\""),
        "warn-rule should appear in the XML"
    );
}
