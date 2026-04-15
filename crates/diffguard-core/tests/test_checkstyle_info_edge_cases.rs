//! Edge case tests for Checkstyle Info severity mapping
//!
//! These tests verify edge cases not covered by the red tests:
//! - Boundary values (line 0, large line numbers)
//! - Empty and whitespace-only strings
//! - Unicode characters in paths, messages, rule_ids
//! - Multiple Info findings on the same line
//! - Mixed severity ordering (Info before/after Warn/Error)
//! - Verifying no cross-contamination between severities

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

fn info_finding(
    rule_id: &str,
    message: &str,
    path: &str,
    line: u32,
    column: Option<u32>,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Info,
        message: message.to_string(),
        path: path.to_string(),
        line,
        column,
        match_text: "matched".to_string(),
        snippet: "the matched code".to_string(),
    }
}

/// Test Info severity with line number 0 (boundary value).
/// Line 0 is technically valid in some contexts.
#[test]
fn test_info_severity_line_zero() {
    let findings = vec![info_finding(
        "todo",
        "TODO at line 0",
        "src/lib.rs",
        0,
        None,
    )];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info should map to severity=info even at line 0"
    );
    assert!(
        xml.contains("line=\"0\""),
        "Line 0 should be preserved in output"
    );
    assert!(
        !xml.contains("severity=\"warning\""),
        "Info at line 0 should not produce severity=warning"
    );
}

/// Test Info severity with a very large line number.
#[test]
fn test_info_severity_large_line_number() {
    let findings = vec![info_finding("todo", "TODO", "src/lib.rs", u32::MAX, None)];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info should map to severity=info even with large line number"
    );
    assert!(
        xml.contains(&format!("line=\"{}\"", u32::MAX)),
        "Large line number should be preserved"
    );
}

/// Test Info severity with empty rule_id.
#[test]
fn test_info_severity_empty_rule_id() {
    let findings = vec![info_finding("", "Empty rule id", "src/lib.rs", 1, None)];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info should map to severity=info even with empty rule_id"
    );
    assert!(
        xml.contains("source=\"\""),
        "Empty rule_id should appear as empty source attribute"
    );
    assert!(
        !xml.contains("severity=\"warning\""),
        "Info with empty rule_id should not produce severity=warning"
    );
}

/// Test Info severity with empty message.
#[test]
fn test_info_severity_empty_message() {
    let findings = vec![info_finding("rule", "", "src/lib.rs", 1, None)];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info should map to severity=info even with empty message"
    );
    assert!(
        xml.contains("message=\"\""),
        "Empty message should appear as empty message attribute"
    );
    assert!(
        !xml.contains("severity=\"warning\""),
        "Info with empty message should not produce severity=warning"
    );
}

/// Test Info severity with empty path.
#[test]
fn test_info_severity_empty_path() {
    let findings = vec![info_finding("rule", "message", "", 1, None)];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info should map to severity=info even with empty path"
    );
    assert!(
        xml.contains("name=\"\""),
        "Empty path should appear as empty name attribute"
    );
    assert!(
        !xml.contains("severity=\"warning\""),
        "Info with empty path should not produce severity=warning"
    );
}

/// Test Info severity with whitespace-only strings.
#[test]
fn test_info_severity_whitespace_strings() {
    let findings = vec![Finding {
        rule_id: "   ".to_string(),
        severity: Severity::Info,
        message: "   ".to_string(),
        path: "   ".to_string(),
        line: 1,
        column: None,
        match_text: "".to_string(),
        snippet: "".to_string(),
    }];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info should map to severity=info with whitespace-only strings"
    );
    assert!(
        !xml.contains("severity=\"warning\""),
        "Info with whitespace strings should not produce severity=warning"
    );
}

/// Test Info severity with Unicode characters in path, message, and rule_id.
#[test]
fn test_info_severity_unicode_content() {
    let findings = vec![Finding {
        rule_id: "规则-тест-🔒".to_string(),
        severity: Severity::Info,
        message: "Сообщение с юникодом:日本語".to_string(),
        path: "src/路径/folder/📁".to_string(),
        line: 42,
        column: None,
        match_text: "matched".to_string(),
        snippet: "matched code".to_string(),
    }];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info should map to severity=info with Unicode content"
    );
    assert!(
        xml.contains("source=\"规则-тест-🔒\""),
        "Unicode rule_id should be preserved"
    );
    // Note: Unicode should NOT be escaped - it should appear directly
    assert!(
        xml.contains("Сообщение"),
        "Unicode message should be preserved"
    );
    assert!(
        !xml.contains("severity=\"warning\""),
        "Info with Unicode should not produce severity=warning"
    );
}

/// Test multiple Info findings on the same line (same file).
#[test]
fn test_info_multiple_findings_same_line() {
    let findings = vec![
        info_finding("todo-1", "First TODO", "src/lib.rs", 10, None),
        info_finding("todo-2", "Second TODO", "src/lib.rs", 10, None),
        info_finding("debug-1", "Debug print", "src/lib.rs", 10, None),
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // All should have severity="info"
    let info_count = xml.matches("severity=\"info\"").count();
    assert_eq!(
        info_count, 3,
        "All three Info findings should have severity=info, found {}",
        info_count
    );

    // None should have severity="warning"
    let warning_count = xml.matches("severity=\"warning\"").count();
    assert_eq!(
        warning_count, 0,
        "Info findings should not produce severity=warning, found {}",
        warning_count
    );
}

/// Test mixed severity ordering: Info first, then Warn, then Error.
#[test]
fn test_info_mixed_severity_order_info_first() {
    let findings = vec![
        info_finding("info-rule", "Info message", "src/lib.rs", 10, None),
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
        Finding {
            rule_id: "error-rule".to_string(),
            severity: Severity::Error,
            message: "Error message".to_string(),
            path: "src/lib.rs".to_string(),
            line: 30,
            column: None,
            match_text: "matched".to_string(),
            snippet: "the matched code".to_string(),
        },
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info finding should have severity=info"
    );
    assert!(
        xml.contains("severity=\"warning\""),
        "Warn finding should have severity=warning"
    );
    assert!(
        xml.contains("severity=\"error\""),
        "Error finding should have severity=error"
    );
    // Ensure source attributes are correct
    assert!(
        xml.contains("source=\"info-rule\""),
        "info-rule should appear"
    );
    assert!(
        xml.contains("source=\"warn-rule\""),
        "warn-rule should appear"
    );
    assert!(
        xml.contains("source=\"error-rule\""),
        "error-rule should appear"
    );
}

/// Test mixed severity ordering: Error first, then Warn, then Info.
#[test]
fn test_info_mixed_severity_order_info_last() {
    let findings = vec![
        Finding {
            rule_id: "error-rule".to_string(),
            severity: Severity::Error,
            message: "Error message".to_string(),
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
        info_finding("info-rule", "Info message", "src/lib.rs", 30, None),
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info finding should have severity=info"
    );
    assert!(
        xml.contains("severity=\"warning\""),
        "Warn finding should have severity=warning"
    );
    assert!(
        xml.contains("severity=\"error\""),
        "Error finding should have severity=error"
    );
}

/// Test that Info findings don't cross-contaminate with Warn findings
/// when both exist in the same receipt.
#[test]
fn test_info_no_cross_contamination_with_warn() {
    let findings = vec![
        info_finding("info-rule", "Info message", "src/lib.rs", 10, None),
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

    // Each severity should appear exactly once
    let info_count = xml.matches("severity=\"info\"").count();
    let warning_count = xml.matches("severity=\"warning\"").count();

    assert_eq!(
        info_count, 1,
        "Info should appear exactly once, found {}",
        info_count
    );
    assert_eq!(
        warning_count, 1,
        "Warn should appear exactly once, found {}",
        warning_count
    );
}

/// Test Info severity with column specified.
#[test]
fn test_info_severity_with_column() {
    let findings = vec![info_finding(
        "todo",
        "TODO comment",
        "src/lib.rs",
        10,
        Some(5),
    )];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info should map to severity=info even with column"
    );
    assert!(
        xml.contains("column=\"5\""),
        "Column should be included when specified"
    );
    assert!(
        !xml.contains("severity=\"warning\""),
        "Info with column should not produce severity=warning"
    );
}

/// Test that an Info-only receipt doesn't accidentally include "warning" anywhere.
#[test]
fn test_info_only_no_warning_string_in_output() {
    let findings = vec![
        info_finding("info-1", "Info 1", "src/a.rs", 1, None),
        info_finding("info-2", "Info 2", "src/b.rs", 2, None),
        info_finding("info-3", "Info 3", "src/c.rs", 3, Some(10)),
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // The string "warning" (as a severity value) should NOT appear
    assert!(
        !xml.contains("severity=\"warning\""),
        "Info-only receipt should not contain severity=warning anywhere"
    );

    // But "info" should appear 3 times (once per finding)
    let info_count = xml.matches("severity=\"info\"").count();
    assert_eq!(
        info_count, 3,
        "Info-only receipt should have severity=info 3 times, found {}",
        info_count
    );
}

/// Test that the word "warning" can appear in message content without being confused.
/// This is a sanity check to ensure we're matching the attribute value, not just any substring.
#[test]
fn test_warning_word_in_message_not_confused_with_severity() {
    let findings = vec![Finding {
        rule_id: "warn-word".to_string(),
        severity: Severity::Info,
        message: "This message contains the word warning in lowercase".to_string(),
        path: "src/lib.rs".to_string(),
        line: 1,
        column: None,
        match_text: "matched".to_string(),
        snippet: "the matched code".to_string(),
    }];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Should have severity="info"
    assert!(
        xml.contains("severity=\"info\""),
        "Info should map to severity=info"
    );

    // Should NOT have severity="warning" even though the word appears in message
    assert!(
        !xml.contains("severity=\"warning\""),
        "Info should not produce severity=warning just because message contains 'warning'"
    );

    // The message itself should still contain the word "warning"
    assert!(
        xml.contains("the word warning in lowercase"),
        "Message content should be preserved verbatim"
    );
}

/// Test Info severity with a very long rule_id and message.
#[test]
fn test_info_severity_long_content() {
    let long_rule_id = "a".repeat(1000);
    let long_message = "x".repeat(10000);

    let findings = vec![Finding {
        rule_id: long_rule_id.clone(),
        severity: Severity::Info,
        message: long_message.clone(),
        path: "src/lib.rs".to_string(),
        line: 1,
        column: None,
        match_text: "matched".to_string(),
        snippet: "the matched code".to_string(),
    }];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    assert!(
        xml.contains("severity=\"info\""),
        "Info should map to severity=info even with very long content"
    );
    assert!(
        xml.contains(&format!("source=\"{}\"", "a".repeat(1000).as_str())),
        "Long rule_id should be preserved"
    );
    assert!(
        !xml.contains("severity=\"warning\""),
        "Info with long content should not produce severity=warning"
    );
}

/// Test that the XML output is well-formed even with all Info findings.
#[test]
fn test_info_xml_well_formed() {
    let findings = vec![
        info_finding("rule1", "msg1", "a.rs", 1, None),
        info_finding("rule2", "msg2", "b.rs", 2, Some(3)),
    ];
    let receipt = make_receipt(findings);
    let xml = render_checkstyle_for_receipt(&receipt);

    // Check well-formed XML structure
    assert!(
        xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
        "Should start with XML declaration"
    );
    assert!(
        xml.contains("<checkstyle version=\"5.0\">"),
        "Should contain checkstyle root element"
    );
    assert!(
        xml.contains("</checkstyle>"),
        "Should close checkstyle element"
    );

    // Should have 2 file elements
    let file_count = xml.matches("<file name=").count();
    assert_eq!(file_count, 2, "Should have 2 file elements");

    // Should have 2 error elements
    let error_count = xml.matches("<error").count();
    assert_eq!(error_count, 2, "Should have 2 error elements");

    // Each error should have severity="info"
    let info_count = xml.matches("severity=\"info\"").count();
    assert_eq!(info_count, 2, "Both errors should have severity=info");
}
