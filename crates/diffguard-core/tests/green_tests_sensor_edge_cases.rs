//! Green tests for render_sensor_report() — edge cases and stress tests.
//!
//! These tests verify that render_sensor_report() handles edge cases correctly,
//! complementing the red tests which verify core functionality.
//!
//! Edge cases covered:
//! - Missing rule metadata (help/url become None)
//! - Suppressed count preservation
//! - truncated_count preservation
//! - Verdict reasons preservation
//! - Empty artifacts
//! - Empty capabilities
//! - None column in findings
//! - Multiple findings with same tag from different rules
//! - Unicode and special characters
//! - Boundary values

use diffguard_core::{RuleMetadata, SensorReportContext, render_sensor_report};
use diffguard_types::{
    Artifact, CAP_GIT, CAP_STATUS_AVAILABLE, CapabilityStatus, CheckReceipt, DiffMeta, Finding,
    Scope, Severity, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
};
use std::collections::HashMap;

// ============================================================================
// Helper Functions
// ============================================================================

fn make_check_receipt(findings: Vec<Finding>) -> CheckReceipt {
    CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard-test".to_string(),
            version: "1.0.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 5,
            lines_scanned: 100,
        },
        findings,
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 1,
                warn: 2,
                error: 3,
                suppressed: 4,
            },
            reasons: vec!["has_error".to_string(), "exceeds_threshold".to_string()],
        },
        timing: None,
    }
}

fn make_sensor_context() -> SensorReportContext {
    let mut capabilities = HashMap::new();
    capabilities.insert(
        CAP_GIT.to_string(),
        CapabilityStatus {
            status: CAP_STATUS_AVAILABLE.to_string(),
            reason: None,
            detail: None,
        },
    );

    let mut rule_metadata = HashMap::new();
    rule_metadata.insert(
        "rust.no_unwrap".to_string(),
        RuleMetadata {
            help: Some("Use ? operator instead".to_string()),
            url: Some("https://doc.rust-lang.org".to_string()),
            tags: vec!["safety".to_string(), "correctness".to_string()],
        },
    );

    SensorReportContext {
        started_at: "2024-01-15T10:30:00Z".to_string(),
        ended_at: "2024-01-15T10:30:01Z".to_string(),
        duration_ms: 1000,
        capabilities,
        artifacts: vec![Artifact {
            path: "artifacts/sensor/report.json".to_string(),
            format: "json".to_string(),
        }],
        rule_metadata,
        truncated_count: 5,
        rules_total: 10,
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Verifies that findings without matching rule_metadata get None for help and URL.
/// This is critical because sensor users need to know when rule metadata is missing.
#[test]
fn test_render_sensor_report_finding_without_rule_metadata_has_none_help_and_url() {
    let findings = vec![Finding {
        rule_id: "unknown.rule".to_string(), // Not in rule_metadata
        severity: Severity::Error,
        message: "Unknown rule error".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        column: Some(10),
        match_text: "test".to_string(),
        snippet: "test()".to_string(),
    }];
    let receipt = make_check_receipt(findings);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    let finding = &report.findings[0];
    assert!(
        finding.help.is_none(),
        "SensorFinding MUST have None help when rule_id not in rule_metadata"
    );
    assert!(
        finding.url.is_none(),
        "SensorFinding MUST have None url when rule_id not in rule_metadata"
    );
}

/// Verifies that suppressed count is preserved in the data payload.
/// Suppressed findings are still important for governance metrics.
#[test]
fn test_render_sensor_report_preserves_suppressed_count() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    let data = report
        .data
        .as_ref()
        .expect("SensorReport MUST have data payload");
    assert_eq!(
        data["diffguard"]["suppressed_count"], 4,
        "SensorReport MUST preserve suppressed_count from verdict"
    );
}

/// Verifies that truncated_count from context is preserved in the data payload.
/// This tells sensor consumers how many findings were dropped.
#[test]
fn test_render_sensor_report_preserves_truncated_count() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    let data = report
        .data
        .as_ref()
        .expect("SensorReport MUST have data payload");
    assert_eq!(
        data["diffguard"]["truncated_count"], 5,
        "SensorReport MUST preserve truncated_count from context"
    );
}

/// Verifies that rules_total from context is preserved in the data payload.
#[test]
fn test_render_sensor_report_preserves_rules_total() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    let data = report
        .data
        .as_ref()
        .expect("SensorReport MUST have data payload");
    assert_eq!(
        data["diffguard"]["rules_total"], 10,
        "SensorReport MUST preserve rules_total from context"
    );
}

/// Verifies that verdict reasons are preserved.
/// Reasons explain WHY a non-pass verdict was given.
#[test]
fn test_render_sensor_report_preserves_verdict_reasons() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert_eq!(
        report.verdict.reasons.len(),
        2,
        "SensorReport MUST preserve verdict reasons"
    );
    assert!(
        report.verdict.reasons.contains(&"has_error".to_string()),
        "SensorReport verdict reasons MUST include 'has_error'"
    );
    assert!(
        report
            .verdict
            .reasons
            .contains(&"exceeds_threshold".to_string()),
        "SensorReport verdict reasons MUST include 'exceeds_threshold'"
    );
}

/// Verifies that findings with None column are handled correctly.
/// Column may be None when line-based matching is used.
#[test]
fn test_render_sensor_report_handles_none_column() {
    let findings = vec![Finding {
        rule_id: "rust.no_unwrap".to_string(),
        severity: Severity::Error,
        message: "Avoid unwrap".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        column: None, // None column
        match_text: ".unwrap()".to_string(),
        snippet: "let x = foo.unwrap();".to_string(),
    }];
    let receipt = make_check_receipt(findings);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert!(
        report.findings[0].location.column.is_none(),
        "SensorFinding column MUST be None when input has None column"
    );
}

/// Verifies that multiple findings with same tag from different rules are counted correctly.
#[test]
fn test_render_sensor_report_counts_same_tag_from_different_rules() {
    let findings = vec![
        Finding {
            rule_id: "rust.no_unwrap".to_string(), // Has tag "safety"
            severity: Severity::Error,
            message: "Avoid unwrap".to_string(),
            path: "src/lib.rs".to_string(),
            line: 42,
            column: Some(10),
            match_text: ".unwrap()".to_string(),
            snippet: "foo.unwrap()".to_string(),
        },
        Finding {
            rule_id: "rust.no_clone".to_string(), // Assume has tag "safety" too
            severity: Severity::Warn,
            message: "Avoid clone".to_string(),
            path: "src/main.rs".to_string(),
            line: 100,
            column: Some(5),
            match_text: ".clone()".to_string(),
            snippet: "x.clone()".to_string(),
        },
    ];
    let receipt = make_check_receipt(findings);
    let mut ctx = make_sensor_context();
    // Add rule metadata for the second rule with same tag
    ctx.rule_metadata.insert(
        "rust.no_clone".to_string(),
        RuleMetadata {
            help: Some("Use reference instead".to_string()),
            url: Some("https://rust-lang.org".to_string()),
            tags: vec!["safety".to_string()], // Same tag as rust.no_unwrap
        },
    );

    let report = render_sensor_report(&receipt, &ctx);

    let data = report
        .data
        .as_ref()
        .expect("SensorReport MUST have data payload");
    let tags = data["diffguard"]["tags_matched"]
        .as_object()
        .expect("tags_matched must be present");
    assert_eq!(
        tags["safety"].as_u64(),
        Some(2),
        "SensorReport MUST count same tag from different rules (safety=2)"
    );
}

/// Verifies that empty artifacts list is handled correctly.
#[test]
fn test_render_sensor_report_handles_empty_artifacts() {
    let receipt = make_check_receipt(vec![]);
    let mut ctx = make_sensor_context();
    ctx.artifacts = vec![]; // Empty artifacts

    let report = render_sensor_report(&receipt, &ctx);

    assert!(
        report.artifacts.is_empty(),
        "SensorReport MUST handle empty artifacts list"
    );
}

/// Verifies that empty capabilities map is handled correctly.
#[test]
fn test_render_sensor_report_handles_empty_capabilities() {
    let receipt = make_check_receipt(vec![]);
    let mut ctx = make_sensor_context();
    ctx.capabilities = HashMap::new(); // Empty capabilities

    let report = render_sensor_report(&receipt, &ctx);

    assert!(
        report.run.capabilities.is_empty(),
        "SensorReport MUST handle empty capabilities"
    );
}

/// Verifies that findings with all severity levels render correctly.
#[test]
fn test_render_sensor_report_handles_all_severity_levels() {
    let findings = vec![
        Finding {
            rule_id: "info.rule".to_string(),
            severity: Severity::Info,
            message: "Info message".to_string(),
            path: "src/lib.rs".to_string(),
            line: 1,
            column: None,
            match_text: "info".to_string(),
            snippet: "info()".to_string(),
        },
        Finding {
            rule_id: "warn.rule".to_string(),
            severity: Severity::Warn,
            message: "Warn message".to_string(),
            path: "src/lib.rs".to_string(),
            line: 2,
            column: None,
            match_text: "warn".to_string(),
            snippet: "warn()".to_string(),
        },
        Finding {
            rule_id: "error.rule".to_string(),
            severity: Severity::Error,
            message: "Error message".to_string(),
            path: "src/lib.rs".to_string(),
            line: 3,
            column: None,
            match_text: "error".to_string(),
            snippet: "error()".to_string(),
        },
    ];
    let receipt = make_check_receipt(findings);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert_eq!(
        report.findings.len(),
        3,
        "SensorReport MUST include all findings"
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count(),
        1,
        "SensorReport MUST preserve Info severity"
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warn)
            .count(),
        1,
        "SensorReport MUST preserve Warn severity"
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count(),
        1,
        "SensorReport MUST preserve Error severity"
    );
}

/// Verifies that findings with zero line number are handled (edge case).
#[test]
fn test_render_sensor_report_handles_zero_line_number() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Info,
        message: "Zero line".to_string(),
        path: "src/lib.rs".to_string(),
        line: 0, // Edge case: zero line
        column: Some(0),
        match_text: "test".to_string(),
        snippet: "test".to_string(),
    }];
    let receipt = make_check_receipt(findings);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert_eq!(
        report.findings[0].location.line, 0,
        "SensorReport MUST preserve zero line number"
    );
}

/// Verifies that findings with very large line numbers are handled.
#[test]
fn test_render_sensor_report_handles_large_line_numbers() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Info,
        message: "Large line".to_string(),
        path: "src/lib.rs".to_string(),
        line: u32::MAX, // Edge case: max line number
        column: Some(u32::MAX),
        match_text: "test".to_string(),
        snippet: "test".to_string(),
    }];
    let receipt = make_check_receipt(findings);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert_eq!(
        report.findings[0].location.line,
        u32::MAX,
        "SensorReport MUST preserve large line numbers"
    );
    assert_eq!(
        report.findings[0].location.column,
        Some(u32::MAX),
        "SensorReport MUST preserve large column numbers"
    );
}

/// Verifies that findings with all verdict statuses render correctly.
#[test]
fn test_render_sensor_report_handles_all_verdict_statuses() {
    let statuses = vec![
        VerdictStatus::Pass,
        VerdictStatus::Fail,
        VerdictStatus::Skip,
    ];

    for status in statuses {
        let receipt = CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard-test".to_string(),
                version: "1.0.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 3,
                scope: Scope::Added,
                files_scanned: 5,
                lines_scanned: 100,
            },
            findings: vec![],
            verdict: Verdict {
                status,
                counts: VerdictCounts::default(),
                reasons: vec![],
            },
            timing: None,
        };
        let ctx = make_sensor_context();

        let report = render_sensor_report(&receipt, &ctx);

        assert_eq!(
            report.verdict.status, receipt.verdict.status,
            "SensorReport MUST preserve verdict status",
        );
    }
}

/// Verifies that diff metadata with zero values is preserved.
#[test]
fn test_render_sensor_report_handles_zero_diff_metadata() {
    let receipt = CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard-test".to_string(),
            version: "1.0.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned: 0, // Zero
            lines_scanned: 0, // Zero
        },
        findings: vec![],
        verdict: Verdict {
            status: VerdictStatus::Pass,
            counts: VerdictCounts::default(),
            reasons: vec![],
        },
        timing: None,
    };
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    let data = report
        .data
        .as_ref()
        .expect("SensorReport MUST have data payload");
    assert_eq!(
        data["diff"]["files_scanned"], 0,
        "SensorReport MUST preserve zero files_scanned"
    );
    assert_eq!(
        data["diff"]["lines_scanned"], 0,
        "SensorReport MUST preserve zero lines_scanned"
    );
    assert_eq!(
        data["diff"]["context_lines"], 0,
        "SensorReport MUST preserve zero context_lines"
    );
}

/// Verifies that multiple findings with no tags don't produce tags_matched.
#[test]
fn test_render_sensor_report_omits_tags_matched_when_no_tags() {
    let findings = vec![Finding {
        rule_id: "notag.rule".to_string(), // No tags in metadata
        severity: Severity::Info,
        message: "No tag".to_string(),
        path: "src/lib.rs".to_string(),
        line: 1,
        column: None,
        match_text: "test".to_string(),
        snippet: "test".to_string(),
    }];
    let receipt = make_check_receipt(findings);
    let mut ctx = make_sensor_context();
    ctx.rule_metadata.insert(
        "notag.rule".to_string(),
        RuleMetadata {
            help: None,
            url: None,
            tags: vec![], // Empty tags
        },
    );

    let report = render_sensor_report(&receipt, &ctx);

    let data = report
        .data
        .as_ref()
        .expect("SensorReport MUST have data payload");
    assert!(
        !data["diffguard"]
            .as_object()
            .unwrap()
            .contains_key("tags_matched"),
        "SensorReport MUST NOT include tags_matched when no rules have tags"
    );
}
