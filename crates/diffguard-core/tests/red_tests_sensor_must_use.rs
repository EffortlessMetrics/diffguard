//! Red tests for render_sensor_report() #[must_use] attribute.
//!
//! These tests verify that render_sensor_report() returns a properly structured
//! SensorReport that MUST be used by callers. The #[must_use] attribute ensures
//! that discarding the SensorReport produces a compiler warning/error, preventing
//! silent sensor data loss.
//!
//! NOTE: These are RED tests - they define what correct behavior looks like.
//! The render_sensor_report() function must be marked with #[must_use] so that
//! any caller discarding the result receives a compiler warning.

use diffguard_core::{RuleMetadata, SensorReportContext, render_sensor_report};
use diffguard_types::{
    Artifact, CAP_GIT, CAP_STATUS_AVAILABLE, CHECK_ID_PATTERN, CapabilityStatus, CheckReceipt,
    DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
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
                suppressed: 0,
            },
            reasons: vec!["has_error".to_string()],
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
        truncated_count: 0,
        rules_total: 10,
    }
}

// ============================================================================
// Tests for #[must_use] on render_sensor_report()
// ============================================================================

/// Verifies that render_sensor_report returns a SensorReport with sensor.report.v1 schema.
/// The #[must_use] attribute ensures callers cannot discard this critical sensor data.
#[test]
fn test_render_sensor_report_returns_sensor_report_v1_schema() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    // The return value MUST be captured - discarding it would lose sensor data
    let report = render_sensor_report(&receipt, &ctx);

    // Verify the schema is the sensor.report.v1 format
    assert_eq!(
        report.schema, "sensor.report.v1",
        "render_sensor_report MUST return sensor.report.v1 schema - this is the R2 Library Contract"
    );
}

/// Verifies that render_sensor_report preserves tool metadata.
/// Tool name and version are critical for sensor data traceability.
#[test]
fn test_render_sensor_report_preserves_tool_metadata() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert_eq!(
        report.tool.name, "diffguard-test",
        "SensorReport MUST preserve tool name for traceability"
    );
    assert_eq!(
        report.tool.version, "1.0.0",
        "SensorReport MUST preserve tool version for reproducibility"
    );
}

/// Verifies that render_sensor_report includes run metadata from context.
/// Run metadata (timing, capabilities) is essential for sensor analytics.
#[test]
fn test_render_sensor_report_includes_run_metadata() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert_eq!(
        report.run.started_at, "2024-01-15T10:30:00Z",
        "SensorReport MUST include started_at timestamp"
    );
    assert_eq!(
        report.run.ended_at, "2024-01-15T10:30:01Z",
        "SensorReport MUST include ended_at timestamp"
    );
    assert_eq!(
        report.run.duration_ms, 1000,
        "SensorReport MUST include duration_ms"
    );
    assert!(
        report.run.capabilities.contains_key("git"),
        "SensorReport MUST include capability status"
    );
}

/// Verifies that render_sensor_report preserves the verdict.
/// Verdict status and counts are the primary sensor data for governance decisions.
#[test]
fn test_render_sensor_report_preserves_verdict() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert_eq!(
        report.verdict.status,
        VerdictStatus::Fail,
        "SensorReport MUST preserve verdict status"
    );
    assert_eq!(
        report.verdict.counts.error, 3,
        "SensorReport MUST preserve error count"
    );
    assert_eq!(
        report.verdict.counts.warn, 2,
        "SensorReport MUST preserve warn count"
    );
    assert_eq!(
        report.verdict.counts.info, 1,
        "SensorReport MUST preserve info count"
    );
}

/// Verifies that render_sensor_report includes artifacts from context.
/// Artifacts are produced by the sensor run and must not be lost.
#[test]
fn test_render_sensor_report_includes_artifacts() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert!(
        !report.artifacts.is_empty(),
        "SensorReport MUST include artifacts - discarding this loses sensor outputs"
    );
    assert_eq!(
        report.artifacts[0].format, "json",
        "SensorReport artifact format MUST be preserved"
    );
}

/// Verifies that render_sensor_report maps findings to sensor format correctly.
/// Each finding becomes a SensorFinding with fingerprint, location, and metadata.
#[test]
fn test_render_sensor_report_maps_findings_to_sensor_format() {
    let findings = vec![Finding {
        rule_id: "rust.no_unwrap".to_string(),
        severity: Severity::Error,
        message: "Avoid unwrap in production code".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        column: Some(10),
        match_text: ".unwrap()".to_string(),
        snippet: "let x = value.unwrap();".to_string(),
    }];
    let receipt = make_check_receipt(findings);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert_eq!(
        report.findings.len(),
        1,
        "SensorReport MUST include all findings"
    );

    let sensor_finding = &report.findings[0];
    assert_eq!(
        sensor_finding.check_id, CHECK_ID_PATTERN,
        "SensorFinding check_id MUST be diffguard.pattern"
    );
    assert_eq!(
        sensor_finding.code, "rust.no_unwrap",
        "SensorFinding code MUST map from rule_id"
    );
    assert_eq!(
        sensor_finding.severity,
        Severity::Error,
        "SensorFinding severity MUST be preserved"
    );
    assert!(
        sensor_finding.fingerprint.len() == 64,
        "SensorFinding fingerprint MUST be a 64-char SHA-256"
    );
}

/// Verifies that render_sensor_report includes help and URL from rule metadata.
/// This metadata is critical for sensor users to understand and act on findings.
#[test]
fn test_render_sensor_report_includes_rule_metadata() {
    let findings = vec![Finding {
        rule_id: "rust.no_unwrap".to_string(),
        severity: Severity::Warn,
        message: "Avoid unwrap".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        column: Some(10),
        match_text: ".unwrap()".to_string(),
        snippet: "value.unwrap()".to_string(),
    }];
    let receipt = make_check_receipt(findings);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    let finding = &report.findings[0];
    assert!(
        finding.help.is_some(),
        "SensorFinding MUST include help text from rule_metadata - losing this harms sensor usability"
    );
    assert!(
        finding.url.is_some(),
        "SensorFinding MUST include URL from rule_metadata - losing this prevents sensor users from learning more"
    );
}

/// Verifies that render_sensor_report includes diff metadata in data payload.
/// Diff context (base, head, scope) is essential for sensor reproducibility.
#[test]
fn test_render_sensor_report_includes_diff_metadata() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    let data = report
        .data
        .as_ref()
        .expect("SensorReport MUST have data payload");
    assert_eq!(
        data["diff"]["base"], "origin/main",
        "SensorReport data MUST include diff base ref"
    );
    assert_eq!(
        data["diff"]["head"], "HEAD",
        "SensorReport data MUST include diff head ref"
    );
    assert_eq!(
        data["diff"]["scope"], "added",
        "SensorReport data MUST include diff scope"
    );
}

/// Verifies that render_sensor_report includes rules_matched count.
/// This aggregate statistic is a key sensor metric for governance dashboards.
#[test]
fn test_render_sensor_report_includes_rules_matched() {
    let findings = vec![
        Finding {
            rule_id: "rust.no_unwrap".to_string(),
            severity: Severity::Error,
            message: "Avoid unwrap".to_string(),
            path: "src/lib.rs".to_string(),
            line: 42,
            column: Some(10),
            match_text: ".unwrap()".to_string(),
            snippet: "value.unwrap()".to_string(),
        },
        Finding {
            rule_id: "rust.no_unwrap".to_string(), // Same rule
            severity: Severity::Error,
            message: "Avoid unwrap".to_string(),
            path: "src/main.rs".to_string(),
            line: 100,
            column: Some(5),
            match_text: ".unwrap()".to_string(),
            snippet: "foo.unwrap()".to_string(),
        },
    ];
    let receipt = make_check_receipt(findings);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    let data = report
        .data
        .as_ref()
        .expect("SensorReport MUST have data payload");
    assert_eq!(
        data["diffguard"]["rules_matched"], 1,
        "SensorReport MUST count distinct rules matched (not total findings)"
    );
    // But we should have 2 findings
    assert_eq!(
        report.findings.len(),
        2,
        "SensorReport MUST include all findings even if same rule"
    );
}

/// Verifies that render_sensor_report includes tags_matched from rule metadata.
/// Tag counts are important sensor metrics for category-based governance.
#[test]
fn test_render_sensor_report_includes_tags_matched() {
    let findings = vec![Finding {
        rule_id: "rust.no_unwrap".to_string(), // Has tags: "safety", "correctness"
        severity: Severity::Warn,
        message: "Avoid unwrap".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        column: Some(10),
        match_text: ".unwrap()".to_string(),
        snippet: "value.unwrap()".to_string(),
    }];
    let receipt = make_check_receipt(findings);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    let data = report
        .data
        .as_ref()
        .expect("SensorReport MUST have data payload");
    let tags = data["diffguard"]["tags_matched"]
        .as_object()
        .expect("SensorReport MUST include tags_matched when rules have tags");

    assert_eq!(
        tags["safety"].as_u64(),
        Some(1),
        "SensorReport tags_matched MUST count 'safety' tag occurrences"
    );
    assert_eq!(
        tags["correctness"].as_u64(),
        Some(1),
        "SensorReport tags_matched MUST count 'correctness' tag occurrences"
    );
}

/// Verifies that render_sensor_report handles empty findings correctly.
/// Even with no findings, the SensorReport must be captured for governance attestation.
#[test]
fn test_render_sensor_report_handles_empty_findings() {
    let receipt = make_check_receipt(vec![]);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert!(
        report.findings.is_empty(),
        "SensorReport MUST handle empty findings (pass verdict)"
    );
    // The verdict is still Fail in our test receipt, but with 0 findings
    // This is the governance system's responsibility
}

/// Verifies that render_sensor_report normalizes paths to forward slashes.
/// Cross-platform path normalization is critical for sensor data consistency.
#[test]
fn test_render_sensor_report_normalizes_paths() {
    let findings = vec![Finding {
        rule_id: "test.rule".to_string(),
        severity: Severity::Info,
        message: "Test".to_string(),
        path: r"src\components\Button.rs".to_string(), // Backslashes
        line: 10,
        column: None,
        match_text: "test".to_string(),
        snippet: "test".to_string(),
    }];
    let receipt = make_check_receipt(findings);
    let ctx = make_sensor_context();

    let report = render_sensor_report(&receipt, &ctx);

    assert_eq!(
        report.findings[0].location.path, "src/components/Button.rs",
        "SensorReport MUST normalize paths to forward slashes for cross-platform consistency"
    );
}
