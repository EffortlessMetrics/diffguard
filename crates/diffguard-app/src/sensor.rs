//! Sensor report rendering for Cockpit ecosystem integration.
//!
//! This module converts CheckReceipt to the `sensor.report.v1` format.

use std::collections::HashMap;

use diffguard_types::{
    Artifact, CapabilityStatus, CheckReceipt, RunMeta, SensorFinding, SensorLocation, SensorReport,
    SENSOR_REPORT_SCHEMA_V1,
};

use crate::fingerprint::compute_fingerprint;

/// Context for rendering a sensor report.
#[derive(Debug, Clone, Default)]
pub struct SensorReportContext {
    /// ISO 8601 timestamp when the run started.
    pub started_at: String,
    /// ISO 8601 timestamp when the run ended.
    pub ended_at: String,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Capability status (e.g., git availability).
    pub capabilities: HashMap<String, CapabilityStatus>,
    /// List of artifacts produced.
    pub artifacts: Vec<Artifact>,
    /// Rule metadata for help/url lookup.
    pub rule_metadata: HashMap<String, RuleMetadata>,
}

/// Metadata for a rule (help text and URL).
#[derive(Debug, Clone, Default)]
pub struct RuleMetadata {
    pub help: Option<String>,
    pub url: Option<String>,
}

/// Renders a CheckReceipt as a SensorReport.
pub fn render_sensor_report(receipt: &CheckReceipt, ctx: &SensorReportContext) -> SensorReport {
    let findings = receipt
        .findings
        .iter()
        .map(|f| {
            let metadata = ctx.rule_metadata.get(&f.rule_id);
            SensorFinding {
                check_id: "diffguard.pattern".to_string(),
                code: f.rule_id.clone(),
                severity: f.severity,
                message: f.message.clone(),
                location: SensorLocation {
                    path: normalize_path(&f.path),
                    line: f.line,
                    column: f.column,
                },
                fingerprint: compute_fingerprint(f),
                help: metadata.and_then(|m| m.help.clone()),
                url: metadata.and_then(|m| m.url.clone()),
                data: Some(serde_json::json!({
                    "match_text": f.match_text,
                    "snippet": f.snippet,
                })),
            }
        })
        .collect();

    let data = serde_json::json!({
        "diff": {
            "base": receipt.diff.base,
            "head": receipt.diff.head,
            "context_lines": receipt.diff.context_lines,
            "scope": receipt.diff.scope,
            "files_scanned": receipt.diff.files_scanned,
            "lines_scanned": receipt.diff.lines_scanned,
        }
    });

    SensorReport {
        schema: SENSOR_REPORT_SCHEMA_V1.to_string(),
        tool: receipt.tool.clone(),
        run: RunMeta {
            started_at: ctx.started_at.clone(),
            ended_at: ctx.ended_at.clone(),
            duration_ms: ctx.duration_ms,
            capabilities: ctx.capabilities.clone(),
        },
        verdict: receipt.verdict.clone(),
        findings,
        artifacts: ctx.artifacts.clone(),
        data: Some(data),
    }
}

/// Renders a CheckReceipt as a sensor.report.v1 JSON string.
pub fn render_sensor_json(
    receipt: &CheckReceipt,
    ctx: &SensorReportContext,
) -> Result<String, serde_json::Error> {
    let report = render_sensor_report(receipt, ctx);
    serde_json::to_string_pretty(&report)
}

/// Normalizes a path to use forward slashes (for cross-platform consistency).
fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::{
        DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
    };

    fn test_receipt() -> CheckReceipt {
        CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 2,
                lines_scanned: 50,
            },
            findings: vec![Finding {
                rule_id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "Avoid unwrap".to_string(),
                path: "src/lib.rs".to_string(),
                line: 42,
                column: Some(10),
                match_text: ".unwrap()".to_string(),
                snippet: "let x = foo.unwrap();".to_string(),
            }],
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 1,
                    suppressed: 0,
                },
                reasons: vec!["1 error(s)".to_string()],
            },
            timing: None,
        }
    }

    fn test_context() -> SensorReportContext {
        let mut ctx = SensorReportContext {
            started_at: "2024-01-15T10:30:00Z".to_string(),
            ended_at: "2024-01-15T10:30:01Z".to_string(),
            duration_ms: 1234,
            capabilities: HashMap::new(),
            artifacts: vec![Artifact {
                path: "artifacts/diffguard/report.json".to_string(),
                format: "json".to_string(),
            }],
            rule_metadata: HashMap::new(),
        };
        ctx.capabilities.insert(
            "git".to_string(),
            CapabilityStatus {
                status: "available".to_string(),
                reason: None,
            },
        );
        ctx.rule_metadata.insert(
            "rust.no_unwrap".to_string(),
            RuleMetadata {
                help: Some("Use ? operator instead".to_string()),
                url: Some(
                    "https://doc.rust-lang.org/book/ch09-02-recoverable-errors-with-result.html"
                        .to_string(),
                ),
            },
        );
        ctx
    }

    #[test]
    fn sensor_report_has_correct_schema() {
        let receipt = test_receipt();
        let ctx = test_context();
        let report = render_sensor_report(&receipt, &ctx);
        assert_eq!(report.schema, "sensor.report.v1");
    }

    #[test]
    fn sensor_report_preserves_tool_meta() {
        let receipt = test_receipt();
        let ctx = test_context();
        let report = render_sensor_report(&receipt, &ctx);
        assert_eq!(report.tool.name, "diffguard");
        assert_eq!(report.tool.version, "0.1.0");
    }

    #[test]
    fn sensor_report_includes_run_meta() {
        let receipt = test_receipt();
        let ctx = test_context();
        let report = render_sensor_report(&receipt, &ctx);
        assert_eq!(report.run.started_at, "2024-01-15T10:30:00Z");
        assert_eq!(report.run.ended_at, "2024-01-15T10:30:01Z");
        assert_eq!(report.run.duration_ms, 1234);
        assert!(report.run.capabilities.contains_key("git"));
    }

    #[test]
    fn sensor_finding_has_correct_check_id() {
        let receipt = test_receipt();
        let ctx = test_context();
        let report = render_sensor_report(&receipt, &ctx);
        assert_eq!(report.findings[0].check_id, "diffguard.pattern");
    }

    #[test]
    fn sensor_finding_maps_rule_id_to_code() {
        let receipt = test_receipt();
        let ctx = test_context();
        let report = render_sensor_report(&receipt, &ctx);
        assert_eq!(report.findings[0].code, "rust.no_unwrap");
    }

    #[test]
    fn sensor_finding_has_fingerprint() {
        let receipt = test_receipt();
        let ctx = test_context();
        let report = render_sensor_report(&receipt, &ctx);
        assert_eq!(report.findings[0].fingerprint.len(), 16);
    }

    #[test]
    fn sensor_finding_includes_help_and_url() {
        let receipt = test_receipt();
        let ctx = test_context();
        let report = render_sensor_report(&receipt, &ctx);
        assert!(report.findings[0].help.is_some());
        assert!(report.findings[0].url.is_some());
    }

    #[test]
    fn sensor_finding_includes_data() {
        let receipt = test_receipt();
        let ctx = test_context();
        let report = render_sensor_report(&receipt, &ctx);
        let data = report.findings[0].data.as_ref().unwrap();
        assert_eq!(data["match_text"], ".unwrap()");
        assert_eq!(data["snippet"], "let x = foo.unwrap();");
    }

    #[test]
    fn sensor_report_includes_diff_data() {
        let receipt = test_receipt();
        let ctx = test_context();
        let report = render_sensor_report(&receipt, &ctx);
        let data = report.data.as_ref().unwrap();
        assert_eq!(data["diff"]["base"], "origin/main");
        assert_eq!(data["diff"]["head"], "HEAD");
    }

    #[test]
    fn normalize_path_converts_backslashes() {
        assert_eq!(normalize_path(r"src\lib.rs"), "src/lib.rs");
        assert_eq!(normalize_path(r"src\nested\file.rs"), "src/nested/file.rs");
        assert_eq!(normalize_path("src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn snapshot_sensor_report_with_findings() {
        let receipt = test_receipt();
        let ctx = test_context();
        let json = render_sensor_json(&receipt, &ctx).unwrap();
        insta::assert_snapshot!(json);
    }

    #[test]
    fn snapshot_sensor_report_no_findings() {
        let mut receipt = test_receipt();
        receipt.findings = vec![];
        receipt.verdict = Verdict {
            status: VerdictStatus::Pass,
            counts: VerdictCounts::default(),
            reasons: vec![],
        };
        let ctx = test_context();
        let json = render_sensor_json(&receipt, &ctx).unwrap();
        insta::assert_snapshot!(json);
    }

    #[test]
    fn snapshot_sensor_report_skip_status() {
        let mut receipt = test_receipt();
        receipt.findings = vec![];
        receipt.verdict = Verdict {
            status: VerdictStatus::Skip,
            counts: VerdictCounts::default(),
            reasons: vec!["git_unavailable".to_string()],
        };
        let mut ctx = test_context();
        ctx.capabilities.insert(
            "git".to_string(),
            CapabilityStatus {
                status: "unavailable".to_string(),
                reason: Some("git command not found".to_string()),
            },
        );
        let json = render_sensor_json(&receipt, &ctx).unwrap();
        insta::assert_snapshot!(json);
    }
}
