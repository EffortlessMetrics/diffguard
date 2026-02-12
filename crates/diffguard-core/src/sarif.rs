//! SARIF (Static Analysis Results Interchange Format) output renderer.
//!
//! Converts CheckReceipt to SARIF 2.1.0 format for integration with
//! code scanning tools and GitHub Advanced Security.

use serde::Serialize;
use std::collections::BTreeMap;

use diffguard_types::{CheckReceipt, Finding, Severity};

/// SARIF schema URL
const SARIF_SCHEMA: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// SARIF version
const SARIF_VERSION: &str = "2.1.0";

/// GitHub repository URL for diffguard
const DIFFGUARD_INFO_URI: &str = "https://github.com/effortless-mgmt/diffguard";

/// Root SARIF document structure.
#[derive(Debug, Clone, Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// A single SARIF run (analysis execution).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<SarifInvocation>>,
}

/// Tool information (driver).
#[derive(Debug, Clone, Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

/// Tool driver with rules.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SarifRule>,
}

/// Rule definition.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_configuration: Option<SarifRuleConfiguration>,
}

/// Rule configuration (default severity level).
#[derive(Debug, Clone, Serialize)]
pub struct SarifRuleConfiguration {
    pub level: SarifLevel,
}

/// SARIF result (finding).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: SarifLevel,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_fingerprints: Option<BTreeMap<String, String>>,
}

/// SARIF severity level.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SarifLevel {
    Error,
    Warning,
    Note,
    None,
}

impl From<Severity> for SarifLevel {
    fn from(s: Severity) -> Self {
        match s {
            Severity::Error => SarifLevel::Error,
            Severity::Warn => SarifLevel::Warning,
            Severity::Info => SarifLevel::Note,
        }
    }
}

/// Message with text.
#[derive(Debug, Clone, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

/// Location of a result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

/// Physical location with file and region.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

/// Artifact (file) location.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
}

/// Region within a file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    pub start_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifSnippet>,
}

/// Code snippet.
#[derive(Debug, Clone, Serialize)]
pub struct SarifSnippet {
    pub text: String,
}

/// Invocation information.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifInvocation {
    pub execution_successful: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
}

/// Renders a CheckReceipt as a SARIF 2.1.0 report.
pub fn render_sarif_for_receipt(receipt: &CheckReceipt) -> SarifReport {
    // Collect unique rules from findings
    let rules = collect_rules_from_findings(&receipt.findings);

    // Convert findings to SARIF results
    let results: Vec<SarifResult> = receipt
        .findings
        .iter()
        .map(finding_to_sarif_result)
        .collect();

    SarifReport {
        schema: SARIF_SCHEMA.to_string(),
        version: SARIF_VERSION.to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: receipt.tool.name.clone(),
                    version: receipt.tool.version.clone(),
                    information_uri: DIFFGUARD_INFO_URI.to_string(),
                    rules,
                },
            },
            results,
            invocations: None,
        }],
    }
}

/// Renders a SARIF report as a JSON string.
pub fn render_sarif_json(receipt: &CheckReceipt) -> Result<String, serde_json::Error> {
    let report = render_sarif_for_receipt(receipt);
    serde_json::to_string_pretty(&report)
}

/// Collects unique rule definitions from findings.
fn collect_rules_from_findings(findings: &[Finding]) -> Vec<SarifRule> {
    let mut seen = BTreeMap::new();

    for f in findings {
        if !seen.contains_key(&f.rule_id) {
            seen.insert(
                f.rule_id.clone(),
                SarifRule {
                    id: f.rule_id.clone(),
                    short_description: Some(SarifMessage {
                        text: f.message.clone(),
                    }),
                    default_configuration: Some(SarifRuleConfiguration {
                        level: f.severity.into(),
                    }),
                },
            );
        }
    }

    seen.into_values().collect()
}

/// Converts a diffguard Finding to a SARIF Result.
fn finding_to_sarif_result(f: &Finding) -> SarifResult {
    // Create a fingerprint based on rule, path, line
    let mut fingerprints = BTreeMap::new();
    fingerprints.insert(
        "primaryLocationLineHash".to_string(),
        format!("{}:{}:{}", f.rule_id, f.path, f.line),
    );

    SarifResult {
        rule_id: f.rule_id.clone(),
        level: f.severity.into(),
        message: SarifMessage {
            text: f.message.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: f.path.clone(),
                    uri_base_id: Some("%SRCROOT%".to_string()),
                },
                region: Some(SarifRegion {
                    start_line: f.line,
                    start_column: f.column,
                    snippet: Some(SarifSnippet {
                        text: f.snippet.clone(),
                    }),
                }),
            },
        }],
        partial_fingerprints: Some(fingerprints),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::{
        CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, ToolMeta, Verdict, VerdictCounts,
        VerdictStatus,
    };

    /// Helper to create a test receipt with multiple findings
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
                    rule_id: "python.no_print".to_string(),
                    severity: Severity::Warn,
                    message: "Remove print() before merging.".to_string(),
                    path: "scripts/deploy.py".to_string(),
                    line: 8,
                    column: None,
                    match_text: "print(".to_string(),
                    snippet: "print(\"Deploying...\")".to_string(),
                },
            ],
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 2,
                    error: 1,
                    ..Default::default()
                },
                reasons: vec![
                    "1 error-level finding".to_string(),
                    "2 warning-level findings".to_string(),
                ],
            },
            timing: None,
        }
    }

    /// Helper to create a test receipt with no findings
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
                counts: VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 0,
                    ..Default::default()
                },
                reasons: vec![],
            },
            timing: None,
        }
    }

    /// Helper to create a test receipt with info-level findings
    fn create_test_receipt_info_findings() -> CheckReceipt {
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
                files_scanned: 1,
                lines_scanned: 10,
            },
            findings: vec![Finding {
                rule_id: "info.todo".to_string(),
                severity: Severity::Info,
                message: "Found a TODO comment.".to_string(),
                path: "src/lib.rs".to_string(),
                line: 5,
                column: None,
                match_text: "TODO".to_string(),
                snippet: "// TODO: refactor this".to_string(),
            }],
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: VerdictCounts {
                    info: 1,
                    warn: 0,
                    error: 0,
                    ..Default::default()
                },
                reasons: vec![],
            },
            timing: None,
        }
    }

    #[test]
    fn sarif_has_correct_schema_and_version() {
        let receipt = create_test_receipt_empty();
        let sarif = render_sarif_for_receipt(&receipt);

        assert_eq!(sarif.schema, SARIF_SCHEMA);
        assert_eq!(sarif.version, SARIF_VERSION);
    }

    #[test]
    fn sarif_tool_info_is_correct() {
        let receipt = create_test_receipt_with_findings();
        let sarif = render_sarif_for_receipt(&receipt);

        assert_eq!(sarif.runs.len(), 1);
        let driver = &sarif.runs[0].tool.driver;
        assert_eq!(driver.name, "diffguard");
        assert_eq!(driver.version, "0.1.0");
        assert_eq!(driver.information_uri, DIFFGUARD_INFO_URI);
    }

    #[test]
    fn sarif_contains_all_findings() {
        let receipt = create_test_receipt_with_findings();
        let sarif = render_sarif_for_receipt(&receipt);

        assert_eq!(sarif.runs[0].results.len(), 3);
    }

    #[test]
    fn sarif_severity_mapping_error() {
        let receipt = create_test_receipt_with_findings();
        let sarif = render_sarif_for_receipt(&receipt);

        let error_result = &sarif.runs[0].results[0];
        assert!(matches!(error_result.level, SarifLevel::Error));
    }

    #[test]
    fn sarif_severity_mapping_warning() {
        let receipt = create_test_receipt_with_findings();
        let sarif = render_sarif_for_receipt(&receipt);

        let warn_result = &sarif.runs[0].results[1];
        assert!(matches!(warn_result.level, SarifLevel::Warning));
    }

    #[test]
    fn sarif_severity_mapping_note() {
        let receipt = create_test_receipt_info_findings();
        let sarif = render_sarif_for_receipt(&receipt);

        let info_result = &sarif.runs[0].results[0];
        assert!(matches!(info_result.level, SarifLevel::Note));
    }

    #[test]
    fn sarif_location_includes_line_and_column() {
        let receipt = create_test_receipt_with_findings();
        let sarif = render_sarif_for_receipt(&receipt);

        let result = &sarif.runs[0].results[0];
        let location = &result.locations[0];
        let region = location.physical_location.region.as_ref().unwrap();

        assert_eq!(region.start_line, 15);
        assert_eq!(region.start_column, Some(10));
    }

    #[test]
    fn sarif_location_without_column() {
        let receipt = create_test_receipt_with_findings();
        let sarif = render_sarif_for_receipt(&receipt);

        // Third finding has no column
        let result = &sarif.runs[0].results[2];
        let location = &result.locations[0];
        let region = location.physical_location.region.as_ref().unwrap();

        assert_eq!(region.start_line, 8);
        assert_eq!(region.start_column, None);
    }

    #[test]
    fn sarif_empty_receipt_has_no_results() {
        let receipt = create_test_receipt_empty();
        let sarif = render_sarif_for_receipt(&receipt);

        assert!(sarif.runs[0].results.is_empty());
        assert!(sarif.runs[0].tool.driver.rules.is_empty());
    }

    #[test]
    fn sarif_rules_are_deduplicated() {
        // Create receipt with duplicate rule IDs
        let mut receipt = create_test_receipt_with_findings();
        receipt.findings.push(Finding {
            rule_id: "rust.no_unwrap".to_string(), // Same as first finding
            severity: Severity::Error,
            message: "Avoid unwrap/expect in production code.".to_string(),
            path: "src/other.rs".to_string(),
            line: 100,
            column: None,
            match_text: ".unwrap()".to_string(),
            snippet: "x.unwrap()".to_string(),
        });

        let sarif = render_sarif_for_receipt(&receipt);

        // Should have 3 unique rules, not 4
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 3);
    }

    #[test]
    fn sarif_json_is_valid() {
        let receipt = create_test_receipt_with_findings();
        let json = render_sarif_json(&receipt).expect("should serialize");

        // Should parse back successfully
        let _: serde_json::Value = serde_json::from_str(&json).expect("should be valid JSON");
    }

    /// Snapshot test for SARIF output with findings.
    #[test]
    fn snapshot_sarif_with_findings() {
        let receipt = create_test_receipt_with_findings();
        let json = render_sarif_json(&receipt).expect("should serialize");
        insta::assert_snapshot!(json);
    }

    /// Snapshot test for SARIF output with no findings.
    #[test]
    fn snapshot_sarif_no_findings() {
        let receipt = create_test_receipt_empty();
        let json = render_sarif_json(&receipt).expect("should serialize");
        insta::assert_snapshot!(json);
    }

    /// Snapshot test for SARIF output with info-level findings.
    #[test]
    fn snapshot_sarif_info_findings() {
        let receipt = create_test_receipt_info_findings();
        let json = render_sarif_json(&receipt).expect("should serialize");
        insta::assert_snapshot!(json);
    }
}
