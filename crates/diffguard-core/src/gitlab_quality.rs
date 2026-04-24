//! GitLab Code Quality output renderer.
//!
//! Converts CheckReceipt to GitLab Code Quality JSON format for integration with
//! GitLab Merge Request code quality reports.
//!
//! Schema reference: https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool

use serde::Serialize;
use sha2::{Digest, Sha256};

use diffguard_types::{CheckReceipt, Finding, Severity};

/// GitLab Code Quality report (array of findings).
pub type GitLabQualityReport = Vec<GitLabFinding>;

/// A single GitLab Code Quality finding.
#[derive(Debug, Clone, Serialize)]
pub struct GitLabFinding {
    /// Description of the code quality violation.
    pub description: String,
    /// Unique fingerprint for this finding.
    pub fingerprint: String,
    /// Severity level: info, minor, major, critical, or blocker.
    pub severity: GitLabSeverity,
    /// Location of the finding.
    pub location: GitLabLocation,
    /// Check name (rule identifier).
    pub check_name: String,
    /// Optional additional content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<GitLabContent>,
}

/// GitLab severity levels.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum GitLabSeverity {
    Info,
    Minor,
    Major,
    Critical,
    Blocker,
}

/// GitLab location structure.
#[derive(Debug, Clone, Serialize)]
pub struct GitLabLocation {
    /// File path.
    pub path: String,
    /// Lines (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<GitLabLines>,
}

/// GitLab lines structure.
#[derive(Debug, Clone, Serialize)]
pub struct GitLabLines {
    /// Beginning line number.
    pub begin: u32,
}

/// GitLab content structure.
#[derive(Debug, Clone, Serialize)]
pub struct GitLabContent {
    /// Body of the content.
    pub body: String,
}

impl From<Severity> for GitLabSeverity {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Info => GitLabSeverity::Info,
            Severity::Warn => GitLabSeverity::Minor,
            Severity::Error => GitLabSeverity::Major,
        }
    }
}

/// Renders a CheckReceipt as a GitLab Code Quality report.
pub fn render_gitlab_quality_for_receipt(receipt: &CheckReceipt) -> GitLabQualityReport {
    receipt.findings.iter().map(finding_to_gitlab).collect()
}

/// Renders a GitLab Code Quality report as a JSON string.
///
/// # Errors
///
/// Returns [`serde_json::Error`] if serialization fails.
pub fn render_gitlab_quality_json(receipt: &CheckReceipt) -> Result<String, serde_json::Error> {
    let report = render_gitlab_quality_for_receipt(receipt);
    serde_json::to_string_pretty(&report)
}

/// Converts a Finding to a GitLab finding.
fn finding_to_gitlab(finding: &Finding) -> GitLabFinding {
    let fingerprint = compute_fingerprint(finding);
    let content = if finding.snippet.is_empty() {
        None
    } else {
        Some(GitLabContent {
            body: finding.snippet.clone(),
        })
    };

    GitLabFinding {
        description: finding.message.clone(),
        fingerprint,
        severity: finding.severity.into(),
        location: GitLabLocation {
            path: finding.path.clone(),
            lines: Some(GitLabLines {
                begin: finding.line,
            }),
        },
        check_name: finding.rule_id.clone(),
        content,
    }
}

/// Computes a deterministic fingerprint for a finding.
fn compute_fingerprint(finding: &Finding) -> String {
    let mut hasher = Sha256::new();
    hasher.update(finding.rule_id.as_bytes());
    hasher.update(finding.path.as_bytes());
    hasher.update(finding.line.to_string().as_bytes());
    if let Some(col) = finding.column {
        hasher.update(col.to_string().as_bytes());
    }
    hasher.update(finding.match_text.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::{
        CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
        VerdictCounts, VerdictStatus,
    };

    fn make_test_receipt(findings: Vec<Finding>) -> CheckReceipt {
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            diff: DiffMeta {
                base: "main".to_string(),
                head: "feature".to_string(),
                context_lines: 3,
                scope: Scope::Added,
                files_scanned: 3,
                lines_scanned: 150,
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

    fn make_finding(
        rule_id: &str,
        severity: Severity,
        message: &str,
        path: &str,
        line: u32,
    ) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity,
            message: message.to_string(),
            path: path.to_string(),
            line,
            column: None,
            match_text: "matched".to_string(),
            snippet: String::new(),
        }
    }

    fn make_finding_with_match_text(
        rule_id: &str,
        severity: Severity,
        message: &str,
        path: &str,
        line: u32,
        match_text: &str,
    ) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            severity,
            message: message.to_string(),
            path: path.to_string(),
            line,
            column: None,
            match_text: match_text.to_string(),
            snippet: String::new(),
        }
    }

    #[test]
    fn gitlab_quality_severity_mapping() {
        let receipt = make_test_receipt(vec![
            make_finding(
                "rust.no_unwrap",
                Severity::Error,
                "Avoid unwrap.",
                "src/main.rs",
                42,
            ),
            make_finding(
                "js.no_console",
                Severity::Warn,
                "console.log",
                "src/index.js",
                15,
            ),
            make_finding(
                "python.no_print",
                Severity::Info,
                "Use logging.",
                "src/app.py",
                20,
            ),
        ]);
        let report = render_gitlab_quality_for_receipt(&receipt);

        assert_eq!(report.len(), 3);
        // Error -> major
        assert!(matches!(report[0].severity, GitLabSeverity::Major));
        // Warn -> minor
        assert!(matches!(report[1].severity, GitLabSeverity::Minor));
        // Info -> info
        assert!(matches!(report[2].severity, GitLabSeverity::Info));
    }

    #[test]
    fn gitlab_quality_empty_receipt() {
        let receipt = make_test_receipt(vec![]);
        let report = render_gitlab_quality_for_receipt(&receipt);
        assert!(report.is_empty());
    }

    #[test]
    fn gitlab_quality_fingerprint_consistency() {
        let receipt = make_test_receipt(vec![make_finding(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap.",
            "src/main.rs",
            42,
        )]);
        let report1 = render_gitlab_quality_for_receipt(&receipt);
        let report2 = render_gitlab_quality_for_receipt(&receipt);
        assert_eq!(report1[0].fingerprint, report2[0].fingerprint);
    }

    #[test]
    fn gitlab_quality_json_serialization() {
        let receipt = make_test_receipt(vec![make_finding(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap.",
            "src/main.rs",
            42,
        )]);
        let json = render_gitlab_quality_json(&receipt).expect("should serialize");

        // Should be valid JSON array
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse");
        assert!(parsed.is_array());
    }

    /// Snapshot test for GitLab Quality output with findings.
    #[test]
    fn snapshot_gitlab_quality_with_findings() {
        let receipt = make_test_receipt(vec![
            make_finding(
                "rust.no_unwrap",
                Severity::Error,
                "Avoid unwrap/expect in production code.",
                "src/main.rs",
                42,
            ),
            make_finding(
                "js.no_console",
                Severity::Warn,
                "Use of console.log detected.",
                "src/index.js",
                15,
            ),
        ]);
        let json = render_gitlab_quality_json(&receipt).expect("should serialize");
        insta::assert_snapshot!("gitlab_quality_with_findings", json);
    }

    /// Snapshot test for GitLab Quality output with no findings.
    #[test]
    fn snapshot_gitlab_quality_no_findings() {
        let receipt = make_test_receipt(vec![]);
        let json = render_gitlab_quality_json(&receipt).expect("should serialize");
        insta::assert_snapshot!("gitlab_quality_no_findings", json);
    }

    // ── Fingerprint bug-fix tests ─────────────────────────────────────────────
    // Bug: compute_fingerprint used finding.message instead of finding.match_text.
    // These tests will FAIL until the fix is applied (line 126: use match_text).

    /// Two findings with the same rule_id, path, line, and message BUT different
    /// match_text MUST have different fingerprints. Using message in the hash
    /// causes these to collide (same fingerprint), which is wrong.
    #[test]
    fn fingerprint_uses_match_text_not_message() {
        let finding_a = make_finding_with_match_text(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap/expect in production code.", // same message
            "src/main.rs",
            42,
            ".unwrap()", // different match_text
        );
        let finding_b = make_finding_with_match_text(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap/expect in production code.", // same message
            "src/main.rs",
            42,
            ".expect(\"something\")", // different match_text
        );

        let report_a = render_gitlab_quality_for_receipt(&make_test_receipt(vec![finding_a]));
        let report_b = render_gitlab_quality_for_receipt(&make_test_receipt(vec![finding_b]));

        // The fingerprints MUST differ because match_text differs
        assert_ne!(
            report_a[0].fingerprint, report_b[0].fingerprint,
            "fingerprint must use match_text, not message; \
             findings with different match_text values should have different fingerprints"
        );
    }

    /// Verify that match_text alone drives fingerprint differentiation when all
    /// other fields are identical. This isolates the fix to match_text hashing.
    #[test]
    fn fingerprint_changes_when_match_text_changes() {
        let base = make_finding_with_match_text(
            "js.no_console",
            Severity::Warn,
            "Remove console.log before merging.",
            "src/index.js",
            10,
            "console.log",
        );
        let changed = make_finding_with_match_text(
            "js.no_console",
            Severity::Warn,
            "Remove console.log before merging.",
            "src/index.js",
            10,
            "console.warn",
        );

        let report_base = render_gitlab_quality_for_receipt(&make_test_receipt(vec![base]));
        let report_changed = render_gitlab_quality_for_receipt(&make_test_receipt(vec![changed]));

        assert_ne!(
            report_base[0].fingerprint, report_changed[0].fingerprint,
            "changing only match_text must change the fingerprint"
        );
    }

    /// Sanity check: two completely identical findings must produce identical fingerprints.
    #[test]
    fn fingerprint_identical_for_identical_findings() {
        let finding_a = make_finding_with_match_text(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap.",
            "src/lib.rs",
            99,
            ".unwrap()",
        );
        let finding_b = make_finding_with_match_text(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap.",
            "src/lib.rs",
            99,
            ".unwrap()",
        );

        let report_a = render_gitlab_quality_for_receipt(&make_test_receipt(vec![finding_a]));
        let report_b = render_gitlab_quality_for_receipt(&make_test_receipt(vec![finding_b]));

        assert_eq!(
            report_a[0].fingerprint, report_b[0].fingerprint,
            "identical findings must produce identical fingerprints"
        );
    }
}
