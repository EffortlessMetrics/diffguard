//! Snapshot tests for GitLab Code Quality output.
//!
//! Run with: cargo test -p diffguard-core
//! Review snapshots with: cargo insta test -p diffguard-core --review

use diffguard_core::render_gitlab_quality_json;
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

fn finding(rule_id: &str, severity: Severity, message: &str, path: &str, line: u32) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity,
        message: message.to_string(),
        path: path.to_string(),
        line,
        column: None,
        match_text: "matched".to_string(),
        snippet: "the matched code".to_string(),
    }
}

#[test]
fn snapshot_gitlab_quality_empty() {
    let receipt = make_receipt(vec![]);
    let json = render_gitlab_quality_json(&receipt).unwrap();
    assert!(
        json.contains("[]"),
        "empty findings should produce empty array"
    );
    insta::assert_snapshot!("gitlab_quality_empty", json);
}

#[test]
fn snapshot_gitlab_quality_single_finding() {
    let receipt = make_receipt(vec![finding(
        "no-console-log",
        Severity::Warn,
        "Use of console.log detected",
        "src/index.js",
        42,
    )]);
    let json = render_gitlab_quality_json(&receipt).unwrap();
    assert!(json.contains("Use of console.log detected"));
    assert!(json.contains("no-console-log"));
    assert!(json.contains("src/index.js"));
    assert!(json.contains("42"));
    insta::assert_snapshot!("gitlab_quality_single_finding", json);
}

#[test]
fn snapshot_gitlab_quality_all_severities() {
    let receipt = make_receipt(vec![
        finding("info-rule", Severity::Info, "Info message", "a.rs", 1),
        finding("warn-rule", Severity::Warn, "Warning message", "b.rs", 2),
        finding("error-rule", Severity::Error, "Error message", "c.rs", 3),
    ]);
    let json = render_gitlab_quality_json(&receipt).unwrap();
    // Check severity labels
    assert!(json.contains("\"info\""));
    assert!(json.contains("\"minor\"")); // Warn -> minor
    assert!(json.contains("\"major\"")); // Error -> major
    insta::assert_snapshot!("gitlab_quality_all_severities", json);
}

#[test]
fn snapshot_gitlab_quality_fingerprint_deterministic() {
    let f = finding("rule", Severity::Error, "msg", "f.rs", 10);
    let receipt1 = make_receipt(vec![f.clone()]);
    let receipt2 = make_receipt(vec![f.clone()]);
    let json1 = render_gitlab_quality_json(&receipt1).unwrap();
    let json2 = render_gitlab_quality_json(&receipt2).unwrap();
    assert_eq!(
        json1, json2,
        "identical findings must produce identical JSON"
    );
}

#[test]
fn snapshot_gitlab_quality_prettyprinted() {
    let receipt = make_receipt(vec![finding(
        "test-rule",
        Severity::Info,
        "Test message",
        "test.rs",
        1,
    )]);
    let json = render_gitlab_quality_json(&receipt).unwrap();
    assert!(json.contains('\n'), "output should be pretty-printed");
    assert!(
        json.contains("  "),
        "pretty-printed JSON should have indentation"
    );
}
