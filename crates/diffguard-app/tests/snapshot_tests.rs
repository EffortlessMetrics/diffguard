//! Snapshot tests for JSON receipt output (Roadmap 1.14) and
//! GitHub annotation format (Roadmap 1.15).
//!
//! These tests verify the output formats for various finding scenarios:
//! - No findings (pass)
//! - Warnings only
//! - Errors only
//! - Mixed severity
//! - With suppressions
//! - Info only
//! - No column info

use diffguard_types::{
    CheckReceipt, DiffMeta, Finding, Severity, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
    CHECK_SCHEMA_V1,
};

// =========================================================================
// Helper Functions
// =========================================================================

fn test_finding(severity: Severity) -> Finding {
    Finding {
        rule_id: "test.rule".to_string(),
        severity,
        message: "Test message".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        column: Some(3),
        match_text: "match".to_string(),
        snippet: "let x = match;".to_string(),
    }
}

fn render_annotations(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Info => "notice",
                Severity::Warn => "warning",
                Severity::Error => "error",
            };
            format!(
                "::{level} file={path},line={line}::{rule} {msg}",
                level = level,
                path = f.path,
                line = f.line,
                rule = f.rule_id,
                msg = f.message
            )
        })
        .collect()
}

// =========================================================================
// JSON Receipt Snapshot Tests (Roadmap 1.14)
// =========================================================================

/// Snapshot test for JSON receipt with no findings (pass scenario).
/// Validates: Roadmap 1.14 - JSON receipt structure for clean pass
#[test]
fn snapshot_json_receipt_no_findings() {
    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 3,
            scope: diffguard_types::Scope::Added,
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
                suppressed: 0,
            },
            reasons: vec![],
        },
    };

    let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
    insta::assert_snapshot!(json);
}

/// Snapshot test for JSON receipt with warnings only (warn scenario).
/// Validates: Roadmap 1.14 - JSON receipt structure for warnings
#[test]
fn snapshot_json_receipt_warnings_only() {
    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "feature/branch".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: diffguard_types::Scope::Changed,
            files_scanned: 3,
            lines_scanned: 45,
        },
        findings: vec![
            Finding {
                rule_id: "rust.no_dbg".to_string(),
                severity: Severity::Warn,
                message: "Remove dbg! macro before merging".to_string(),
                path: "src/main.rs".to_string(),
                line: 15,
                column: Some(5),
                match_text: "dbg!".to_string(),
                snippet: "    dbg!(config);".to_string(),
            },
            Finding {
                rule_id: "js.no_console".to_string(),
                severity: Severity::Warn,
                message: "Remove console.log before merging".to_string(),
                path: "src/utils.ts".to_string(),
                line: 42,
                column: Some(3),
                match_text: "console.log".to_string(),
                snippet: "  console.log(\"debug\");".to_string(),
            },
        ],
        verdict: Verdict {
            status: VerdictStatus::Warn,
            counts: VerdictCounts {
                info: 0,
                warn: 2,
                error: 0,
                suppressed: 0,
            },
            reasons: vec!["2 warning(s)".to_string()],
        },
    };

    let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
    insta::assert_snapshot!(json);
}

/// Snapshot test for JSON receipt with errors only (fail scenario).
/// Validates: Roadmap 1.14 - JSON receipt structure for errors
#[test]
fn snapshot_json_receipt_errors_only() {
    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: diffguard_types::Scope::Added,
            files_scanned: 2,
            lines_scanned: 30,
        },
        findings: vec![
            Finding {
                rule_id: "security.no_hardcoded_secret".to_string(),
                severity: Severity::Error,
                message: "Hardcoded secret detected".to_string(),
                path: "src/config.rs".to_string(),
                line: 8,
                column: Some(15),
                match_text: "API_KEY".to_string(),
                snippet: "const API_KEY: &str = \"sk-secret123\";".to_string(),
            },
            Finding {
                rule_id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "Avoid unwrap in production code".to_string(),
                path: "src/lib.rs".to_string(),
                line: 25,
                column: Some(20),
                match_text: ".unwrap()".to_string(),
                snippet: "    let value = result.unwrap();".to_string(),
            },
        ],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 2,
                suppressed: 0,
            },
            reasons: vec!["2 error(s)".to_string()],
        },
    };

    let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
    insta::assert_snapshot!(json);
}

/// Snapshot test for JSON receipt with mixed severity findings.
/// Validates: Roadmap 1.14 - JSON receipt structure for mixed findings
#[test]
fn snapshot_json_receipt_mixed() {
    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: diffguard_types::Scope::Added,
            files_scanned: 1,
            lines_scanned: 2,
        },
        findings: vec![test_finding(Severity::Warn), test_finding(Severity::Error)],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 1,
                error: 1,
                suppressed: 0,
            },
            reasons: vec!["1 error(s)".to_string(), "1 warning(s)".to_string()],
        },
    };

    let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
    insta::assert_snapshot!(json);
}

/// Snapshot test for JSON receipt with suppressed findings.
/// Validates: Roadmap 1.14 - JSON receipt structure with suppressions
#[test]
fn snapshot_json_receipt_with_suppressions() {
    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: diffguard_types::Scope::Added,
            files_scanned: 4,
            lines_scanned: 80,
        },
        findings: vec![Finding {
            rule_id: "rust.no_dbg".to_string(),
            severity: Severity::Warn,
            message: "Remove dbg! macro before merging".to_string(),
            path: "src/debug.rs".to_string(),
            line: 10,
            column: Some(5),
            match_text: "dbg!".to_string(),
            snippet: "    dbg!(value);".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Warn,
            counts: VerdictCounts {
                info: 0,
                warn: 1,
                error: 0,
                suppressed: 3,
            },
            reasons: vec!["1 warning(s)".to_string()],
        },
    };

    let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
    insta::assert_snapshot!(json);
}

/// Snapshot test for JSON receipt with info-level findings.
/// Validates: Roadmap 1.14 - JSON receipt structure for info findings
#[test]
fn snapshot_json_receipt_info_only() {
    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: diffguard_types::Scope::Added,
            files_scanned: 1,
            lines_scanned: 15,
        },
        findings: vec![Finding {
            rule_id: "style.todo_comment".to_string(),
            severity: Severity::Info,
            message: "TODO comment found".to_string(),
            path: "src/lib.rs".to_string(),
            line: 5,
            column: Some(1),
            match_text: "TODO".to_string(),
            snippet: "// TODO: refactor this later".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Pass,
            counts: VerdictCounts {
                info: 1,
                warn: 0,
                error: 0,
                suppressed: 0,
            },
            reasons: vec![],
        },
    };

    let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
    insta::assert_snapshot!(json);
}

/// Snapshot test for JSON receipt with column=None (no column info).
/// Validates: Roadmap 1.14 - JSON receipt structure with null column
#[test]
fn snapshot_json_receipt_no_column() {
    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.1.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: diffguard_types::Scope::Added,
            files_scanned: 1,
            lines_scanned: 10,
        },
        findings: vec![Finding {
            rule_id: "python.no_print".to_string(),
            severity: Severity::Warn,
            message: "Remove print statement".to_string(),
            path: "scripts/deploy.py".to_string(),
            line: 12,
            column: None,
            match_text: "print(".to_string(),
            snippet: "print(\"Deploying...\")".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Warn,
            counts: VerdictCounts {
                info: 0,
                warn: 1,
                error: 0,
                suppressed: 0,
            },
            reasons: vec!["1 warning(s)".to_string()],
        },
    };

    let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
    insta::assert_snapshot!(json);
}

// =========================================================================
// GitHub Annotation Format Snapshot Tests (Roadmap 1.15)
// =========================================================================

/// Snapshot test for empty annotations (no findings).
/// Validates: Roadmap 1.15 - GitHub annotation format with no findings
#[test]
fn snapshot_annotations_empty() {
    let findings: Vec<Finding> = vec![];
    let annotations = render_annotations(&findings);
    insta::assert_snapshot!(annotations.join("\n"));
}

/// Snapshot test for annotations with info-level finding only.
/// Validates: Roadmap 1.15 - GitHub annotation format for notices
#[test]
fn snapshot_annotations_info_only() {
    let findings = vec![Finding {
        rule_id: "style.todo_comment".to_string(),
        severity: Severity::Info,
        message: "TODO comment found".to_string(),
        path: "src/lib.rs".to_string(),
        line: 5,
        column: Some(1),
        match_text: "TODO".to_string(),
        snippet: "// TODO: refactor this later".to_string(),
    }];
    let annotations = render_annotations(&findings);
    insta::assert_snapshot!(annotations.join("\n"));
}

/// Snapshot test for annotations with warning-level finding only.
/// Validates: Roadmap 1.15 - GitHub annotation format for warnings
#[test]
fn snapshot_annotations_warning_only() {
    let findings = vec![Finding {
        rule_id: "rust.no_dbg".to_string(),
        severity: Severity::Warn,
        message: "Remove dbg! macro before merging".to_string(),
        path: "src/main.rs".to_string(),
        line: 15,
        column: Some(5),
        match_text: "dbg!".to_string(),
        snippet: "    dbg!(config);".to_string(),
    }];
    let annotations = render_annotations(&findings);
    insta::assert_snapshot!(annotations.join("\n"));
}

/// Snapshot test for annotations with error-level finding only.
/// Validates: Roadmap 1.15 - GitHub annotation format for errors
#[test]
fn snapshot_annotations_error_only() {
    let findings = vec![Finding {
        rule_id: "security.no_hardcoded_secret".to_string(),
        severity: Severity::Error,
        message: "Hardcoded secret detected".to_string(),
        path: "src/config.rs".to_string(),
        line: 8,
        column: Some(15),
        match_text: "API_KEY".to_string(),
        snippet: "const API_KEY: &str = \"sk-secret123\";".to_string(),
    }];
    let annotations = render_annotations(&findings);
    insta::assert_snapshot!(annotations.join("\n"));
}

/// Snapshot test for annotations with all three severities.
/// Validates: Roadmap 1.15 - GitHub annotation format for mixed severities
#[test]
fn snapshot_annotations_all_severities() {
    let findings = vec![
        test_finding(Severity::Info),
        test_finding(Severity::Warn),
        test_finding(Severity::Error),
    ];
    let annotations = render_annotations(&findings);
    insta::assert_snapshot!(annotations.join("\n"));
}

/// Snapshot test for annotations with multiple findings across files.
/// Validates: Roadmap 1.15 - GitHub annotation format for multiple files
#[test]
fn snapshot_annotations_multiple_files() {
    let findings = vec![
        Finding {
            rule_id: "rust.no_unwrap".to_string(),
            severity: Severity::Error,
            message: "Avoid unwrap in production code".to_string(),
            path: "src/lib.rs".to_string(),
            line: 25,
            column: Some(20),
            match_text: ".unwrap()".to_string(),
            snippet: "    let value = result.unwrap();".to_string(),
        },
        Finding {
            rule_id: "rust.no_dbg".to_string(),
            severity: Severity::Warn,
            message: "Remove dbg! macro before merging".to_string(),
            path: "src/main.rs".to_string(),
            line: 42,
            column: Some(3),
            match_text: "dbg!".to_string(),
            snippet: "  dbg!(args);".to_string(),
        },
        Finding {
            rule_id: "python.no_print".to_string(),
            severity: Severity::Warn,
            message: "Remove print statement".to_string(),
            path: "scripts/deploy.py".to_string(),
            line: 8,
            column: None,
            match_text: "print(".to_string(),
            snippet: "print(\"Starting deployment\")".to_string(),
        },
    ];
    let annotations = render_annotations(&findings);
    insta::assert_snapshot!(annotations.join("\n"));
}

/// Snapshot test for annotations with special characters in message.
/// Validates: Roadmap 1.15 - GitHub annotation format handles special chars
#[test]
fn snapshot_annotations_special_characters() {
    let findings = vec![Finding {
        rule_id: "style.no_fixme".to_string(),
        severity: Severity::Info,
        message: "FIXME comment: \"fix this <urgent>\" needs attention".to_string(),
        path: "src/parser.rs".to_string(),
        line: 100,
        column: Some(5),
        match_text: "FIXME".to_string(),
        snippet: "// FIXME: \"fix this <urgent>\" - handle edge case".to_string(),
    }];
    let annotations = render_annotations(&findings);
    insta::assert_snapshot!(annotations.join("\n"));
}

/// Snapshot test for annotations with deeply nested path.
/// Validates: Roadmap 1.15 - GitHub annotation format with nested paths
#[test]
fn snapshot_annotations_nested_path() {
    let findings = vec![Finding {
        rule_id: "go.no_panic".to_string(),
        severity: Severity::Error,
        message: "Avoid panic in library code".to_string(),
        path: "internal/pkg/handlers/auth/middleware/rate_limiter.go".to_string(),
        line: 157,
        column: Some(9),
        match_text: "panic(".to_string(),
        snippet: "\t\tpanic(\"rate limit exceeded\")".to_string(),
    }];
    let annotations = render_annotations(&findings);
    insta::assert_snapshot!(annotations.join("\n"));
}
