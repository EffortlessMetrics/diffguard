//! Snapshot tests for diffguard-types JSON serialization baselines.
//!
//! These tests capture the serialization format of key types to detect
//! any accidental output changes.

use diffguard_types::*;

/// Snapshot test: CheckReceipt minimal serialization
/// Covers: tool, diff, findings, verdict, timing fields
#[test]
fn snapshot_check_receipt_minimal() {
    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 42,
            lines_scanned: 1337,
        },
        findings: vec![Finding {
            rule_id: "rust.no_eval".to_string(),
            severity: Severity::Error,
            message: "Avoid eval - potential code injection".to_string(),
            path: "src/main.rs".to_string(),
            line: 42,
            column: Some(5),
            match_text: "eval(".to_string(),
            snippet: "    let result = eval(user_input);".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
                suppressed: 0,
            },
            reasons: vec![REASON_TOOL_ERROR.to_string()],
        },
        timing: None,
    };

    let json = serde_json::to_string_pretty(&receipt).unwrap();
    let expected = include_str!("./snapshots/check_receipt_minimal.json");
    assert_eq!(json.trim(), expected.trim());
}

/// Snapshot test: ConfigFile minimal serialization
/// Covers: defaults, rule array, all field types
#[test]
fn snapshot_config_file_minimal() {
    let config = ConfigFile {
        includes: vec![],
        defaults: Defaults::default(),
        rule: vec![RuleConfig {
            id: "rust.no_eval".to_string(),
            severity: Severity::Error,
            message: "Avoid eval".to_string(),
            description: String::new(),
            languages: vec!["rust".to_string()],
            patterns: vec![r"\beval\s*\(".to_string()],
            paths: vec![],
            exclude_paths: vec!["*.test.rs".to_string()],
            ignore_comments: true,
            ignore_strings: false,
            match_mode: Default::default(),
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: None,
            url: None,
            tags: vec!["security".to_string(), "injection".to_string()],
            test_cases: vec![],
        }],
    };

    let json = serde_json::to_string_pretty(&config).unwrap();
    let expected = include_str!("./snapshots/config_file_minimal.json");
    assert_eq!(json.trim(), expected.trim());
}

/// Snapshot test: Finding serialization
/// Covers: all Finding fields including optional column
#[test]
fn snapshot_finding_example() {
    let finding = Finding {
        rule_id: "rust.no_eval".to_string(),
        severity: Severity::Error,
        message: "Avoid eval - potential code injection".to_string(),
        path: "src/main.rs".to_string(),
        line: 42,
        column: Some(5),
        match_text: "eval(".to_string(),
        snippet: "    let result = eval(user_input);".to_string(),
    };

    let json = serde_json::to_string_pretty(&finding).unwrap();
    let expected = include_str!("./snapshots/finding_example.json");
    assert_eq!(json.trim(), expected.trim());
}

/// Snapshot test: Verdict pass serialization
/// Covers: VerdictStatus::Pass with populated counts
#[test]
fn snapshot_verdict_pass() {
    let verdict = Verdict {
        status: VerdictStatus::Pass,
        counts: VerdictCounts {
            info: 5,
            warn: 2,
            error: 0,
            suppressed: 0,
        },
        reasons: vec![],
    };

    let json = serde_json::to_string_pretty(&verdict).unwrap();
    let expected = include_str!("./snapshots/verdict_pass.json");
    assert_eq!(json.trim(), expected.trim());
}

/// Snapshot test: Verdict fail serialization with tool_error reason
/// Covers: VerdictStatus::Fail with error counts and tool_error reason
#[test]
fn snapshot_verdict_fail() {
    let verdict = Verdict {
        status: VerdictStatus::Fail,
        counts: VerdictCounts {
            info: 0,
            warn: 1,
            error: 3,
            suppressed: 0,
        },
        reasons: vec![REASON_TOOL_ERROR.to_string()],
    };

    let json = serde_json::to_string_pretty(&verdict).unwrap();
    let expected = include_str!("./snapshots/verdict_fail.json");
    assert_eq!(json.trim(), expected.trim());
}

/// Snapshot test: Verdict skip serialization with missing_base reason
/// Covers: VerdictStatus::Skip with missing_base reason (the fix in this work item)
#[test]
fn snapshot_verdict_skip() {
    let verdict = Verdict {
        status: VerdictStatus::Skip,
        counts: VerdictCounts::default(),
        reasons: vec![REASON_MISSING_BASE.to_string()],
    };

    let json = serde_json::to_string_pretty(&verdict).unwrap();
    let expected = include_str!("./snapshots/verdict_skip.json");
    assert_eq!(json.trim(), expected.trim());
}

/// Snapshot test: Defaults serialization
/// Covers: all Defaults fields
#[test]
fn snapshot_defaults_example() {
    let defaults = Defaults {
        base: Some("origin/main".to_string()),
        head: Some("HEAD".to_string()),
        scope: Some(Scope::Added),
        fail_on: Some(FailOn::Error),
        max_findings: Some(200),
        diff_context: Some(0),
        ignore_comments: None,
        ignore_strings: None,
    };

    let json = serde_json::to_string_pretty(&defaults).unwrap();
    let expected = include_str!("./snapshots/defaults_example.json");
    assert_eq!(json.trim(), expected.trim());
}
