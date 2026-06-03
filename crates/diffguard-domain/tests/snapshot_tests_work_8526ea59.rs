//! Snapshot tests for `evaluate_lines()` output baselines.
//!
//! These snapshots capture the deterministic output of `evaluate_lines` for various
//! input scenarios to detect any output changes, especially in the column calculation
//! and the byte_to_column usize→u32 conversion.
//!
//! The fix at evaluate.rs:298 ensures that when byte_to_column returns a column
//! value that exceeds u32::MAX, the column is None rather than silently truncating.
//!
//! These snapshots verify:
//! - Normal evaluation with column calculation
//! - Empty content handling
//! - Multiple rules matching same line
//! - VerdictCounts aggregation
//! - RuleHitStat aggregation
//! - Files scanned count

use diffguard_domain::{InputLine, compile_rules, evaluate_lines};
use diffguard_types::{MatchMode, RuleConfig, Severity};

/// Helper to create a RuleConfig for testing
fn make_rule(id: &str, severity: Severity, pattern: &str) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity,
        message: format!("found: {}", pattern),
        languages: vec![],
        patterns: vec![pattern.to_string()],
        paths: vec![],
        exclude_paths: vec![],
        ignore_comments: false,
        ignore_strings: false,
        match_mode: MatchMode::Any,
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
        tags: vec![],
        test_cases: vec![],
    }
}

/// Helper to format an Evaluation for snapshot comparison
/// Uses debug formatting to capture all fields
fn format_evaluation(eval: &diffguard_domain::Evaluation) -> String {
    format!(
        "=== Evaluation ===\n\
         findings_count: {}\n\
         truncated_findings: {}\n\
         files_scanned: {}\n\
         lines_scanned: {}\n\
         \n\
         === Counts ===\n\
         info: {}, warn: {}, error: {}, suppressed: {}\n\
         \n\
         === Findings ===\n\
         {}\n\
         \n\
         === Rule Hits ===\n\
         {}",
        eval.findings.len(),
        eval.truncated_findings,
        eval.files_scanned,
        eval.lines_scanned,
        eval.counts.info,
        eval.counts.warn,
        eval.counts.error,
        eval.counts.suppressed,
        eval.findings
            .iter()
            .map(|f| format!(
                "- rule_id: {}, severity: {:?}, message: {}, path: {}, line: {}, column: {:?}, match_text: {:?}, snippet: {:?}",
                f.rule_id, f.severity, f.message, f.path, f.line, f.column, f.match_text, f.snippet
            ))
            .collect::<Vec<_>>()
            .join("\n"),
        eval.rule_hits
            .iter()
            .map(|r| format!(
                "- rule_id: {}, total: {}, emitted: {}, suppressed: {}, info: {}, warn: {}, error: {}",
                r.rule_id, r.total, r.emitted, r.suppressed, r.info, r.warn, r.error
            ))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

// ============================================================================
// Snapshot tests for evaluate_lines output
// ============================================================================

/// Snapshot test: Single rule matching at start of line
/// Verifies column calculation for match at position 0
#[test]
fn snapshot_evaluate_match_at_column_one() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "abc")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "abc def".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_match_at_column_one", snapshot);
}

/// Snapshot test: Single rule matching in middle of line
/// Verifies column calculation for non-zero position
#[test]
fn snapshot_evaluate_match_in_middle() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "def")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "abc def ghi".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_match_in_middle", snapshot);
}

/// Snapshot test: Empty content produces no findings
/// Verifies graceful handling of empty input
#[test]
fn snapshot_evaluate_empty_content() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "pattern")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: String::new(),
    };

    let eval = evaluate_lines([line], &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_empty_content", snapshot);
}

/// Snapshot test: Whitespace-only content produces no findings
/// Verifies no spurious matches on whitespace
#[test]
fn snapshot_evaluate_whitespace_only() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "abc")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "      ".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_whitespace_only", snapshot);
}

/// Snapshot test: Multiple rules matching same line
/// Verifies multiple findings are produced and counts are correct
#[test]
fn snapshot_evaluate_multiple_rules_same_line() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[
        make_rule("rule1", Severity::Error, "abc"),
        make_rule("rule2", Severity::Warn, "def"),
    ])
    .unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "abcdef".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_multiple_rules_same_line", snapshot);
}

/// Snapshot test: Tab character column calculation
/// Verifies tabs count as single character in column
#[test]
fn snapshot_evaluate_tab_column() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "b")]).unwrap();

    // "a\tb" is 3 bytes, 3 chars. 'b' is at column 3.
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "a\tb".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_tab_column", snapshot);
}

/// Snapshot test: Emoji in content
/// Verifies multi-byte UTF-8 characters count correctly
#[test]
fn snapshot_evaluate_emoji_column() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "👍")]).unwrap();

    // "a👍b" is 6 bytes, 3 chars. '👍' is at column 2.
    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "a👍b".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_emoji_column", snapshot);
}

/// Snapshot test: Multiple files scanned
/// Verifies files_scanned count is correct
#[test]
fn snapshot_evaluate_multiple_files() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "error")]).unwrap();

    let lines = [
        InputLine {
            path: "file1.rs".to_string(),
            line: 1,
            content: "error here".to_string(),
        },
        InputLine {
            path: "file2.rs".to_string(),
            line: 1,
            content: "also error".to_string(),
        },
        InputLine {
            path: "file1.rs".to_string(),
            line: 2,
            content: "another error".to_string(),
        },
    ];

    let eval = evaluate_lines(lines, &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_multiple_files", snapshot);
}

/// Snapshot test: Max findings truncation
/// Verifies truncated_findings count when limit is exceeded
#[test]
fn snapshot_evaluate_max_findings_truncation() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "error")]).unwrap();

    let lines: Vec<_> = (0..10)
        .map(|i| InputLine {
            path: format!("file{}.rs", i),
            line: 1,
            content: "error on this line".to_string(),
        })
        .collect();

    // Limit to 3 findings
    let eval = evaluate_lines(lines, &rules, 3);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_max_findings_truncation", snapshot);
}

/// Snapshot test: No matches produces empty findings
/// Verifies all-zero counts when no rules match
#[test]
fn snapshot_evaluate_no_matches() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "xyz")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "abc def ghi".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_no_matches", snapshot);
}

/// Snapshot test: Zero max_findings produces counts but no findings
/// Verifies evaluation still works when max_findings is 0
#[test]
fn snapshot_evaluate_zero_max_findings() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "error")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "error here".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 0);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_zero_max_findings", snapshot);
}

/// Snapshot test: Single char line with match
/// Verifies column 1 for single character match
#[test]
fn snapshot_evaluate_single_char_match() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[make_rule("test.rule", Severity::Error, "x")]).unwrap();

    let line = InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "x".to_string(),
    };

    let eval = evaluate_lines([line], &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_single_char_match", snapshot);
}
