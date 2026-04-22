//! Snapshot tests for `evaluate_lines*` functions output structure.
//!
//! These tests capture the baseline output of `evaluate_lines`,
//! `evaluate_lines_with_overrides`, and `evaluate_lines_with_overrides_and_language`
//! so that any refactoring changes are immediately detected.
//!
//! The Evaluation struct is serialized in a deterministic format for snapshot comparison.

use diffguard_domain::{
    Evaluation, InputLine, evaluate_lines, evaluate_lines_with_overrides_and_language,
    rules::compile_rules,
};
use diffguard_types::{MatchMode, RuleConfig, Severity};

/// Helper to create a RuleConfig for testing
#[allow(clippy::too_many_arguments)]
fn test_rule(
    id: &str,
    severity: Severity,
    message: &str,
    languages: Vec<&str>,
    patterns: Vec<&str>,
    paths: Vec<&str>,
    exclude_paths: Vec<&str>,
    ignore_comments: bool,
    ignore_strings: bool,
) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity,
        message: message.to_string(),
        languages: languages.into_iter().map(|s| s.to_string()).collect(),
        patterns: patterns.into_iter().map(|s| s.to_string()).collect(),
        paths: paths.into_iter().map(|s| s.to_string()).collect(),
        exclude_paths: exclude_paths.into_iter().map(|s| s.to_string()).collect(),
        ignore_comments,
        ignore_strings,
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

/// Helper to format Evaluation for snapshot in a deterministic way.
/// Sorts rule_hits by rule_id for consistent ordering.
fn format_evaluation(eval: &Evaluation) -> String {
    let mut output = String::new();
    output.push_str("Evaluation {\n");
    output.push_str(&format!("  findings: {} items\n", eval.findings.len()));
    for (i, f) in eval.findings.iter().enumerate() {
        output.push_str(&format!(
            "    [{}] rule_id={}, severity={:?}, message={}, path={}, line={}, column={:?}, match_text={:?}, snippet={:?}\n",
            i, f.rule_id, f.severity, f.message, f.path, f.line, f.column, f.match_text, f.snippet
        ));
    }
    output.push_str(&format!(
        "  counts: VerdictCounts {{ info: {}, warn: {}, error: {}, suppressed: {} }}\n",
        eval.counts.info, eval.counts.warn, eval.counts.error, eval.counts.suppressed
    ));
    output.push_str(&format!(
        "  truncated_findings: {}\n",
        eval.truncated_findings
    ));
    output.push_str(&format!("  files_scanned: {}\n", eval.files_scanned));
    output.push_str(&format!("  lines_scanned: {}\n", eval.lines_scanned));
    output.push_str(&format!(
        "  rule_hits: {} items (sorted by rule_id)\n",
        eval.rule_hits.len()
    ));
    // rule_hits are already sorted by rule_id due to BTreeMap
    for rh in &eval.rule_hits {
        output.push_str(&format!(
            "    RuleHitStat {{ rule_id={}, total={}, emitted={}, suppressed={}, info={}, warn={}, error={} }}\n",
            rh.rule_id, rh.total, rh.emitted, rh.suppressed, rh.info, rh.warn, rh.error
        ));
    }
    output.push_str("}\n");
    output
}

// =============================================================================
// Snapshot Tests for evaluate_lines
// =============================================================================

/// Snapshot test: empty input produces empty evaluation.
#[test]
fn test_evaluate_lines_empty_input() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[test_rule(
        "test_rule",
        Severity::Warn,
        "test message",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines(vec![], &rules, 100);
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_lines_empty_input", snapshot);
}

/// Snapshot test: single line with no match.
#[test]
fn test_evaluate_lines_no_match() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[test_rule(
        "test_rule",
        Severity::Warn,
        "test message",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines(
        [InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: "some content".to_string(),
        }],
        &rules,
        100,
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_lines_no_match", snapshot);
}

/// Snapshot test: single line with pattern match.
#[test]
fn test_evaluate_lines_single_match() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[test_rule(
        "test_rule",
        Severity::Warn,
        "test message",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines(
        [InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: "this has pattern in it".to_string(),
        }],
        &rules,
        100,
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_lines_single_match", snapshot);
}

/// Snapshot test: multiple rules matching same line.
#[test]
fn test_evaluate_lines_multiple_rules() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[
        test_rule(
            "rule_one",
            Severity::Info,
            "first rule message",
            vec![],
            vec!["pattern"],
            vec![],
            vec![],
            false,
            false,
        ),
        test_rule(
            "rule_two",
            Severity::Error,
            "second rule message",
            vec![],
            vec!["pattern"],
            vec![],
            vec![],
            false,
            false,
        ),
    ])
    .unwrap();

    let eval = evaluate_lines(
        [InputLine {
            path: "test.txt".to_string(),
            line: 1,
            content: "this has pattern in it".to_string(),
        }],
        &rules,
        100,
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_lines_multiple_rules", snapshot);
}

/// Snapshot test: max_findings truncation.
#[test]
fn test_evaluate_lines_max_findings_truncation() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[test_rule(
        "test_rule",
        Severity::Warn,
        "test message",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines(
        [
            InputLine {
                path: "a.txt".to_string(),
                line: 1,
                content: "pattern".to_string(),
            },
            InputLine {
                path: "b.txt".to_string(),
                line: 1,
                content: "pattern".to_string(),
            },
            InputLine {
                path: "c.txt".to_string(),
                line: 1,
                content: "pattern".to_string(),
            },
        ],
        &rules,
        2, // max_findings = 2, but we have 3 matches
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_lines_max_findings_truncation", snapshot);
}

/// Snapshot test: multiple files scanned.
#[test]
fn test_evaluate_lines_multiple_files() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[test_rule(
        "test_rule",
        Severity::Warn,
        "test message",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines(
        [
            InputLine {
                path: "a.txt".to_string(),
                line: 1,
                content: "pattern".to_string(),
            },
            InputLine {
                path: "a.txt".to_string(),
                line: 2,
                content: "pattern".to_string(),
            },
            InputLine {
                path: "b.txt".to_string(),
                line: 1,
                content: "pattern".to_string(),
            },
            InputLine {
                path: "c.txt".to_string(),
                line: 1,
                content: "no match".to_string(),
            },
        ],
        &rules,
        100,
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_lines_multiple_files", snapshot);
}

// =============================================================================
// Snapshot Tests for evaluate_lines_with_overrides_and_language
// =============================================================================

/// Snapshot test: forced language affects preprocessing.
#[test]
fn test_evaluate_with_forced_language_rust() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[test_rule(
        "test_rule",
        Severity::Warn,
        "test message",
        vec!["rust"],
        vec!["TODO"],
        vec![],
        vec![],
        true,
        false,
    )])
    .unwrap();

    // In Rust, TODO in a comment should be ignored (ignore_comments=true)
    // but TODO in a string should still match
    let eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "script.txt".to_string(), // .txt has unknown language
            line: 1,
            content: "// TODO: fix this".to_string(),
        }],
        &rules,
        100,
        None,
        Some("rust"),
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_with_forced_language_rust_comment", snapshot);
}

/// Snapshot test: force language on line that would normally be unknown.
#[test]
fn test_evaluate_with_forced_language_rust_string() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[test_rule(
        "test_rule",
        Severity::Warn,
        "test message",
        vec!["rust"],
        vec!["TODO"],
        vec![],
        vec![],
        false,
        true,
    )])
    .unwrap();

    // With ignore_strings=true, TODO in string should be ignored
    let eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "script.txt".to_string(),
            line: 1,
            content: r#"let msg = "TODO: fix this";"#.to_string(),
        }],
        &rules,
        100,
        None,
        Some("rust"),
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_with_forced_language_rust_string", snapshot);
}

/// Snapshot test: multiple rules with different severity levels.
#[test]
fn test_evaluate_mixed_severities() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[
        test_rule(
            "info_rule",
            Severity::Info,
            "info message",
            vec![],
            vec!["info_pattern"],
            vec![],
            vec![],
            false,
            false,
        ),
        test_rule(
            "warn_rule",
            Severity::Warn,
            "warn message",
            vec![],
            vec!["warn_pattern"],
            vec![],
            vec![],
            false,
            false,
        ),
        test_rule(
            "error_rule",
            Severity::Error,
            "error message",
            vec![],
            vec!["error_pattern"],
            vec![],
            vec![],
            false,
            false,
        ),
    ])
    .unwrap();

    let eval = evaluate_lines(
        [
            InputLine {
                path: "test.txt".to_string(),
                line: 1,
                content: "info_pattern".to_string(),
            },
            InputLine {
                path: "test.txt".to_string(),
                line: 2,
                content: "warn_pattern".to_string(),
            },
            InputLine {
                path: "test.txt".to_string(),
                line: 3,
                content: "error_pattern".to_string(),
            },
        ],
        &rules,
        100,
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_mixed_severities", snapshot);
}

/// Snapshot test: rule_hits aggregation for multiple matches.
#[test]
fn test_evaluate_rule_hits_aggregation() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[
        test_rule(
            "rule_a",
            Severity::Warn,
            "message a",
            vec![],
            vec!["match_a"],
            vec![],
            vec![],
            false,
            false,
        ),
        test_rule(
            "rule_b",
            Severity::Info,
            "message b",
            vec![],
            vec!["match_b"],
            vec![],
            vec![],
            false,
            false,
        ),
    ])
    .unwrap();

    let eval = evaluate_lines(
        [
            // rule_a matches twice, rule_b matches once
            InputLine {
                path: "a.txt".to_string(),
                line: 1,
                content: "match_a and match_b".to_string(),
            },
            InputLine {
                path: "a.txt".to_string(),
                line: 2,
                content: "match_a".to_string(),
            },
        ],
        &rules,
        100,
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_rule_hits_aggregation", snapshot);
}

/// Snapshot test: language detection from file extension.
#[test]
fn test_evaluate_language_detection() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[test_rule(
        "test_rule",
        Severity::Warn,
        "test message",
        vec!["python"],
        vec!["# TODO"],
        vec![],
        vec![],
        true,
        false,
    )])
    .unwrap();

    // Python file should detect language and apply ignore_comments
    let eval = evaluate_lines(
        [InputLine {
            path: "script.py".to_string(),
            line: 1,
            content: "# TODO: fix this".to_string(),
        }],
        &rules,
        100,
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_language_detection_comment", snapshot);
}

/// Snapshot test: same pattern in non-Python file (unknown language) should match.
#[test]
fn test_evaluate_unknown_language_no_preprocessing() {
    use insta::assert_snapshot;

    let rules = compile_rules(&[test_rule(
        "test_rule",
        Severity::Warn,
        "test message",
        vec!["python"],
        vec!["# TODO"],
        vec![],
        vec![],
        true,
        false,
    )])
    .unwrap();

    // Unknown file should not apply Python comment preprocessing
    let eval = evaluate_lines(
        [InputLine {
            path: "script.txt".to_string(),
            line: 1,
            content: "# TODO: fix this".to_string(),
        }],
        &rules,
        100,
    );
    let snapshot = format_evaluation(&eval);
    assert_snapshot!("evaluate_unknown_language_no_preprocessing", snapshot);
}
