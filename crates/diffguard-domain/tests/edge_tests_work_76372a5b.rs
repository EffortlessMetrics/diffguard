//! Edge case tests for work-76372a5b: Refactor `evaluate_lines_with_overrides_and_language`
//!
//! These tests stress the implementation with boundary values, empty inputs,
//! special characters, Unicode content, and other edge cases not covered
//! by the red tests.

use diffguard_domain::{
    InputLine, evaluate_lines, evaluate_lines_with_overrides_and_language, rules::compile_rules,
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

// =============================================================================
// Empty and Boundary Inputs
// =============================================================================

/// Test that empty input produces correct empty result.
#[test]
fn test_empty_input_produces_empty_evaluation() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Warn,
        "msg",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines(vec![], &rules, 100);

    assert_eq!(
        eval.findings.len(),
        0,
        "Empty input should produce no findings"
    );
    assert_eq!(
        eval.counts.warn, 0,
        "Empty input should produce no warnings"
    );
    assert_eq!(eval.counts.error, 0, "Empty input should produce no errors");
    assert_eq!(eval.counts.info, 0, "Empty input should produce no info");
    assert_eq!(
        eval.counts.suppressed, 0,
        "Empty input should produce no suppressed"
    );
    assert_eq!(
        eval.truncated_findings, 0,
        "Empty input should produce no truncated"
    );
    assert_eq!(
        eval.lines_scanned, 0,
        "Empty input should have 0 lines scanned"
    );
    assert_eq!(
        eval.files_scanned, 0,
        "Empty input should have 0 files scanned"
    );
    assert!(
        eval.rule_hits.is_empty(),
        "Empty input should have no rule hits"
    );
}

/// Test single line, single file - boundary case.
#[test]
fn test_single_line_single_file() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Warn,
        "msg",
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
            path: "a.txt".to_string(),
            line: 1,
            content: "pattern found here".to_string(),
        }],
        &rules,
        100,
    );

    assert_eq!(eval.findings.len(), 1, "Should find 1 finding");
    assert_eq!(eval.counts.warn, 1, "Should have 1 warning");
    assert_eq!(eval.lines_scanned, 1, "Should scan 1 line");
    assert_eq!(eval.files_scanned, 1, "Should scan 1 file");
}

/// Test max_findings of zero should emit nothing but still count.
#[test]
fn test_max_findings_zero_still_counts_matches() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Warn,
        "msg",
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
                line: 2,
                content: "pattern".to_string(),
            },
        ],
        &rules,
        0, // max_findings = 0
    );

    assert!(
        eval.findings.is_empty(),
        "Zero max should produce no findings"
    );
    assert_eq!(eval.counts.warn, 2, "Counts should still track all matches");
    assert_eq!(eval.truncated_findings, 2, "Truncated should be 2");
}

// =============================================================================
// Counters and Statistics Accuracy
// =============================================================================

/// Test that files_scanned counts distinct files correctly.
#[test]
fn test_files_scanned_counts_distinct_files() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Warn,
        "msg",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    // 3 files with multiple lines each
    let eval = evaluate_lines(
        [
            InputLine {
                path: "a.txt".to_string(),
                line: 1,
                content: "line".to_string(),
            },
            InputLine {
                path: "a.txt".to_string(),
                line: 2,
                content: "line".to_string(),
            },
            InputLine {
                path: "b.txt".to_string(),
                line: 1,
                content: "line".to_string(),
            },
            InputLine {
                path: "c.txt".to_string(),
                line: 1,
                content: "line".to_string(),
            },
        ],
        &rules,
        100,
    );

    assert_eq!(eval.files_scanned, 3, "Should count 3 distinct files");
}

/// Test that lines_scanned is accurate.
#[test]
fn test_lines_scanned_accurate() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Warn,
        "msg",
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
                content: "no match".to_string(),
            },
            InputLine {
                path: "b.txt".to_string(),
                line: 2,
                content: "no match".to_string(),
            },
            InputLine {
                path: "c.txt".to_string(),
                line: 3,
                content: "no match".to_string(),
            },
        ],
        &rules,
        100,
    );

    assert_eq!(eval.lines_scanned, 3, "Should track 3 lines scanned");
}

/// Test that rule_hits contains rules that have some activity.
/// Rules with no matches at all are not added to rule_hits (this is the actual behavior).
#[test]
fn test_rule_hits_contains_active_rules() {
    let rules = compile_rules(&[
        test_rule(
            "unused_rule",
            Severity::Warn,
            "msg",
            vec![],
            vec!["pattern"],
            vec![],
            vec![],
            false,
            false,
        ),
        test_rule(
            "used_rule",
            Severity::Error,
            "msg",
            vec![],
            vec!["match"],
            vec![],
            vec![],
            false,
            false,
        ),
    ])
    .unwrap();

    // Only "used_rule" matches
    let eval = evaluate_lines(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: "match".to_string(),
        }],
        &rules,
        100,
    );

    // Only used_rule should be in rule_hits
    let used_hit = eval
        .rule_hits
        .iter()
        .find(|r| r.rule_id == "used_rule")
        .expect("used_rule should be in rule_hits");
    assert_eq!(used_hit.total, 1);
    assert_eq!(used_hit.emitted, 1);

    // unused_rule should NOT be in rule_hits (no matches = not tracked)
    assert!(
        eval.rule_hits.iter().all(|r| r.rule_id != "unused_rule"),
        "Unused rule should not be in rule_hits"
    );
}

// =============================================================================
// Unicode and Special Characters
// =============================================================================

/// Test handling of Unicode content in lines.
#[test]
fn test_unicode_content_handled() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Warn,
        "msg",
        vec![],
        vec!["привет"], // "hello" in Russian
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: "привет мир".to_string(), // "hello world"
        }],
        &rules,
        100,
    );

    assert_eq!(eval.counts.warn, 1, "Should match Unicode pattern");
    assert_eq!(eval.findings.len(), 1);
}

/// Test handling of emoji in content.
#[test]
fn test_emoji_in_content() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Warn,
        "msg",
        vec![],
        vec![r"🔥"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: "test 🔥 warning".to_string(),
        }],
        &rules,
        100,
    );

    assert_eq!(eval.counts.warn, 1, "Should match emoji");
}

/// Test handling of paths with spaces.
#[test]
fn test_path_with_spaces() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Warn,
        "msg",
        vec![],
        vec!["pattern"],
        vec!["**/*"],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines(
        [InputLine {
            path: "src/my file.txt".to_string(),
            line: 1,
            content: "pattern found".to_string(),
        }],
        &rules,
        100,
    );

    assert_eq!(eval.findings.len(), 1, "Should handle path with spaces");
    assert_eq!(eval.findings[0].path, "src/my file.txt");
}

// =============================================================================
// Suppression Edge Cases
// =============================================================================

/// Test suppression with wildcard.
#[test]
fn test_suppression_wildcard_ignores_all() {
    let rules = compile_rules(&[
        test_rule(
            "rule.one",
            Severity::Warn,
            "msg1",
            vec![],
            vec!["pattern"],
            vec![],
            vec![],
            false,
            false,
        ),
        test_rule(
            "rule.two",
            Severity::Error,
            "msg2",
            vec![],
            vec!["pattern"],
            vec![],
            vec![],
            false,
            false,
        ),
    ])
    .unwrap();

    let eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: "pattern // diffguard: ignore *".to_string(),
        }],
        &rules,
        100,
        None,
        None,
    );

    assert_eq!(eval.counts.warn, 0);
    assert_eq!(eval.counts.error, 0);
    assert_eq!(eval.counts.suppressed, 2, "Both rules should be suppressed");
    assert!(eval.findings.is_empty());
}

/// Test suppression with ignore-all.
#[test]
fn test_suppression_ignore_all() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Error,
        "msg",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: "pattern // diffguard: ignore-all".to_string(),
        }],
        &rules,
        100,
        None,
        None,
    );

    assert_eq!(eval.counts.error, 0);
    assert_eq!(eval.counts.suppressed, 1);
    assert!(eval.findings.is_empty());
}

/// Test ignore-next-line suppression.
#[test]
fn test_suppression_ignore_next_line() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Error,
        "msg",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines_with_overrides_and_language(
        [
            InputLine {
                path: "a.txt".to_string(),
                line: 1,
                content: "// diffguard: ignore-next-line rule".to_string(),
            },
            InputLine {
                path: "a.txt".to_string(),
                line: 2,
                content: "pattern".to_string(),
            },
            InputLine {
                path: "a.txt".to_string(),
                line: 3,
                content: "pattern".to_string(),
            },
        ],
        &rules,
        100,
        None,
        None,
    );

    // Line 2 should be suppressed, line 3 should not
    assert_eq!(eval.counts.error, 1, "Only line 3 should fire");
    assert_eq!(eval.counts.suppressed, 1, "Line 2 should be suppressed");
    assert_eq!(eval.findings.len(), 1);
    assert_eq!(eval.findings[0].line, 3);
}

// =============================================================================
// Language Detection Edge Cases
// =============================================================================

/// Test force_language case insensitivity.
#[test]
fn test_force_language_case_insensitive() {
    let rules = compile_rules(&[test_rule(
        "rust.no_unwrap",
        Severity::Error,
        "no unwrap",
        vec!["rust"],
        vec![r"\.unwrap\("],
        vec![],
        vec![],
        true,
        true,
    )])
    .unwrap();

    let lines = [InputLine {
        path: "src/custom.ext".to_string(),
        line: 1,
        content: "let x = y.unwrap();".to_string(),
    }];

    // Uppercase should work the same as lowercase
    let eval_upper =
        evaluate_lines_with_overrides_and_language(lines.clone(), &rules, 100, None, Some("RUST"));

    let eval_lower =
        evaluate_lines_with_overrides_and_language(lines.clone(), &rules, 100, None, Some("rust"));

    assert_eq!(
        eval_upper.counts.error, eval_lower.counts.error,
        "force_language should be case-insensitive"
    );
}

/// Test language detection for various extensions.
#[test]
fn test_language_detection_js_ts() {
    let rules = compile_rules(&[test_rule(
        "js.no_console",
        Severity::Warn,
        "no console",
        vec!["javascript"],
        vec![r"console\."],
        vec!["**/*.js"],
        vec![],
        false,
        false,
    )])
    .unwrap();

    // .js should match javascript rules
    let eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "src/app.js".to_string(),
            line: 1,
            content: "console.log('hello')".to_string(),
        }],
        &rules,
        100,
        None,
        None,
    );

    assert_eq!(eval.counts.warn, 1, ".js should be detected as javascript");
}

// =============================================================================
// Ignore Comments / Strings Combinations
// =============================================================================

/// Test ignore_strings only (not comments).
#[test]
fn test_ignore_strings_only() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Error,
        "msg",
        vec![],
        vec!["secret"],
        vec![],
        vec![],
        false, // don't ignore comments
        true,  // ignore strings
    )])
    .unwrap();

    // Pattern in string should be ignored
    let eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: r#"let x = "secret";"#.to_string(),
        }],
        &rules,
        100,
        None,
        None,
    );

    assert_eq!(eval.counts.error, 0, "String should be ignored");
}

/// Test ignore_comments only (not strings).
#[test]
fn test_ignore_comments_only() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Error,
        "msg",
        vec![],
        vec!["secret"],
        vec![],
        vec![],
        true,  // ignore comments
        false, // don't ignore strings
    )])
    .unwrap();

    // Pattern in comment should be ignored
    let eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: "// secret in comment".to_string(),
        }],
        &rules,
        100,
        None,
        None,
    );

    assert_eq!(eval.counts.error, 0, "Comment should be ignored");
}

/// Test ignore neither - should match everywhere.
#[test]
fn test_ignore_neither() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Error,
        "msg",
        vec![],
        vec!["secret"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: "// secret and \"secret\"".to_string(),
        }],
        &rules,
        100,
        None,
        None,
    );

    // Should match both occurrences
    assert_eq!(eval.counts.error, 1, "Should find the match");
    assert_eq!(eval.findings.len(), 1);
}

// =============================================================================
// MatchMode::Absent Edge Cases
// =============================================================================

/// Test MatchMode::Absent with matching content (no finding expected).
#[test]
fn test_match_mode_absent_when_present() {
    let rules = compile_rules(&[RuleConfig {
        id: "no_print".to_string(),
        description: String::new(),
        severity: Severity::Error,
        message: "print should not be present".to_string(),
        languages: vec![],
        patterns: vec![r"print\(".to_string()],
        paths: vec![],
        exclude_paths: vec![],
        ignore_comments: false,
        ignore_strings: false,
        match_mode: MatchMode::Absent,
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
    }])
    .unwrap();

    // print is present, so no finding
    let eval = evaluate_lines(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: "print('hello')".to_string(),
        }],
        &rules,
        100,
    );

    assert_eq!(
        eval.findings.len(),
        0,
        "Absent mode should not fire when pattern present"
    );
    assert_eq!(eval.counts.error, 0);
}

/// Test MatchMode::Absent without matching content (finding expected).
#[test]
fn test_match_mode_absent_when_missing() {
    let rules = compile_rules(&[RuleConfig {
        id: "no_print".to_string(),
        description: String::new(),
        severity: Severity::Error,
        message: "print should be present".to_string(),
        languages: vec![],
        patterns: vec![r"print\(".to_string()],
        paths: vec![],
        exclude_paths: vec![],
        ignore_comments: false,
        ignore_strings: false,
        match_mode: MatchMode::Absent,
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
    }])
    .unwrap();

    // print is NOT present, so finding fires
    let eval = evaluate_lines(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: "puts 'hello'".to_string(),
        }],
        &rules,
        100,
    );

    assert_eq!(
        eval.findings.len(),
        1,
        "Absent mode should fire when pattern missing"
    );
    assert_eq!(eval.counts.error, 1);
    assert_eq!(eval.findings[0].match_text, "<absent>");
}

// =============================================================================
// Rule Override Edge Cases
// =============================================================================

/// Test that rule with empty depends_on works normally.
#[test]
fn test_rule_with_empty_depends_on() {
    let rules = compile_rules(&[test_rule(
        "lone_rule",
        Severity::Warn,
        "msg",
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
            path: "a.txt".to_string(),
            line: 1,
            content: "pattern".to_string(),
        }],
        &rules,
        100,
    );

    assert_eq!(
        eval.counts.warn, 1,
        "Rule with empty depends_on should work"
    );
}

/// Test findings contain correct match_text.
#[test]
fn test_findings_have_correct_match_text() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Warn,
        "msg",
        vec![],
        vec![r"foo\w+bar"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let eval = evaluate_lines(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: "fooXYZbar".to_string(),
        }],
        &rules,
        100,
    );

    assert_eq!(eval.findings.len(), 1);
    assert_eq!(eval.findings[0].match_text, "fooXYZbar");
}

/// Test snippet is correctly trimmed for long lines.
#[test]
fn test_long_line_snippet_trimmed() {
    let rules = compile_rules(&[test_rule(
        "rule",
        Severity::Warn,
        "msg",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let long_content = "a".repeat(300) + " pattern " + &"b".repeat(300);

    let eval = evaluate_lines(
        [InputLine {
            path: "a.txt".to_string(),
            line: 1,
            content: long_content.clone(),
        }],
        &rules,
        100,
    );

    assert_eq!(eval.findings.len(), 1);
    // Snippet should be truncated to 240 chars + ellipsis
    let snippet_len = eval.findings[0].snippet.chars().count();
    assert!(
        snippet_len <= 241,
        "Snippet should be <= 241 chars (240 + ellipsis)"
    );
    assert!(
        eval.findings[0].snippet.ends_with('…'),
        "Snippet should end with ellipsis"
    );
}
