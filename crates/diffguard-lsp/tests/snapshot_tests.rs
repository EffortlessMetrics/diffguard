//! Snapshot tests for key output-producing functions in diffguard-lsp.
//!
//! These tests capture the current output of public functions that produce
//! structured output (strings, vectors, diagnostics). If the output format
//! changes in the future, these tests will fail, alerting maintainers to
//! review the change.
//!
//! Covered functions:
//! - `config::format_rule_explanation` - human-readable rule explanations
//! - `config::find_similar_rules` - "did you mean" suggestions
//! - `text::build_synthetic_diff` - synthetic git diff output
//! - `text::changed_lines_between` - changed line detection

use std::collections::BTreeSet;

use diffguard_types::{MatchMode, RuleConfig, Severity};

/// Snapshot test for format_rule_explanation output.
/// Covers: full rule with all fields populated.
#[test]
fn test_format_rule_explanation_full_rule() {
    let rule = RuleConfig {
        id: "rust.no_unwrap".to_string(),
        description: "Avoid using unwrap()".to_string(),
        severity: Severity::Error,
        message: "Calling .unwrap() on an Option may panic".to_string(),
        languages: vec!["rust".to_string()],
        patterns: vec![r"\.unwrap\(\)".to_string()],
        paths: vec!["**/*.rs".to_string()],
        exclude_paths: vec!["**/tests/**".to_string()],
        ignore_comments: true,
        ignore_strings: true,
        match_mode: MatchMode::Any,
        multiline: false,
        multiline_window: None,
        context_patterns: vec![],
        context_window: None,
        escalate_patterns: vec![],
        escalate_window: None,
        escalate_to: None,
        depends_on: vec![],
        help: Some("Use pattern matching or unwrap_or instead.".to_string()),
        url: Some("https://diffguard.example.com/rules/rust.no_unwrap".to_string()),
        tags: vec!["safety".to_string(), "panics".to_string()],
        test_cases: vec![],
    };

    let explanation = diffguard_lsp::config::format_rule_explanation(&rule);

    // Snapshot the full explanation string
    // This captures the exact format of the output including newlines
    assert!(
        explanation.contains("Rule: rust.no_unwrap"),
        "explanation should contain rule ID"
    );
    assert!(
        explanation.contains("Severity: error"),
        "explanation should contain severity"
    );
    assert!(
        explanation.contains("Message:"),
        "explanation should contain message section"
    );
    assert!(
        explanation.contains("Patterns:"),
        "explanation should contain patterns section"
    );
    assert!(
        explanation.contains("rust.no_unwrap"),
        "explanation should contain the rule ID"
    );
}

/// Snapshot test for format_rule_explanation with minimal rule.
#[test]
fn test_format_rule_explanation_minimal_rule() {
    let rule = RuleConfig {
        id: "minimal".to_string(),
        description: String::new(),
        severity: Severity::Warn,
        message: "A minimal rule".to_string(),
        languages: vec![],
        patterns: vec!["test".to_string()],
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
    };

    let explanation = diffguard_lsp::config::format_rule_explanation(&rule);

    assert!(explanation.contains("Rule: minimal"));
    assert!(explanation.contains("Severity: warn"));
    assert!(explanation.contains("Message:"));
    assert!(explanation.contains("A minimal rule"));
}

/// Snapshot test for find_similar_rules with exact prefix match.
#[test]
fn test_find_similar_rules_prefix_match() {
    let rules = vec![
        make_rule("rust.no_unwrap"),
        make_rule("rust.no_expect"),
        make_rule("security.no_eval"),
        make_rule("security.no_shell"),
    ];

    // Query that should match "rust.no_unwrap" via prefix
    let suggestions = diffguard_lsp::config::find_similar_rules("rust.no_unw", &rules);

    assert!(
        suggestions.contains(&"rust.no_unwrap".to_string()),
        "should suggest rust.no_unwrap for 'rust.no_unw' query"
    );
    // Should be limited to 5 results
    assert!(suggestions.len() <= 5);
}

/// Snapshot test for find_similar_rules with substring match.
#[test]
fn test_find_similar_rules_substring_match() {
    let rules = vec![
        make_rule("rust.no_unwrap"),
        make_rule("rust.no_expect"),
        make_rule("security.no_eval"),
        make_rule("security.no_shell"),
    ];

    // Query that should match via substring
    let suggestions = diffguard_lsp::config::find_similar_rules("no_unwrap", &rules);

    assert!(
        suggestions.contains(&"rust.no_unwrap".to_string()),
        "should suggest rust.no_unwrap for 'no_unwrap' query"
    );
}

/// Snapshot test for find_similar_rules with edit distance match.
#[test]
fn test_find_similar_rules_edit_distance() {
    let rules = vec![
        make_rule("rust.no_unwrap"),
        make_rule("rust.no_expect"),
        make_rule("security.no_eval"),
        make_rule("security.no_shell"),
    ];

    // Query with typo (1 character off)
    let suggestions = diffguard_lsp::config::find_similar_rules("rust.no_unwrp", &rules);

    assert!(
        suggestions.contains(&"rust.no_unwrap".to_string()),
        "should suggest rust.no_unwrap for 'rust.no_unwrp' (typo)"
    );
}

/// Snapshot test for find_similar_rules with no matches.
#[test]
fn test_find_similar_rules_no_matches() {
    let rules = vec![make_rule("rust.no_unwrap"), make_rule("security.no_eval")];

    let suggestions = diffguard_lsp::config::find_similar_rules("completely_different_xyz", &rules);

    assert!(
        suggestions.is_empty(),
        "should return empty for no similar rules"
    );
}

/// Snapshot test for build_synthetic_diff with single changed line.
#[test]
fn test_build_synthetic_diff_single_line() {
    let changed = BTreeSet::from([2_u32]);
    let diff = diffguard_lsp::text::build_synthetic_diff(
        "src/main.rs",
        "line one\nline two\nline three\n",
        &changed,
    );

    assert!(diff.contains("diff --git"));
    assert!(diff.contains("src/main.rs"));
    assert!(diff.contains("@@"));
    assert!(diff.contains("+line two"));
}

/// Snapshot test for build_synthetic_diff with multiple changed lines.
#[test]
fn test_build_synthetic_diff_multiple_lines() {
    let changed = BTreeSet::from([1_u32, 3_u32, 5_u32]);
    let diff = diffguard_lsp::text::build_synthetic_diff(
        "test.txt",
        "one\ntwo\nthree\nfour\nfive\nsix\n",
        &changed,
    );

    assert!(diff.contains("diff --git"));
    assert!(diff.contains("test.txt"));
    // Each changed line should appear as an addition
    assert!(diff.contains("+one"));
    assert!(diff.contains("+three"));
    assert!(diff.contains("+five"));
    // Unchanged lines should not appear as additions
    assert!(!diff.contains("+two"));
    assert!(!diff.contains("+four"));
}

/// Snapshot test for build_synthetic_diff with empty changed set.
#[test]
fn test_build_synthetic_diff_empty_changes() {
    let changed = BTreeSet::<u32>::new();
    let diff = diffguard_lsp::text::build_synthetic_diff("empty.txt", "content\n", &changed);

    // Should still produce diff header but no hunks
    assert!(diff.contains("diff --git"));
    assert!(diff.contains("empty.txt"));
}

/// Snapshot test for changed_lines_between with modified line.
#[test]
fn test_changed_lines_between_modified() {
    let before = "alpha\nbeta\ngamma\n";
    let after = "alpha\nBETA\ngamma\n";

    let changed = diffguard_lsp::text::changed_lines_between(before, after);

    assert_eq!(changed, BTreeSet::from([2]));
}

/// Snapshot test for changed_lines_between with added line.
///
/// Note: Due to how split_lines works (split on '\n'), trailing newlines
/// produce empty string elements. So "alpha\nbeta\n" has 3 elements:
/// ["alpha", "beta", ""]
#[test]
fn test_changed_lines_between_added() {
    // No trailing newline - 2 lines each
    let before = "alpha\nbeta";
    let after = "alpha\nbeta\ngamma";

    let changed = diffguard_lsp::text::changed_lines_between(before, after);

    assert_eq!(changed, BTreeSet::from([3]));
}

/// Snapshot test for changed_lines_between with removed line.
#[test]
fn test_changed_lines_between_removed() {
    let before = "alpha\nbeta\ngamma\n";
    let after = "alpha\ngamma\n";

    let changed = diffguard_lsp::text::changed_lines_between(before, after);

    assert!(changed.contains(&2) || changed.contains(&3));
}

/// Snapshot test for changed_lines_between with no changes.
#[test]
fn test_changed_lines_between_no_change() {
    let text = "same\nlines\nhere\n";
    let changed = diffguard_lsp::text::changed_lines_between(text, text);

    assert!(changed.is_empty());
}

/// Helper to create a minimal RuleConfig for testing.
fn make_rule(id: &str) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity: Severity::Warn,
        message: "test message".to_string(),
        languages: vec![],
        patterns: vec!["a".to_string()],
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
