//! Integration tests for work-95f4074b: `is_wildcard()` `#[must_use]` attribute
//!
//! These tests verify that `is_wildcard()` integrates correctly with the
//! full suppression workflow - from parsing directives to tracking suppressions
//! to evaluating lines with rules.
//!
//! Integration points tested:
//! - `parse_suppression()` → `Suppression` → `is_wildcard()`
//! - `SuppressionTracker::process_line()` → `EffectiveSuppressions`
//! - `evaluate_lines()` with suppression tracking

use diffguard_domain::preprocess::{Language, PreprocessOptions, Preprocessor};
use diffguard_domain::rules::compile_rules;
use diffguard_domain::suppression::{SuppressionTracker, parse_suppression};
use diffguard_domain::{InputLine, evaluate_lines};
use diffguard_types::{MatchMode, RuleConfig, Severity};

/// Helper: preprocess a line for comment masking
fn masked_comments(line: &str, lang: Language) -> String {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), lang);
    p.sanitize_line(line)
}

/// Helper: create a test rule
fn test_rule(
    id: &str,
    severity: Severity,
    message: &str,
    languages: Vec<&str>,
    patterns: Vec<&str>,
) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity,
        message: message.to_string(),
        languages: languages.into_iter().map(|s| s.to_string()).collect(),
        patterns: patterns.into_iter().map(|s| s.to_string()).collect(),
        paths: vec![],
        exclude_paths: vec![],
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
        help: None,
        url: None,
        tags: vec![],
        test_cases: vec![],
    }
}

// ==================== Integration: is_wildcard() in suppression parsing ====================

/// Integration: `parse_suppression()` output feeds into `is_wildcard()` correctly
#[test]
fn integration_parse_suppression_feeds_is_wildcard_true() {
    // Wildcard: ignore *
    let line = "// diffguard: ignore *";
    let suppression = parse_suppression(line).expect("should parse");

    // The is_wildcard() result reflects the parsed rule_ids
    assert!(
        suppression.is_wildcard(),
        "Wildcard suppression should have is_wildcard() == true"
    );
    assert!(
        suppression.suppresses("any.rule"),
        "Wildcard should suppress any rule"
    );
}

/// Integration: `parse_suppression()` output feeds into `is_wildcard()` correctly
#[test]
fn integration_parse_suppression_feeds_is_wildcard_false() {
    // Specific rule: ignore rust.no_unwrap
    let line = "// diffguard: ignore rust.no_unwrap";
    let suppression = parse_suppression(line).expect("should parse");

    assert!(
        !suppression.is_wildcard(),
        "Specific rule should have is_wildcard() == false"
    );
    assert!(
        suppression.suppresses("rust.no_unwrap"),
        "Should suppress specific rule"
    );
    assert!(
        !suppression.suppresses("other.rule"),
        "Should NOT suppress other rules"
    );
}

// ==================== Integration: is_wildcard() in SuppressionTracker ====================

/// Integration: SuppressionTracker.process_line() returns EffectiveSuppressions
/// that correctly reflects wildcard suppressions from is_wildcard()
#[test]
fn integration_tracker_process_line_wildcard() {
    let mut tracker = SuppressionTracker::new();
    let lang = Language::Rust;

    // Line 1: wildcard suppression on same line
    let line1 = "let x = y.unwrap(); // diffguard: ignore";
    let masked = masked_comments(line1, lang);
    let effective = tracker.process_line(line1, &masked);

    // The effective suppressions should reflect wildcard behavior
    assert!(
        effective.suppress_all,
        "Wildcard suppression should set suppress_all = true"
    );
    assert!(
        effective.is_suppressed("any.rule"),
        "Wildcard should suppress any rule"
    );
    assert!(
        effective.is_suppressed("rust.no_unwrap"),
        "Wildcard should suppress rust.no_unwrap"
    );
}

/// Integration: SuppressionTracker correctly handles ignore-next-line wildcard
#[test]
fn integration_tracker_next_line_wildcard() {
    let mut tracker = SuppressionTracker::new();
    let lang = Language::Rust;

    // Line 1: ignore-next-line with wildcard
    let line1 = "// diffguard: ignore-next-line *";
    let masked1 = masked_comments(line1, lang);
    let effective1 = tracker.process_line(line1, &masked1);

    // Line 1 should NOT be suppressed (it's a next-line directive)
    assert!(
        !effective1.suppress_all && effective1.is_empty(),
        "ignore-next-line should not suppress same line"
    );

    // Line 2: the pending suppression should apply
    let line2 = "let x = y.unwrap();";
    let masked2 = masked_comments(line2, lang);
    let effective2 = tracker.process_line(line2, &masked2);

    assert!(
        effective2.suppress_all,
        "Next line should be suppressed by wildcard"
    );
}

/// Integration: Multiple suppressions combine correctly with wildcards
#[test]
fn integration_tracker_multiple_suppressions_with_wildcard() {
    let mut tracker = SuppressionTracker::new();
    let lang = Language::Rust;

    // Line 1: ignore rust.no_unwrap
    let line1 = "let x = y.unwrap(); // diffguard: ignore rust.no_unwrap";
    let masked1 = masked_comments(line1, lang);
    let effective1 = tracker.process_line(line1, &masked1);

    assert!(
        !effective1.suppress_all,
        "Specific rule should not set suppress_all"
    );
    assert!(
        effective1.is_suppressed("rust.no_unwrap"),
        "Should suppress rust.no_unwrap"
    );

    // Line 2: ignore * (should set suppress_all)
    let line2 = "let y = z.dbg(); // diffguard: ignore *";
    let masked2 = masked_comments(line2, lang);
    let effective2 = tracker.process_line(line2, &masked2);

    assert!(effective2.suppress_all, "Wildcard should set suppress_all");
}

// ==================== Integration: Full evaluate_lines with wildcard suppressions ====================

/// Integration: evaluate_lines correctly applies wildcard suppressions
#[test]
fn integration_evaluate_lines_wildcard_suppression() {
    let rules = compile_rules(&[test_rule(
        "rust.no_unwrap",
        Severity::Error,
        "no unwrap",
        vec!["rust"],
        vec![r"\.unwrap\("],
    )])
    .unwrap();

    // Line with wildcard suppression - should suppress ALL rules
    let lines = [InputLine {
        path: "src/lib.rs".to_string(),
        line: 1,
        content: "let x = y.unwrap(); // diffguard: ignore *".to_string(),
    }];

    let eval = evaluate_lines(lines, &rules, 100);

    // Wildcard should suppress all findings
    assert_eq!(
        eval.counts.error, 0,
        "Wildcard should suppress rust.no_unwrap error"
    );
    assert_eq!(
        eval.findings.len(),
        0,
        "No findings should be emitted when wildcard suppression is active"
    );
}

/// Integration: evaluate_lines correctly distinguishes wildcard vs specific rules
#[test]
fn integration_evaluate_lines_specific_vs_wildcard() {
    let rules = compile_rules(&[
        test_rule(
            "rust.no_unwrap",
            Severity::Error,
            "no unwrap",
            vec!["rust"],
            vec![r"\.unwrap\("],
        ),
        test_rule(
            "rust.no_println",
            Severity::Warn,
            "no println",
            vec!["rust"],
            vec![r"println!\("],
        ),
    ])
    .unwrap();

    // Line with specific rule suppression (only suppresses rust.no_unwrap)
    let lines = [InputLine {
        path: "src/lib.rs".to_string(),
        line: 1,
        content: "let x = y.unwrap(); println!(\"hi\"); // diffguard: ignore rust.no_unwrap"
            .to_string(),
    }];

    let eval = evaluate_lines(lines, &rules, 100);

    // Only rust.no_unwrap should be suppressed, but println! should still be flagged
    assert_eq!(eval.counts.error, 0, "rust.no_unwrap should be suppressed");
    // Note: rust.no_println is a warning, not error
    assert!(
        eval.counts.warn >= 1,
        "rust.no_println should NOT be suppressed (only rust.no_unwrap was suppressed)"
    );
}

/// Integration: ignore-all directive works as wildcard
#[test]
fn integration_evaluate_lines_ignore_all() {
    let rules = compile_rules(&[test_rule(
        "rust.no_unwrap",
        Severity::Error,
        "no unwrap",
        vec!["rust"],
        vec![r"\.unwrap\("],
    )])
    .unwrap();

    let lines = [InputLine {
        path: "src/lib.rs".to_string(),
        line: 1,
        content: "let x = y.unwrap(); // diffguard: ignore-all".to_string(),
    }];

    let eval = evaluate_lines(lines, &rules, 100);

    assert_eq!(
        eval.counts.error, 0,
        "ignore-all should suppress all findings"
    );
    assert_eq!(eval.findings.len(), 0);
}

/// Integration: empty ignore (bare `diffguard: ignore`) works as wildcard
#[test]
fn integration_evaluate_lines_bare_ignore() {
    let rules = compile_rules(&[test_rule(
        "rust.no_unwrap",
        Severity::Error,
        "no unwrap",
        vec!["rust"],
        vec![r"\.unwrap\("],
    )])
    .unwrap();

    let lines = [InputLine {
        path: "src/lib.rs".to_string(),
        line: 1,
        content: "let x = y.unwrap(); // diffguard: ignore".to_string(),
    }];

    let eval = evaluate_lines(lines, &rules, 100);

    assert_eq!(
        eval.counts.error, 0,
        "Bare ignore should suppress all findings (wildcard)"
    );
    assert_eq!(eval.findings.len(), 0);
}

// ==================== Integration: is_wildcard() with different directive types ====================

/// Integration: is_wildcard() returns correct value for ignore-next-line wildcards
#[test]
fn integration_is_wildcard_ignore_next_line() {
    let line = "// diffguard: ignore-next-line *";
    let suppression = parse_suppression(line).expect("should parse");

    assert!(
        suppression.is_wildcard(),
        "ignore-next-line * should be wildcard"
    );
    assert!(
        suppression.suppresses("any.rule"),
        "Wildcard should suppress any rule"
    );
}

/// Integration: is_wildcard() returns correct value for ignore-all
#[test]
fn integration_is_wildcard_ignore_all() {
    let line = "// diffguard: ignore-all";
    let suppression = parse_suppression(line).expect("should parse");

    assert!(suppression.is_wildcard(), "ignore-all should be wildcard");
    assert!(
        suppression.suppresses("any.rule"),
        "Wildcard should suppress any rule"
    );
}

// ==================== Integration: Language-aware parsing with is_wildcard() ====================

/// Integration: wildcard suppression works correctly across different languages
#[test]
fn integration_wildcard_suppression_python() {
    let mut tracker = SuppressionTracker::new();
    let lang = Language::Python;

    // Python hash comment
    let line = "print(x)  # diffguard: ignore *";
    let masked = masked_comments(line, lang);
    let effective = tracker.process_line(line, &masked);

    assert!(
        effective.suppress_all,
        "Wildcard suppression should work in Python"
    );
    assert!(
        effective.is_suppressed("python.no_print"),
        "Should suppress any python rule"
    );
}

/// Integration: wildcard suppression works in Go
#[test]
fn integration_wildcard_suppression_go() {
    let mut tracker = SuppressionTracker::new();
    let lang = Language::Go;

    // Go double-slash comment
    let line = "fmt.Println(\"hello\") // diffguard: ignore *";
    let masked = masked_comments(line, lang);
    let effective = tracker.process_line(line, &masked);

    assert!(
        effective.suppress_all,
        "Wildcard suppression should work in Go"
    );
    assert!(
        effective.is_suppressed("go.no_print"),
        "Should suppress any Go rule"
    );
}

/// Integration: wildcard suppression works in Shell
#[test]
fn integration_wildcard_suppression_shell() {
    let mut tracker = SuppressionTracker::new();
    let lang = Language::Shell;

    // Shell hash comment
    let line = "echo hello  # diffguard: ignore *";
    let masked = masked_comments(line, lang);
    let effective = tracker.process_line(line, &masked);

    assert!(
        effective.suppress_all,
        "Wildcard suppression should work in Shell"
    );
    assert!(
        effective.is_suppressed("shell.no_echo"),
        "Should suppress any shell rule"
    );
}
