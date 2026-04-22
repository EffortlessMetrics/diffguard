//! Red tests for work-76372a5b: Refactor `evaluate_lines_with_overrides_and_language`
//!
//! These tests verify that the three-phase decomposition of
//! `evaluate_lines_with_overrides_and_language` preserves correct behavior.
//!
//! Phase 1 (prepare_lines): Language detection, preprocessor setup, line preparation
//! Phase 2 (generate_match_events): Rule evaluation per file with dependency gating
//! Phase 3 (collect_findings): Event processing into structured findings
//!
//! These tests will FAIL before the refactoring because the helper functions
//! don't exist yet. After extraction, they should PASS.

use diffguard_domain::{
    InputLine, evaluate_lines_with_overrides_and_language, rules::compile_rules,
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
// Phase 1 Tests: Line preparation with language detection
// =============================================================================

/// Test that Phase 1 (prepare_lines) correctly handles language detection
/// across multiple files with different extensions.
#[test]
fn test_prepare_lines_language_detection_across_files() {
    let rules = compile_rules(&[test_rule(
        "detect_pattern",
        Severity::Warn,
        "found pattern",
        vec![],
        vec!["pattern"],
        vec![],
        vec![],
        true,
        false,
    )])
    .unwrap();

    // Python file - hash comment should be ignored
    // Rust file - hash is NOT a comment, should be detected
    let eval = evaluate_lines_with_overrides_and_language(
        [
            InputLine {
                path: "src/main.py".to_string(),
                line: 1,
                content: "# pattern in python comment".to_string(),
            },
            InputLine {
                path: "src/lib.rs".to_string(),
                line: 1,
                content: "# pattern in rust (not a comment)".to_string(),
            },
        ],
        &rules,
        100,
        None,
        None,
    );

    // Only the Rust file should have a finding
    // This verifies Phase 1 correctly switches languages per file
    assert_eq!(
        eval.counts.warn, 1,
        "Expected 1 warning from Rust file (hash is not a comment), got {}",
        eval.counts.warn
    );
    assert_eq!(eval.findings.len(), 1);
    assert_eq!(
        eval.findings[0].path, "src/lib.rs",
        "Finding should be from Rust file"
    );
}

/// Test that Phase 1 respects forced_language override.
#[test]
fn test_prepare_lines_respects_force_language() {
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

    // File with unknown extension but forced language
    let lines = [InputLine {
        path: "src/custom.ext".to_string(),
        line: 1,
        content: "let x = y.unwrap();".to_string(),
    }];

    // Without force_language - no detection
    let without =
        evaluate_lines_with_overrides_and_language(lines.clone(), &rules, 100, None, None);
    assert_eq!(
        without.counts.error, 0,
        "Without force_language, unknown extension should not match"
    );

    // With force_language = "rust" - should match
    let with = evaluate_lines_with_overrides_and_language(lines, &rules, 100, None, Some("rust"));
    assert_eq!(
        with.counts.error, 1,
        "With force_language=rust, should detect unwrap"
    );
}

// =============================================================================
// Phase 2 Tests: Match event generation with dependency gating
// =============================================================================

/// Test that Phase 2 (generate_match_events) correctly handles dependency gating.
/// A rule that depends on another should only fire if the dependency also fires.
#[test]
fn test_generate_match_events_dependency_gating() {
    let rules = compile_rules(&[
        RuleConfig {
            id: "python.has_eval".to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "eval used".to_string(),
            languages: vec!["python".to_string()],
            patterns: vec![r"\beval\(".to_string()],
            paths: vec!["**/*.py".to_string()],
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
        },
        RuleConfig {
            id: "python.eval_untrusted".to_string(),
            description: String::new(),
            severity: Severity::Error,
            message: "eval with untrusted input".to_string(),
            languages: vec!["python".to_string()],
            patterns: vec![r"(?i)\buntrusted".to_string()],
            paths: vec!["**/*.py".to_string()],
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
            // THIS IS THE KEY: eval_untrusted depends on has_eval
            depends_on: vec!["python.has_eval".to_string()],
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        },
    ])
    .unwrap();

    // Only "untrusted" present, no "eval" - second rule should NOT fire
    let eval_without_eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "src/a.py".to_string(),
            line: 1,
            content: "untrusted_input".to_string(),
        }],
        &rules,
        100,
        None,
        None,
    );
    assert_eq!(
        eval_without_eval.counts.error, 0,
        "eval_untrusted should not fire without has_eval dependency"
    );

    // Both present - both should fire
    let eval_with_eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "src/a.py".to_string(),
            line: 1,
            content: "eval(untrusted_input)".to_string(),
        }],
        &rules,
        100,
        None,
        None,
    );
    assert_eq!(eval_with_eval.counts.warn, 1, "has_eval should fire");
    assert_eq!(
        eval_with_eval.counts.error, 1,
        "eval_untrusted should fire when dependency is met"
    );
}

// =============================================================================
// Phase 3 Tests: Findings collection with suppression and truncation
// =============================================================================

/// Test that Phase 3 (collect_findings) correctly handles max_findings cap
/// while maintaining accurate counts.
#[test]
fn test_collect_findings_respects_max_findings_cap() {
    let rules = compile_rules(&[test_rule(
        "r",
        Severity::Warn,
        "m",
        vec![],
        vec!["x"],
        vec![],
        vec![],
        false,
        false,
    )])
    .unwrap();

    let lines = (0..5).map(|i| InputLine {
        path: "a.txt".to_string(),
        line: i,
        content: "x".to_string(),
    });

    let eval = evaluate_lines_with_overrides_and_language(lines, &rules, 2, None, None);

    // Counts should reflect ALL matches
    assert_eq!(
        eval.counts.warn, 5,
        "counts.warn should be 5 (all matches), got {}",
        eval.counts.warn
    );
    // Findings should be capped
    assert_eq!(
        eval.findings.len(),
        2,
        "findings should be capped to max_findings (2), got {}",
        eval.findings.len()
    );
    // Truncated count should track the rest
    assert_eq!(
        eval.truncated_findings, 3,
        "truncated_findings should be 3, got {}",
        eval.truncated_findings
    );
}

/// Test that Phase 3 correctly tracks per-rule hit statistics.
#[test]
fn test_collect_findings_tracks_rule_hit_stats() {
    let rules = compile_rules(&[
        test_rule(
            "rule.warn",
            Severity::Warn,
            "warn",
            vec![],
            vec!["pattern"],
            vec![],
            vec![],
            false,
            false,
        ),
        test_rule(
            "rule.error",
            Severity::Error,
            "error",
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
        [
            InputLine {
                path: "a.txt".to_string(),
                line: 1,
                content: "pattern".to_string(),
            },
            InputLine {
                path: "a.txt".to_string(),
                line: 2,
                content: "pattern // diffguard: ignore rule.warn".to_string(),
            },
        ],
        &rules,
        100,
        None,
        None,
    );

    let warn_stats = eval
        .rule_hits
        .iter()
        .find(|s| s.rule_id == "rule.warn")
        .expect("warn stats should exist");
    assert_eq!(warn_stats.total, 2, "warn total should be 2");
    assert_eq!(
        warn_stats.emitted, 1,
        "warn emitted should be 1 (one suppressed)"
    );
    assert_eq!(warn_stats.suppressed, 1, "warn suppressed should be 1");

    let error_stats = eval
        .rule_hits
        .iter()
        .find(|s| s.rule_id == "rule.error")
        .expect("error stats should exist");
    assert_eq!(error_stats.total, 2, "error total should be 2");
    assert_eq!(error_stats.emitted, 2, "error emitted should be 2");
    assert_eq!(error_stats.suppressed, 0, "error suppressed should be 0");
}

/// Test that Phase 3 correctly processes suppression directives.
#[test]
fn test_collect_findings_respects_suppression_directives() {
    let rules = compile_rules(&[test_rule(
        "rust.no_unwrap",
        Severity::Error,
        "no unwrap",
        vec!["rust"],
        vec![r"\.unwrap\("],
        vec!["**/*.rs"],
        vec![],
        true,
        true,
    )])
    .unwrap();

    let eval = evaluate_lines_with_overrides_and_language(
        [InputLine {
            path: "src/lib.rs".to_string(),
            line: 1,
            content: "let x = y.unwrap(); // diffguard: ignore rust.no_unwrap".to_string(),
        }],
        &rules,
        100,
        None,
        None,
    );

    assert_eq!(
        eval.counts.error, 0,
        "Suppressed finding should not increment error count"
    );
    assert_eq!(
        eval.counts.suppressed, 1,
        "Suppressed finding should increment suppressed count"
    );
    assert!(
        eval.findings.is_empty(),
        "Suppressed finding should not appear in findings"
    );
}

// =============================================================================
// Integration Tests: Full pipeline behavior
// =============================================================================

/// Integration test verifying the complete pipeline works correctly
/// with all three phases interacting.
#[test]
fn test_full_pipeline_multiple_files_languages_and_suppressions() {
    let rules = compile_rules(&[
        test_rule(
            "python.no_print",
            Severity::Warn,
            "no print",
            vec!["python"],
            vec![r"\bprint\("],
            vec!["**/*.py"],
            vec![],
            true,
            false,
        ),
        test_rule(
            "rust.no_unwrap",
            Severity::Error,
            "no unwrap",
            vec!["rust"],
            vec![r"\.unwrap\("],
            vec!["**/*.rs"],
            vec![],
            true,
            true,
        ),
    ])
    .unwrap();

    let eval = evaluate_lines_with_overrides_and_language(
        [
            // Python file - print in comment should be ignored
            InputLine {
                path: "src/main.py".to_string(),
                line: 1,
                content: "# print('hello')".to_string(),
            },
            // Python file - actual print should be detected
            InputLine {
                path: "src/main.py".to_string(),
                line: 2,
                content: "print('hello')".to_string(),
            },
            // Rust file - unwrap in comment should be ignored
            InputLine {
                path: "src/lib.rs".to_string(),
                line: 1,
                content: "// y.unwrap()".to_string(),
            },
            // Rust file - actual unwrap should be detected
            InputLine {
                path: "src/lib.rs".to_string(),
                line: 2,
                content: "let x = y.unwrap();".to_string(),
            },
        ],
        &rules,
        100,
        None,
        None,
    );

    // Should find: 1 Python print + 1 Rust unwrap = 2 findings
    assert_eq!(
        eval.findings.len(),
        2,
        "Expected 2 findings, got {}",
        eval.findings.len()
    );
    assert_eq!(
        eval.counts.warn, 1,
        "Expected 1 warn (python print), got {}",
        eval.counts.warn
    );
    assert_eq!(
        eval.counts.error, 1,
        "Expected 1 error (rust unwrap), got {}",
        eval.counts.error
    );

    // Verify finding details
    let python_finding = eval
        .findings
        .iter()
        .find(|f| f.path.contains(".py"))
        .expect("Should find python finding");
    assert_eq!(python_finding.line, 2);

    let rust_finding = eval
        .findings
        .iter()
        .find(|f| f.path.contains(".rs"))
        .expect("Should find rust finding");
    assert_eq!(rust_finding.line, 2);
}
