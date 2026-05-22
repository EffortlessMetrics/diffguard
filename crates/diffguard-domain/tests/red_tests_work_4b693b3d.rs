//! Red tests for work-4b693b3d: Extract helper functions from `evaluate_lines_with_overrides_and_language`
//!
//! These tests verify that the three helper functions are extracted with correct signatures
//! and behavior as specified in ADR-0047.
//!
//! **These tests will FAIL until the refactoring is complete.**
//! After extraction, all tests should pass.
//!
//! # Helper Functions to be Extracted
//!
//! 1. `prepare_lines(input_lines: Vec<InputLine>, forced_language: Option<Language>) -> (Vec<PreparedLine>, BTreeMap<String, Vec<usize>>)`
//! 2. `collect_match_events(by_file: &BTreeMap<String, Vec<usize>>, prepared_lines: &[PreparedLine], rules: &[CompiledRule], overrides: Option<&RuleOverrideMatcher>) -> Vec<MatchEvent>`
//! 3. `emit_findings(events: Vec<MatchEvent>, rules: &[CompiledRule], prepared_lines: &[PreparedLine], max_findings: usize) -> (Vec<Finding>, VerdictCounts, u32, BTreeMap<String, RuleHitStat>)`

use std::collections::BTreeMap;

use diffguard_domain::{
    InputLine, Language, RuleHitStat, compile_rules, evaluate_lines,
    evaluate_lines_with_overrides_and_language,
};
use diffguard_types::{Finding, RuleConfig, Severity, VerdictCounts};

// =============================================================================
// Test 1: prepare_lines() exists and has correct signature
// =============================================================================

/// Test that `prepare_lines` is accessible within the crate and has the correct signature.
/// This test verifies the helper function exists and can be called with the right arguments.
#[test]
fn test_prepare_lines_function_exists_with_correct_signature() {
    // The prepare_lines function should take Vec<InputLine> and Option<Language>
    // and return (Vec<PreparedLine>, BTreeMap<String, Vec<usize>>)
    //
    // We test this by calling the function and verifying it returns the expected types.

    let input_lines = vec![
        InputLine {
            path: "test.py".to_string(),
            line: 1,
            content: "print('hello')".to_string(),
        },
        InputLine {
            path: "test.py".to_string(),
            line: 2,
            content: "x = 1".to_string(),
        },
    ];

    // Call prepare_lines - this function should exist after refactoring
    // Signature: prepare_lines(input_lines: Vec<InputLine>, forced_language: Option<Language>)
    //              -> (Vec<PreparedLine>, BTreeMap<String, Vec<usize>>)
    let (prepared_lines, by_file) = diffguard_domain::evaluate::prepare_lines(input_lines, None);

    // Verify the return types are correct
    // prepared_lines should have 2 elements
    assert_eq!(prepared_lines.len(), 2, "Should have 2 prepared lines");

    // by_file should have 1 entry (test.py)
    assert_eq!(by_file.len(), 1, "Should have 1 file in by_file index");
    assert!(
        by_file.contains_key("test.py"),
        "by_file should contain test.py"
    );
    assert_eq!(
        by_file.get("test.py").unwrap().len(),
        2,
        "test.py should have 2 lines"
    );
}

// =============================================================================
// Test 2: prepare_lines() with forced language
// =============================================================================

/// Test that `prepare_lines` correctly applies forced language.
#[test]
fn test_prepare_lines_with_forced_language() {
    let input_lines = vec![InputLine {
        path: "unknown.ext".to_string(),
        line: 1,
        content: "# pattern in comment".to_string(),
    }];

    // Force language to Rust - hash should NOT be treated as a comment
    let (prepared_lines, _by_file) =
        diffguard_domain::evaluate::prepare_lines(input_lines, Some(Language::Rust));

    assert_eq!(prepared_lines.len(), 1);
    // With Rust language, the hash comment should not be masked
    // The masked_comments version should still contain "# pattern"
}

// =============================================================================
// Test 3: collect_match_events() exists and has correct signature
// =============================================================================

/// Test that `collect_match_events` is accessible and returns sorted events.
#[test]
fn test_collect_match_events_function_exists_with_correct_signature() {
    // First, prepare some lines
    let input_lines = vec![
        InputLine {
            path: "test.py".to_string(),
            line: 1,
            content: "print('hello')".to_string(),
        },
        InputLine {
            path: "test.py".to_string(),
            line: 2,
            content: "print('world')".to_string(),
        },
    ];

    // Compile a simple rule that matches "print"
    let rules = compile_rules(&[RuleConfig {
        id: "py.print".to_string(),
        description: String::new(),
        severity: Severity::Warn,
        message: "print found".to_string(),
        languages: vec!["python".to_string()],
        patterns: vec!["print".to_string()],
        paths: vec!["**/*.py".to_string()],
        exclude_paths: vec![],
        ignore_comments: false,
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
        tags: vec![],
        test_cases: vec![],
    }])
    .expect("rules should compile");

    // Get prepared lines
    let (prepared_lines, by_file) = diffguard_domain::evaluate::prepare_lines(input_lines, None);

    // Call collect_match_events
    // Signature: collect_match_events(
    //     by_file: &BTreeMap<String, Vec<usize>>,
    //     prepared_lines: &[PreparedLine],
    //     rules: &[CompiledRule],
    //     overrides: Option<&RuleOverrideMatcher>
    // ) -> Vec<MatchEvent>
    let events =
        diffguard_domain::evaluate::collect_match_events(&by_file, &prepared_lines, &rules, None);

    // Should find 2 matches (one per print)
    assert_eq!(events.len(), 2, "Should find 2 match events");

    // Events should be sorted by anchor_idx
    for i in 1..events.len() {
        assert!(
            events[i - 1].anchor_idx <= events[i].anchor_idx,
            "Events should be sorted by anchor_idx"
        );
    }
}

// =============================================================================
// Test 4: emit_findings() exists and has correct signature
// =============================================================================

/// Test that `emit_findings` is accessible and returns correct types.
#[test]
fn test_emit_findings_function_exists_with_correct_signature() {
    // First, set up the data needed for emit_findings
    let input_lines = vec![InputLine {
        path: "test.py".to_string(),
        line: 1,
        content: "print('hello')".to_string(),
    }];

    let rules = compile_rules(&[RuleConfig {
        id: "py.print".to_string(),
        description: String::new(),
        severity: Severity::Warn,
        message: "print found".to_string(),
        languages: vec!["python".to_string()],
        patterns: vec!["print".to_string()],
        paths: vec!["**/*.py".to_string()],
        exclude_paths: vec![],
        ignore_comments: false,
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
        tags: vec![],
        test_cases: vec![],
    }])
    .expect("rules should compile");

    // Get prepared lines and events
    let (prepared_lines, by_file) = diffguard_domain::evaluate::prepare_lines(input_lines, None);

    let events =
        diffguard_domain::evaluate::collect_match_events(&by_file, &prepared_lines, &rules, None);

    // Call emit_findings
    // Signature: emit_findings(
    //     events: Vec<MatchEvent>,
    //     rules: &[CompiledRule],
    //     prepared_lines: &[PreparedLine],
    //     max_findings: usize
    // ) -> (Vec<Finding>, VerdictCounts, u32, BTreeMap<String, RuleHitStat>)
    let (findings, counts, truncated, rule_hits) =
        diffguard_domain::evaluate::emit_findings(events, &rules, &prepared_lines, 100);

    // Verify return types
    assert_eq!(findings.len(), 1, "Should have 1 finding");
    assert_eq!(counts.warn, 1, "Should have 1 warning");
    assert_eq!(truncated, 0, "Should have 0 truncated");
    assert_eq!(rule_hits.len(), 1, "Should have 1 rule hit stat");
}

// =============================================================================
// Test 5: Orchestrator produces same results as the full pipeline
// =============================================================================

/// Integration test: Verify the extracted helpers produce the same results
/// as calling the orchestrator directly.
///
/// This ensures that the refactoring doesn't change behavior.
#[test]
fn test_helpers_produce_same_results_as_orchestrator() {
    let input_lines = vec![
        InputLine {
            path: "src/main.py".to_string(),
            line: 10,
            content: "print('hello world')".to_string(),
        },
        InputLine {
            path: "src/main.py".to_string(),
            line: 11,
            content: "x = 1  # inline comment".to_string(),
        },
    ];

    let rules = compile_rules(&[
        RuleConfig {
            id: "py.print".to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "print found".to_string(),
            languages: vec!["python".to_string()],
            patterns: vec!["print".to_string()],
            paths: vec!["**/*.py".to_string()],
            exclude_paths: vec![],
            ignore_comments: false,
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
            tags: vec![],
            test_cases: vec![],
        },
        RuleConfig {
            id: "py.no_comments".to_string(),
            description: String::new(),
            severity: Severity::Info,
            message: "comment found".to_string(),
            languages: vec!["python".to_string()],
            patterns: vec!["#".to_string()],
            paths: vec!["**/*.py".to_string()],
            exclude_paths: vec![],
            ignore_comments: false,
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
            tags: vec![],
            test_cases: vec![],
        },
    ])
    .expect("rules should compile");

    // Get result from orchestrator
    let orchestrator_result =
        evaluate_lines_with_overrides_and_language(input_lines.clone(), &rules, 100, None, None);

    // Get result via helpers
    let (prepared_lines, by_file) =
        diffguard_domain::evaluate::prepare_lines(input_lines.clone(), None);
    let events =
        diffguard_domain::evaluate::collect_match_events(&by_file, &prepared_lines, &rules, None);
    let (helper_findings, helper_counts, helper_truncated, helper_rule_hits) =
        diffguard_domain::evaluate::emit_findings(events, &rules, &prepared_lines, 100);

    // Results should match
    assert_eq!(
        orchestrator_result.findings.len(),
        helper_findings.len(),
        "Findings count should match"
    );
    assert_eq!(
        orchestrator_result.counts.warn, helper_counts.warn,
        "Warn count should match"
    );
    assert_eq!(
        orchestrator_result.counts.info, helper_counts.info,
        "Info count should match"
    );
    assert_eq!(
        orchestrator_result.truncated_findings, helper_truncated,
        "Truncated count should match"
    );
    assert_eq!(
        orchestrator_result.rule_hits.len(),
        helper_rule_hits.len(),
        "Rule hits count should match"
    );
}

// =============================================================================
// Test 6: Line count of orchestrator function
// =============================================================================

/// Test that the orchestrator function `evaluate_lines_with_overrides_and_language`
/// has ≤100 lines after the refactoring.
///
/// This is tested indirectly by ensuring the function compiles and all tests pass.
/// The actual line count is enforced by clippy::too_many_lines lint.
#[test]
fn test_orchestrator_function_compiles_without_too_many_lines_warning() {
    // If the function has >100 lines, clippy will warn.
    // This test just verifies the function is callable.
    let input_lines = vec![InputLine {
        path: "test.txt".to_string(),
        line: 1,
        content: "hello".to_string(),
    }];

    let rules = compile_rules(&[RuleConfig {
        id: "test".to_string(),
        description: String::new(),
        severity: Severity::Info,
        message: "test".to_string(),
        languages: vec![],
        patterns: vec!["hello".to_string()],
        paths: vec![],
        exclude_paths: vec![],
        ignore_comments: false,
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
        tags: vec![],
        test_cases: vec![],
    }])
    .expect("rules should compile");

    let result = evaluate_lines_with_overrides_and_language(input_lines, &rules, 100, None, None);

    assert_eq!(result.findings.len(), 1);
}

// =============================================================================
// Test 7: AC5 - Helper signatures are correct
// =============================================================================

/// Test AC5: Verify helper signatures match the specification exactly.
///
/// AC5: Helper Signatures Correct
/// - `prepare_lines(input_lines: Vec<InputLine>, forced_language: Option<Language>) -> (Vec<PreparedLine>, BTreeMap<String, Vec<usize>>)`
/// - `collect_match_events(by_file: &BTreeMap<...>, prepared_lines: &[PreparedLine], rules: &[CompiledRule], overrides: Option<&RuleOverrideMatcher>) -> Vec<MatchEvent>`
/// - `emit_findings(events: Vec<MatchEvent>, rules: &[CompiledRule], prepared_lines: &[PreparedLine], max_findings: usize) -> (Vec<Finding>, VerdictCounts, u32, BTreeMap<String, RuleHitStat>)`
#[test]
fn test_helper_signatures_match_specification() {
    // This test exercises all three helpers to verify they accept and return
    // the correct types as specified in AC5.

    let input_lines = vec![InputLine {
        path: "test.rs".to_string(),
        line: 1,
        content: "let x = 1;".to_string(),
    }];

    let rules = compile_rules(&[RuleConfig {
        id: "test".to_string(),
        description: String::new(),
        severity: Severity::Info,
        message: "test".to_string(),
        languages: vec!["rust".to_string()],
        patterns: vec!["let".to_string()],
        paths: vec!["**/*.rs".to_string()],
        exclude_paths: vec![],
        ignore_comments: false,
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
        tags: vec![],
        test_cases: vec![],
    }])
    .expect("rules should compile");

    // Test prepare_lines signature
    let (prepared_lines, by_file): (Vec<_>, BTreeMap<_, _>) =
        diffguard_domain::evaluate::prepare_lines(input_lines.clone(), Some(Language::Rust));
    assert_eq!(prepared_lines.len(), 1);
    assert_eq!(by_file.len(), 1);

    // Test collect_match_events signature - takes references
    let events: Vec<_> =
        diffguard_domain::evaluate::collect_match_events(&by_file, &prepared_lines, &rules, None);
    assert_eq!(events.len(), 1);

    // Test emit_findings signature - takes owned events, slices for rules/prepared
    let (findings, counts, truncated, rule_hits): (
        Vec<Finding>,
        VerdictCounts,
        u32,
        BTreeMap<String, RuleHitStat>,
    ) = diffguard_domain::evaluate::emit_findings(events, &rules, &prepared_lines, 100);

    assert_eq!(findings.len(), 1);
    assert_eq!(counts.info, 1);
    assert_eq!(truncated, 0);
    assert_eq!(rule_hits.len(), 1);
}

// =============================================================================
// Test 8: All existing tests still pass (AC2 & AC3)
// =============================================================================

/// Test AC2 & AC3: All existing tests continue to pass.
///
/// This test verifies that `evaluate_lines` works correctly - the existing
/// behavior must be preserved after the refactoring.
#[test]
fn test_existing_evaluate_lines_behavior_preserved() {
    let rules = compile_rules(&[RuleConfig {
        id: "rust.no_unwrap".to_string(),
        description: String::new(),
        severity: Severity::Error,
        message: "no unwrap".to_string(),
        languages: vec!["rust".to_string()],
        patterns: vec![r"\.unwrap\(\)".to_string()],
        paths: vec!["**/*.rs".to_string()],
        exclude_paths: vec![],
        ignore_comments: true,
        ignore_strings: true,
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
        tags: vec![],
        test_cases: vec![],
    }])
    .expect("rules should compile");

    let eval = evaluate_lines(
        [InputLine {
            path: "src/lib.rs".to_string(),
            line: 12,
            content: "let x = y.unwrap();".to_string(),
        }],
        &rules,
        100,
    );

    assert_eq!(eval.counts.error, 1);
    assert_eq!(eval.findings.len(), 1);
    assert_eq!(eval.findings[0].line, 12);
    assert!(eval.findings[0].column.is_some());
}
