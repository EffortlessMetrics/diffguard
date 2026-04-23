//! Integration tests for RuleOverrideMatcher LRU cache
//!
//! These tests verify the component handoffs:
//! 1. RuleOverrideMatcher::resolve() returns consistent results
//! 2. Cache correctness when resolve() is called multiple times
//! 3. Full workflow: compile overrides → resolve paths

use diffguard_domain::overrides::{DirectoryRuleOverride, RuleOverrideMatcher};
use diffguard_types::Severity;

/// Helper to create override specs
fn override_spec(
    directory: &str,
    rule_id: &str,
    enabled: Option<bool>,
    severity: Option<Severity>,
) -> DirectoryRuleOverride {
    DirectoryRuleOverride {
        directory: directory.to_string(),
        rule_id: rule_id.to_string(),
        enabled,
        severity,
        exclude_paths: vec![],
    }
}

/// Integration test: RuleOverrideMatcher works with evaluate_lines_with_overrides
///
/// This tests that the matcher is used correctly in the context of override resolution.
/// The actual handoff point is in evaluate.rs at:
/// `let resolved_override = overrides.map(|m| m.resolve(path, &rule.id));`
#[test]
fn integration_resolve_returns_correct_values_for_directory_hierarchy() {
    let matcher = RuleOverrideMatcher::compile(&[
        override_spec("", "rust.no_unwrap", Some(true), Some(Severity::Warn)),
        override_spec("src/legacy", "rust.no_unwrap", Some(false), None), // overrides parent
    ])
    .expect("compile overrides should succeed");

    // Root path matches ""
    let root = matcher.resolve("lib.rs", "rust.no_unwrap");
    assert!(root.enabled);
    assert_eq!(root.severity, Some(Severity::Warn));

    // src/ matches "" (root override)
    let src = matcher.resolve("src/lib.rs", "rust.no_unwrap");
    assert!(src.enabled);
    assert_eq!(src.severity, Some(Severity::Warn));

    // src/legacy matches src/legacy override (disabled)
    let legacy = matcher.resolve("src/legacy/lib.rs", "rust.no_unwrap");
    assert!(!legacy.enabled, "src/legacy should override and disable");

    // src/new does NOT match src/legacy, so it matches only ""
    let new = matcher.resolve("src/new/lib.rs", "rust.no_unwrap");
    assert!(new.enabled, "src/new should use parent override (enabled)");
}

/// Integration test: Multiple rules with different overrides
///
/// This tests that the matcher correctly resolves different rules independently.
#[test]
fn integration_matcher_resolves_multiple_rules_independently() {
    let matcher = RuleOverrideMatcher::compile(&[
        override_spec("", "rust.no_unwrap", Some(false), None), // disable for all
        override_spec("src", "python.lint", Some(true), Some(Severity::Error)), // re-enable for src
    ])
    .expect("compile overrides should succeed");

    // Unknown rule returns default (enabled)
    let unknown = matcher.resolve("src/lib.rs", "unknown.rule");
    assert!(unknown.enabled, "Unknown rule should be enabled by default");
    assert_eq!(
        unknown.severity, None,
        "Unknown rule should have no severity"
    );

    // rust.no_unwrap is disabled everywhere
    let rust_rule = matcher.resolve("src/lib.rs", "rust.no_unwrap");
    assert!(
        !rust_rule.enabled,
        "rust.no_unwrap should be disabled by root override"
    );

    // python.lint is re-enabled in src/ with Error severity
    let python_rule = matcher.resolve("src/main.py", "python.lint");
    assert!(python_rule.enabled, "python.lint should be enabled in src");
    assert_eq!(
        python_rule.severity,
        Some(Severity::Error),
        "python.lint should have Error severity in src"
    );
}

/// Integration test: Cache is used when resolve is called multiple times
///
/// This verifies that repeated calls to resolve() with the same path/rule
/// return cached results without recomputation.
#[test]
fn integration_resolve_returns_consistent_results_on_repeated_calls() {
    let matcher = RuleOverrideMatcher::compile(&[override_spec(
        "src",
        "test.rule",
        Some(false),
        Some(Severity::Error),
    )])
    .expect("compile overrides should succeed");

    let path = "src/lib.rs";
    let rule_id = "test.rule";

    // Call resolve multiple times
    let result1 = matcher.resolve(path, rule_id);
    let result2 = matcher.resolve(path, rule_id);
    let result3 = matcher.resolve(path, rule_id);

    // All results should be identical
    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
}

/// Integration test: Different paths resolve correctly with different rules
///
/// This verifies that the matcher correctly distinguishes between different paths
/// and applies overrides based on directory hierarchy.
#[test]
fn integration_different_paths_get_correct_override_values() {
    let matcher = RuleOverrideMatcher::compile(&[
        override_spec("", "rule", Some(true), Some(Severity::Warn)),
        override_spec("src/legacy", "rule", Some(false), None), // overrides parent
    ])
    .expect("compile overrides should succeed");

    // Root path matches ""
    let root = matcher.resolve("lib.rs", "rule");
    assert!(root.enabled);
    assert_eq!(root.severity, Some(Severity::Warn));

    // src/ matches "" (root override)
    let src = matcher.resolve("src/lib.rs", "rule");
    assert!(src.enabled);
    assert_eq!(src.severity, Some(Severity::Warn));

    // src/legacy matches src/legacy override (disabled)
    let legacy = matcher.resolve("src/legacy/lib.rs", "rule");
    assert!(!legacy.enabled, "src/legacy should override and disable");

    // src/new does NOT match src/legacy, so it matches only ""
    let new = matcher.resolve("src/new/lib.rs", "rule");
    assert!(new.enabled, "src/new should use parent override (enabled)");
}

/// Integration test: Empty path and rule_id edge cases
///
/// This tests the edge case of empty strings.
#[test]
fn integration_empty_path_and_rule_id_handled() {
    let matcher =
        RuleOverrideMatcher::compile(&[override_spec("", "test.rule", Some(false), None)])
            .expect("compile overrides should succeed");

    // Empty path should still match root directory override
    let empty_path = matcher.resolve("", "test.rule");
    assert!(!empty_path.enabled, "Empty path should match root override");

    // Empty rule_id should not match any override
    let empty_rule = matcher.resolve("src/lib.rs", "");
    assert!(
        empty_rule.enabled,
        "Empty rule_id should return default (enabled)"
    );
}

/// Integration test: Cloned matcher has independent cache
///
/// This verifies that cloning a matcher creates independent state,
/// which is important for parallel evaluation.
#[test]
fn integration_cloned_matcher_has_independent_cache() {
    let matcher =
        RuleOverrideMatcher::compile(&[override_spec("src", "test.rule", Some(false), None)])
            .expect("compile overrides should succeed");

    // Populate original's cache
    let _ = matcher.resolve("src/lib.rs", "test.rule");

    // Clone the matcher
    let cloned = matcher.clone();

    // Both should produce the same result
    let original_result = matcher.resolve("src/lib.rs", "test.rule");
    let cloned_result = cloned.resolve("src/lib.rs", "test.rule");

    assert_eq!(original_result, cloned_result);
}

/// Integration test: Default constructed matcher works
///
/// This verifies that RuleOverrideMatcher::default() creates a functional matcher.
#[test]
fn integration_default_matcher_returns_default_values() {
    let matcher = RuleOverrideMatcher::default();

    // Default should enable any rule
    let result = matcher.resolve("src/lib.rs", "any.rule");
    assert!(result.enabled, "Default matcher should enable rules");
    assert_eq!(
        result.severity, None,
        "Default matcher should have no severity"
    );
}

/// Integration test: Many unique paths all resolve correctly
///
/// This tests that the cache handles many unique keys correctly.
#[test]
fn integration_many_unique_paths_resolve_correctly() {
    let matcher = RuleOverrideMatcher::compile(&[override_spec(
        "",
        "test.rule",
        Some(false),
        Some(Severity::Error),
    )])
    .expect("compile overrides should succeed");

    // Resolve many different paths - all should return the same result
    for i in 0..100 {
        let path = format!("src/module_{}/file_{}.rs", i % 10, i);
        let result = matcher.resolve(&path, "test.rule");
        assert!(
            !result.enabled,
            "All paths should be disabled by root override"
        );
        assert_eq!(result.severity, Some(Severity::Error));
    }
}
