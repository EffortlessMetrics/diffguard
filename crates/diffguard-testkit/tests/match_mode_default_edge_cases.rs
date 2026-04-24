//! Edge case tests for MatchMode::default() behavior.
//!
//! These tests verify that `MatchMode::default()` returns `MatchMode::Any`
//! and that fixtures using `MatchMode::default()` produce valid RuleConfigs.
//!
//! This is a green-test-builder edge case test to ensure the lint fix
//! doesn't break the semantic contract of MatchMode's Default implementation.

use diffguard_types::{MatchMode, RuleConfig, Severity};

/// Test that MatchMode::default() returns MatchMode::Any.
///
/// This is the semantic contract that the lint fix relies on.
/// If this test fails, the fixtures and arbitrary generators would
/// produce incorrect RuleConfigs.
#[test]
fn match_mode_default_is_any() {
    let default_mode = MatchMode::default();
    let any_mode = MatchMode::Any;
    assert_eq!(
        default_mode, any_mode,
        "MatchMode::default() should return MatchMode::Any, but got {:?}",
        default_mode
    );
}

/// Test that a RuleConfig created with MatchMode::default() has match_mode = Any.
#[test]
fn rule_config_with_default_match_mode_has_any() {
    let rule = RuleConfig {
        id: "test.rule".to_string(),
        severity: Severity::Warn,
        message: "Test".to_string(),
        description: String::new(),
        languages: vec![],
        patterns: vec!["test".to_string()],
        paths: vec![],
        exclude_paths: vec![],
        ignore_comments: false,
        ignore_strings: false,
        match_mode: MatchMode::default(),
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

    assert_eq!(
        rule.match_mode,
        MatchMode::Any,
        "RuleConfig created with MatchMode::default() should have match_mode = Any"
    );
}

/// Test that MatchMode can be compared for equality.
#[test]
fn match_mode_equality() {
    assert_eq!(MatchMode::default(), MatchMode::Any);
    assert_eq!(MatchMode::Absent, MatchMode::Absent);
    assert_ne!(MatchMode::default(), MatchMode::Absent);
}

/// Test that the fixture configs using MatchMode::default() have match_mode = Any.
#[test]
fn fixture_configs_use_match_mode_any() {
    use diffguard_testkit::fixtures::sample_configs;

    // Test minimal config
    let minimal = sample_configs::minimal();
    assert!(!minimal.rule.is_empty());
    assert_eq!(
        minimal.rule[0].match_mode,
        MatchMode::Any,
        "minimal config should use MatchMode::Any"
    );

    // Test all_severities config
    let all_sev = sample_configs::all_severities();
    for rule in &all_sev.rule {
        assert_eq!(
            rule.match_mode,
            MatchMode::Any,
            "all_severities config rule {} should use MatchMode::Any",
            rule.id
        );
    }
}
