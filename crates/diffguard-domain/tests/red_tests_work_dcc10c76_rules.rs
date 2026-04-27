//! Red tests for work-dcc10c76: GlobSetBuilder::build() error handling in rules.rs
//!
//! These tests verify that `compile_rules` properly returns `RuleCompileError::GlobSetBuild`
//! when `GlobSetBuilder::build()` fails, instead of panicking via `.expect()`.
//!
//! These tests are RED: they fail now (due to `.expect()` panic) and will pass after the fix.

use diffguard_domain::compile_rules;
use diffguard_types::{RuleConfig, Severity};

/// Create a minimal RuleConfig for testing.
fn test_rule_config(rule_id: &str, paths: Vec<String>, patterns: Vec<String>) -> RuleConfig {
    RuleConfig {
        id: rule_id.to_string(),
        description: String::new(),
        severity: Severity::Error,
        message: "test".to_string(),
        languages: vec!["text".to_string()],
        patterns,
        paths,
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
    }
}

#[test]
fn test_compile_rules_returns_globsetbuild_error_on_too_many_globs() {
    // Generate a large number of glob patterns to attempt to trigger
    // GlobSetBuilder::build() overflow error.
    // 50,000 simple patterns like **/pattern_{}/** triggers NFA overflow.
    let many_globs: Vec<String> = (0..50_000)
        .map(|i| format!("**/pattern_{}/**", i))
        .collect();

    let cfg = test_rule_config("test.rule", many_globs, vec!["test".to_string()]);

    // Before fix: compile_rules will panic due to .expect() in compile_globs
    // After fix: compile_rules will return Err(RuleCompileError::GlobSetBuild {...})
    let result = compile_rules(&[cfg]);

    // This assertion will only be reached after the fix
    assert!(
        result.is_err(),
        "compile_rules should return an error when GlobSetBuilder::build() fails, not panic"
    );

    let error = result.unwrap_err();
    let error_str = error.to_string();

    // Verify the error message mentions glob set build failure
    assert!(
        error_str.contains("glob") && error_str.contains("build"),
        "Error should mention glob set build failure, got: {}",
        error_str
    );
}

#[test]
fn test_compile_rules_returns_globsetbuild_error_on_exclude_overflow() {
    // Generate many exclude paths to trigger overflow in compile_globs for exclude paths.
    // 50,000 simple patterns like **/exclude_{}/** triggers NFA overflow.
    let many_exclude_globs: Vec<String> = (0..50_000)
        .map(|i| format!("**/exclude_{}/**", i))
        .collect();

    let cfg = test_rule_config(
        "test.rule",
        vec!["**/*.txt".to_string()],
        vec!["test".to_string()],
    );
    let cfg_with_excludes = RuleConfig {
        exclude_paths: many_exclude_globs,
        ..cfg
    };

    // Before fix: compile_rules will panic due to .expect() in compile_globs
    // After fix: compile_rules will return Err(RuleCompileError::GlobSetBuild {...})
    let result = compile_rules(&[cfg_with_excludes]);

    // This assertion will only be reached after the fix
    assert!(
        result.is_err(),
        "compile_rules should return an error when exclude GlobSetBuilder::build() fails"
    );

    let error = result.unwrap_err();
    let error_str = error.to_string();

    // Verify the error message mentions glob set build failure
    assert!(
        error_str.contains("glob") && error_str.contains("build"),
        "Error should mention glob set build failure, got: {}",
        error_str
    );
}
