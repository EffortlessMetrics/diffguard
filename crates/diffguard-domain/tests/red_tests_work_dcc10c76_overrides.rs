//! Red tests for work-dcc10c76: GlobSetBuilder::build() error handling in overrides.rs
//!
//! These tests verify that `RuleOverrideMatcher::compile` properly returns
//! `OverrideCompileError::GlobSetBuild` when `GlobSetBuilder::build()` fails,
//! instead of panicking via `.expect()`.
//!
//! These tests are RED: they fail now (due to `.expect()` panic) and will pass after the fix.

use diffguard_domain::{DirectoryRuleOverride, RuleOverrideMatcher};
use diffguard_types::Severity;

/// Create a minimal DirectoryRuleOverride for testing.
fn test_override(
    directory: &str,
    rule_id: &str,
    exclude_paths: Vec<String>,
) -> DirectoryRuleOverride {
    DirectoryRuleOverride {
        directory: directory.to_string(),
        rule_id: rule_id.to_string(),
        enabled: Some(true),
        severity: Some(Severity::Warn),
        exclude_paths,
    }
}

#[test]
fn test_override_compile_returns_globsetbuild_error_on_too_many_exclude_globs() {
    // Generate many exclude glob patterns to trigger overflow in compile_exclude_globs.
    // 50,000 simple patterns like **/pattern_{}/** triggers NFA overflow.
    let many_exclude_globs: Vec<String> = (0..50_000)
        .map(|i| format!("**/pattern_{}/**", i))
        .collect();

    let override_spec = test_override("src", "rust.no_unwrap", many_exclude_globs);

    // Before fix: RuleOverrideMatcher::compile will panic due to .expect() in compile_exclude_globs
    // After fix: compile will return Err(OverrideCompileError::GlobSetBuild {...})
    let result = RuleOverrideMatcher::compile(&[override_spec]);

    // This assertion will only be reached after the fix
    assert!(
        result.is_err(),
        "compile should return an error when GlobSetBuilder::build() fails, not panic"
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
