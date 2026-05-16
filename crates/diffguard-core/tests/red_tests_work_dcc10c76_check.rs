//! Red tests for work-dcc10c76: GlobSetBuilder::build() error handling in check.rs
//!
//! These tests verify that `run_check` properly returns `PathFilterError::GlobSetBuild`
//! when `GlobSetBuilder::build()` fails in `compile_filter_globs`,
//! instead of panicking via `.expect()`.
//!
//! These tests are RED: they fail now (due to `.expect()` panic) and will pass after the fix.

use diffguard_core::{CheckPlan, run_check};
use diffguard_types::{ConfigFile, Defaults, FailOn, RuleConfig, Scope};

/// Create a minimal CheckPlan for testing with path filters.
fn test_check_plan(path_filters: Vec<String>) -> CheckPlan {
    CheckPlan {
        base: "HEAD~1".to_string(),
        head: "HEAD".to_string(),
        scope: Scope::Changed,
        diff_context: 3,
        fail_on: FailOn::Error,
        max_findings: 100,
        path_filters,
        only_tags: vec![],
        enable_tags: vec![],
        disable_tags: vec![],
        directory_overrides: vec![],
        force_language: None,
        allowed_lines: None,
        false_positive_fingerprints: Default::default(),
    }
}

/// Create a minimal ConfigFile for testing.
fn test_config_file() -> ConfigFile {
    ConfigFile {
        includes: vec![],
        defaults: Defaults::default(),
        rule: vec![RuleConfig {
            id: "test.rule".to_string(),
            description: String::new(),
            severity: diffguard_types::Severity::Error,
            message: "test".to_string(),
            languages: vec!["text".to_string()],
            patterns: vec!["test".to_string()],
            paths: vec!["**/*.txt".to_string()],
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
        }],
    }
}

/// A minimal unified diff for testing.
const TEST_DIFF: &str = r#"--- a/test.txt
+++ b/test.txt
@@ -1 +1 @@
-old line
+new line
"#;

#[test]
fn test_run_check_returns_globsetbuild_error_on_too_many_path_filters() {
    // Generate many path filter globs to trigger overflow in compile_filter_globs.
    // 50,000 simple patterns like **/pattern_{}/** triggers NFA overflow.
    let many_path_filters: Vec<String> = (0..50_000)
        .map(|i| format!("**/pattern_{}/**", i))
        .collect();

    let plan = test_check_plan(many_path_filters);
    let config = test_config_file();

    // Before fix: run_check will panic due to .expect() in compile_filter_globs
    // After fix: run_check will return Err(PathFilterError::GlobSetBuild {...})
    let result = run_check(&plan, &config, TEST_DIFF);

    // This assertion will only be reached after the fix
    assert!(
        result.is_err(),
        "run_check should return an error when GlobSetBuilder::build() fails, not panic"
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
