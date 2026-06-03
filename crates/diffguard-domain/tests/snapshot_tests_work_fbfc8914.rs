//! Snapshot tests for `RuleOverrideMatcher::resolve()` output baselines.
//!
//! These snapshots capture the deterministic output of `resolve()` for various
//! path/rule_id combinations to detect any output changes.
//!
//! The `ResolvedRuleOverride` struct contains:
//! - `enabled: bool` - Whether the rule is enabled for the path
//! - `severity: Option<Severity>` - Optional severity override

use diffguard_domain::overrides::{DirectoryRuleOverride, RuleOverrideMatcher};
use diffguard_types::Severity;

/// Helper to create override specs
fn override_spec(
    directory: &str,
    rule_id: &str,
    enabled: Option<bool>,
    severity: Option<Severity>,
    exclude_paths: Vec<&str>,
) -> DirectoryRuleOverride {
    DirectoryRuleOverride {
        directory: directory.to_string(),
        rule_id: rule_id.to_string(),
        enabled,
        severity,
        exclude_paths: exclude_paths.into_iter().map(|s| s.to_string()).collect(),
    }
}

/// Snapshot test: resolve unknown rule_id returns default
/// Default is `ResolvedRuleOverride { enabled: true, severity: None }`
#[test]
fn snapshot_resolve_unknown_rule_id() {
    use insta::assert_snapshot;

    let matcher = RuleOverrideMatcher::compile(&[]).expect("compile empty overrides");
    let result = matcher.resolve("src/lib.rs", "unknown.rule");

    let snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        result.enabled, result.severity
    );
    assert_snapshot!("resolve_unknown_rule_id", snapshot);
}

/// Snapshot test: resolve with root directory disable override
#[test]
fn snapshot_resolve_root_directory_disable() {
    use insta::assert_snapshot;

    let matcher = RuleOverrideMatcher::compile(&[override_spec(
        "",
        "rust.no_unwrap",
        Some(false),
        None,
        vec![],
    )])
    .expect("compile overrides");

    let result = matcher.resolve("src/lib.rs", "rust.no_unwrap");

    let snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        result.enabled, result.severity
    );
    assert_snapshot!("resolve_root_directory_disable", snapshot);
}

/// Snapshot test: resolve with root directory severity override
#[test]
fn snapshot_resolve_root_directory_severity() {
    use insta::assert_snapshot;

    let matcher = RuleOverrideMatcher::compile(&[override_spec(
        "",
        "rust.no_unwrap",
        None,
        Some(Severity::Error),
        vec![],
    )])
    .expect("compile overrides");

    let result = matcher.resolve("src/lib.rs", "rust.no_unwrap");

    let snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        result.enabled, result.severity
    );
    assert_snapshot!("resolve_root_directory_severity", snapshot);
}

/// Snapshot test: parent override disabled, child override re-enables with severity
#[test]
fn snapshot_resolve_parent_child_override_merge() {
    use insta::assert_snapshot;

    let matcher = RuleOverrideMatcher::compile(&[
        override_spec("src", "rust.no_unwrap", Some(false), None, vec![]),
        override_spec(
            "src/legacy",
            "rust.no_unwrap",
            Some(true),
            Some(Severity::Warn),
            vec![],
        ),
    ])
    .expect("compile overrides");

    // Path only matches parent
    let parent_result = matcher.resolve("src/new/mod.rs", "rust.no_unwrap");
    let parent_snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        parent_result.enabled, parent_result.severity
    );

    // Path matches child
    let child_result = matcher.resolve("src/legacy/mod.rs", "rust.no_unwrap");
    let child_snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        child_result.enabled, child_result.severity
    );

    let full_snapshot = format!(
        "parent_only: {}\nchild_override: {}",
        parent_snapshot, child_snapshot
    );
    assert_snapshot!("resolve_parent_child_override_merge", full_snapshot);
}

/// Snapshot test: exclude glob disables matching paths
#[test]
fn snapshot_resolve_exclude_glob_disables() {
    use insta::assert_snapshot;

    let matcher = RuleOverrideMatcher::compile(&[override_spec(
        "src",
        "rust.no_unwrap",
        None,
        None,
        vec!["**/generated/**"],
    )])
    .expect("compile overrides");

    // Path matches exclude glob
    let excluded = matcher.resolve("src/generated/file.rs", "rust.no_unwrap");
    let excluded_snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        excluded.enabled, excluded.severity
    );

    // Path does not match exclude glob
    let not_excluded = matcher.resolve("src/lib.rs", "rust.no_unwrap");
    let not_excluded_snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        not_excluded.enabled, not_excluded.severity
    );

    let full_snapshot = format!(
        "excluded: {}\nnot_excluded: {}",
        excluded_snapshot, not_excluded_snapshot
    );
    assert_snapshot!("resolve_exclude_glob_disables", full_snapshot);
}

/// Snapshot test: multiple rules with different overrides
#[test]
fn snapshot_resolve_multiple_rules() {
    use insta::assert_snapshot;

    let matcher = RuleOverrideMatcher::compile(&[
        override_spec("src", "rust.no_unwrap", Some(false), None, vec![]),
        override_spec("", "python.no_print", Some(false), None, vec![]),
    ])
    .expect("compile overrides");

    let rust_result = matcher.resolve("src/lib.rs", "rust.no_unwrap");
    let rust_snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        rust_result.enabled, rust_result.severity
    );

    let python_result = matcher.resolve("main.py", "python.no_print");
    let python_snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        python_result.enabled, python_result.severity
    );

    let full_snapshot = format!(
        "rust_rule: {}\npython_rule: {}",
        rust_snapshot, python_snapshot
    );
    assert_snapshot!("resolve_multiple_rules", full_snapshot);
}

/// Snapshot test: path normalization - ./ prefix is stripped
#[test]
fn snapshot_resolve_path_normalization() {
    use insta::assert_snapshot;

    let matcher = RuleOverrideMatcher::compile(&[override_spec(
        "src",
        "rust.no_unwrap",
        Some(false),
        None,
        vec![],
    )])
    .expect("compile overrides");

    // With ./ prefix
    let with_prefix = matcher.resolve("./src/lib.rs", "rust.no_unwrap");
    let with_prefix_snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        with_prefix.enabled, with_prefix.severity
    );

    // Without ./ prefix
    let without_prefix = matcher.resolve("src/lib.rs", "rust.no_unwrap");
    let without_prefix_snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        without_prefix.enabled, without_prefix.severity
    );

    let full_snapshot = format!(
        "with_prefix: {}\nwithout_prefix: {}",
        with_prefix_snapshot, without_prefix_snapshot
    );
    assert_snapshot!("resolve_path_normalization", full_snapshot);
}

/// Snapshot test: empty path resolves to root
#[test]
fn snapshot_resolve_empty_path() {
    use insta::assert_snapshot;

    let matcher = RuleOverrideMatcher::compile(&[override_spec(
        "",
        "rust.no_unwrap",
        Some(false),
        None,
        vec![],
    )])
    .expect("compile overrides");

    let result = matcher.resolve("", "rust.no_unwrap");

    let snapshot = format!(
        "ResolvedRuleOverride {{ enabled: {}, severity: {:?} }}",
        result.enabled, result.severity
    );
    assert_snapshot!("resolve_empty_path", snapshot);
}

/// Snapshot test: OverrideCompileError error message format
#[test]
fn snapshot_override_compile_error_message() {
    use insta::assert_snapshot;

    let err = RuleOverrideMatcher::compile(&[override_spec(
        "src",
        "rust.no_unwrap",
        None,
        None,
        vec!["["],
    )])
    .expect_err("invalid glob should fail");

    let snapshot = err.to_string();
    assert_snapshot!("override_compile_error_message", snapshot);
}
