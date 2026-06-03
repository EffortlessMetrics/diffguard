//! Red tests for work-95bdb9f2: RuleOverrideMatcher::resolve() #[must_use]
//!
//! Issue #538: `RuleOverrideMatcher::resolve()` was missing `#[must_use]`.
//! The return type `ResolvedRuleOverride` carries meaningful state —
//! `enabled: bool` and `severity: Option<Severity>` — and discarding it means
//! callers operate with defaults instead of the configured override.
//!
//! This is a correctness bug: callers who write `m.resolve(path, &rule.id)`
//! without assigning the result silently lose override configuration.
//!
//! The fix (PR #532, commit e0c2094) added `#[must_use]` to `resolve()`.
//! These tests verify the CORRECT behavior that `#[must_use]` protects.

use diffguard_domain::overrides::{DirectoryRuleOverride, RuleOverrideMatcher};
use diffguard_types::Severity;

/// Helper to create override specs for tests.
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

/// Verifies that `resolve()` returns meaningful state that MUST be used.
///
/// When a rule override sets `enabled: false`, callers MUST check the
/// returned `ResolvedRuleOverride.enabled` to skip the rule. If the return
/// value were silently discarded, the rule would run with default `enabled: true`.
///
/// This test verifies the resolved override carries the correct `enabled` state.
#[test]
fn test_resolve_returns_meaningful_enabled_state() {
    let matcher =
        RuleOverrideMatcher::compile(&[override_spec("src", "rust.no_unwrap", Some(false), None)])
            .expect("compile overrides");

    // The resolved override MUST be used by callers
    let resolved = matcher.resolve("src/lib.rs", "rust.no_unwrap");

    // If #[must_use] is missing and caller discards this, the rule runs
    // with default enabled=true, which is WRONG for this override.
    assert!(
        !resolved.enabled,
        "Override set enabled=false, resolve() returned enabled={}. \
         Callers MUST use this value or the override is silently ignored.",
        resolved.enabled
    );
}

/// Verifies that `resolve()` returns meaningful severity state.
///
/// When a rule override sets a severity, callers MUST use the returned
/// `ResolvedRuleOverride.severity` to apply the override. If the return
/// value were silently discarded, the rule would use its original severity.
///
/// This test verifies the resolved override carries the correct severity.
#[test]
fn test_resolve_returns_meaningful_severity_state() {
    let matcher = RuleOverrideMatcher::compile(&[override_spec(
        "src",
        "rust.no_unwrap",
        None,
        Some(Severity::Info),
    )])
    .expect("compile overrides");

    let resolved = matcher.resolve("src/lib.rs", "rust.no_unwrap");

    // If #[must_use] is missing and caller discards this, the rule uses
    // its original severity, ignoring the override.
    assert_eq!(
        resolved.severity,
        Some(Severity::Info),
        "Override set severity=Info, resolve() returned {:?}. \
         Callers MUST use this value or the override is silently ignored.",
        resolved.severity
    );
}

/// Verifies that `resolve()` default values are meaningful.
///
/// When no override exists for a (path, rule_id) pair, resolve() returns
/// `ResolvedRuleOverride { enabled: true, severity: None }` (the default).
/// Callers MUST check this default to determine if an override applies.
///
/// This test documents the default behavior that must be respected.
#[test]
fn test_resolve_returns_default_when_no_override() {
    let matcher = RuleOverrideMatcher::compile(&[]).expect("compile overrides");

    let resolved = matcher.resolve("src/lib.rs", "rust.no_unwrap");

    // Default is enabled=true (rule runs) with no severity override
    assert!(
        resolved.enabled,
        "Default enabled should be true (rule runs), got {}",
        resolved.enabled
    );
    assert_eq!(
        resolved.severity, None,
        "Default severity should be None (use rule's original), got {:?}",
        resolved.severity
    );
}

/// Verifies that `resolve()` properly merges parent and child directory overrides.
///
/// Child directory overrides should override parent directory overrides.
/// This is the depth-order merge behavior that callers MUST respect.
#[test]
fn test_resolve_merges_override_in_depth_order() {
    let matcher = RuleOverrideMatcher::compile(&[
        // Parent: disable the rule
        override_spec("src", "rust.no_unwrap", Some(false), None),
        // Child: re-enable with Info severity
        override_spec(
            "src/legacy",
            "rust.no_unwrap",
            Some(true),
            Some(Severity::Info),
        ),
    ])
    .expect("compile overrides");

    // Parent directory override applies
    let parent_resolved = matcher.resolve("src/new/mod.rs", "rust.no_unwrap");
    assert!(
        !parent_resolved.enabled,
        "Parent override (enabled=false) should apply, got enabled={}",
        parent_resolved.enabled
    );
    assert_eq!(
        parent_resolved.severity, None,
        "Parent override has no severity, got {:?}",
        parent_resolved.severity
    );

    // Child directory override overrides parent
    let child_resolved = matcher.resolve("src/legacy/mod.rs", "rust.no_unwrap");
    assert!(
        child_resolved.enabled,
        "Child override (enabled=true) should override parent, got enabled={}",
        child_resolved.enabled
    );
    assert_eq!(
        child_resolved.severity,
        Some(Severity::Info),
        "Child override (severity=Info) should override parent, got {:?}",
        child_resolved.severity
    );
}

/// Verifies that root directory override (empty path) applies everywhere.
///
/// An override with directory="" (root) should apply to all paths.
/// Callers MUST use the resolved override or this global override is ignored.
#[test]
fn test_resolve_root_directory_override_applies_everywhere() {
    let matcher =
        RuleOverrideMatcher::compile(&[override_spec("", "rust.no_unwrap", Some(false), None)])
            .expect("compile overrides");

    // Root override should apply to any path
    let resolved_anywhere = matcher.resolve("src/lib.rs", "rust.no_unwrap");
    assert!(
        !resolved_anywhere.enabled,
        "Root override (enabled=false) should apply to all paths, got enabled={}",
        resolved_anywhere.enabled
    );

    let resolved_deep = matcher.resolve("src/deep/nested/file.rs", "rust.no_unwrap");
    assert!(
        !resolved_deep.enabled,
        "Root override should apply to deeply nested paths, got enabled={}",
        resolved_deep.enabled
    );
}

/// Verifies that a rule with no matching override uses default behavior.
///
/// This is the baseline case: no override spec exists, so resolve() returns
/// the default. Callers MUST handle this default correctly.
#[test]
fn test_resolve_no_matching_rule_returns_default() {
    let matcher =
        RuleOverrideMatcher::compile(&[override_spec("src", "other.rule", Some(false), None)])
            .expect("compile overrides");

    // No override for "rust.no_unwrap" - should get default
    let resolved = matcher.resolve("src/lib.rs", "rust.no_unwrap");
    assert!(
        resolved.enabled,
        "No override means default enabled=true, got {}",
        resolved.enabled
    );
    assert_eq!(
        resolved.severity, None,
        "No override means default severity=None, got {:?}",
        resolved.severity
    );
}
