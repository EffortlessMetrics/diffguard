//! Green edge case tests for work-0058c3c4: Add `#[must_use]` to `ConfigFile::built_in()`
//!
//! These tests complement the red tests by verifying edge cases not covered by them:
//! - Idempotency: Multiple calls return identical configs
//! - Clone: The returned ConfigFile can be cloned
//! - Partial use: The return value can be partially used
//!
//! The `#[must_use]` attribute is purely compile-time — it enables a warning if the
//! return value is discarded, but does not change runtime behavior. These tests
//! verify the runtime behavior is unchanged.

use diffguard_types::{ConfigFile, Defaults, Severity};

/// Test that calling `built_in()` twice returns identical configs.
///
/// This verifies idempotency: the compile-time embedded JSON is parsed
/// identically every time, producing equivalent `ConfigFile` instances.
#[test]
fn built_in_idempotent_multiple_calls_identical() {
    let cfg1 = ConfigFile::built_in();
    let cfg2 = ConfigFile::built_in();
    let cfg3 = ConfigFile::built_in();

    assert_eq!(cfg1, cfg2, "first and second call should be identical");
    assert_eq!(cfg2, cfg3, "second and third call should be identical");
}

/// Test that `built_in()` can be cloned.
///
/// The `#[must_use]` attribute should not prevent cloning the returned value.
/// This is a common operation when passing configs to multiple consumers.
#[test]
fn built_in_result_can_be_cloned() {
    let original = ConfigFile::built_in();
    let cloned = original.clone();

    assert_eq!(
        original, cloned,
        "cloned ConfigFile should be identical to original"
    );
    // Verify the clone is independent (modification doesn't affect original)
    let mut modified = cloned.clone();
    modified.rule.clear();
    assert_eq!(
        original.rule.len(),
        36,
        "clearing rules on modified copy should not affect original"
    );
}

/// Test that the defaults from `built_in()` are the standard defaults.
#[test]
fn built_in_defaults_are_standard() {
    let cfg = ConfigFile::built_in();

    // Verify defaults match Defaults::default()
    assert_eq!(cfg.defaults, Defaults::default());

    // Verify specific default values
    assert_eq!(cfg.defaults.base, Some("origin/main".to_string()));
    assert_eq!(cfg.defaults.head, Some("HEAD".to_string()));
    assert_eq!(cfg.defaults.scope, Some(diffguard_types::Scope::Added));
    assert_eq!(cfg.defaults.fail_on, Some(diffguard_types::FailOn::Error));
    assert_eq!(cfg.defaults.max_findings, Some(200));
    assert_eq!(cfg.defaults.diff_context, Some(0));
}

/// Test that `built_in()` returns a config where includes is empty.
#[test]
fn built_in_includes_are_empty() {
    let cfg = ConfigFile::built_in();
    assert!(
        cfg.includes.is_empty(),
        "built_in() should have empty includes, got {:?}",
        cfg.includes
    );
}

/// Test that every rule in `built_in()` has a non-empty ID and valid severity.
///
/// This extends `built_in_returns_config_with_36_rules` by checking each rule.
#[test]
fn built_in_rules_have_valid_ids_and_severities() {
    let cfg = ConfigFile::built_in();

    for rule in &cfg.rule {
        assert!(!rule.id.is_empty(), "rule ID should be non-empty");
        assert!(
            matches!(
                rule.severity,
                Severity::Info | Severity::Warn | Severity::Error
            ),
            "rule '{}' has invalid severity: {:?}",
            rule.id,
            rule.severity
        );
    }
}

/// Test that `built_in()` can be serialized to JSON and deserialized back.
///
/// This verifies the ConfigFile is a valid serde serializable type.
#[test]
fn built_in_round_trip_serialization() {
    let original = ConfigFile::built_in();

    // Serialize to JSON string
    let json =
        serde_json::to_string(&original).expect("ConfigFile::built_in() should serialize to JSON");

    // Deserialize back
    let deserialized: ConfigFile =
        serde_json::from_str(&json).expect("ConfigFile JSON should be deserializable");

    assert_eq!(original, deserialized);
}

/// Test that `built_in()` result can be partially used without warning.
///
/// When only some fields of the returned value are used, #[must_use] should
/// still not warn because the value IS being used (just not completely).
#[test]
fn built_in_partial_use_is_valid() {
    let cfg = ConfigFile::built_in();

    // Using only the rule count - this should NOT trigger #[must_use] warning
    // because the value IS being used (the compiler only warns when the
    // return value is completely discarded, e.g., `ConfigFile::built_in();`)
    let _rule_count = cfg.rule.len();

    // Using only the defaults
    let _defaults = cfg.defaults;

    // Using only the includes
    let _includes = cfg.includes;
}

/// Test that `built_in()` is Send + Sync (required for concurrent use).
///
/// This verifies the returned ConfigFile can be used in multithreaded contexts.
#[test]
fn built_in_result_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ConfigFile>();

    // Also verify the actual built_in() result is Send + Sync
    let cfg = ConfigFile::built_in();
    assert_send_sync::<ConfigFile>();
    // Silence unused warning by using cfg
    let _ = cfg;
}

/// Test that the `#[must_use]` count is still correct after refactoring.
///
/// This is a sanity check that no other `#[must_use]` attributes were added
/// or removed accidentally.
#[test]
fn must_use_count_remains_four() {
    let source = include_str!("../src/lib.rs");
    let count = source.matches("#[must_use]").count();

    assert_eq!(
        count, 4,
        "Expected exactly 4 #[must_use] attributes (3 as_str + 1 built_in)"
    );
}

/// Test that `Severity::as_str` and `ConfigFile::built_in` both have `#[must_use]`.
///
/// This verifies the consistency of the `#[must_use]` pattern across different
/// return types (`&'static str` vs `Self`).
#[test]
fn must_use_attribute_consistency() {
    let source = include_str!("../src/lib.rs");

    // Find lines with #[must_use]
    let must_use_lines: Vec<usize> = source
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("#[must_use]"))
        .map(|(i, _)| i + 1) // 1-indexed
        .collect();

    // Should have 4 occurrences at expected line numbers
    assert_eq!(must_use_lines.len(), 4);

    // The #[must_use] should appear above Severity::as_str, Scope::as_str,
    // FailOn::as_str, and ConfigFile::built_in()
    // We verify by checking these function definitions exist nearby
    assert!(source.contains("#[must_use]\n    pub fn as_str(self) -> &'static str"));
    assert!(source.contains("#[must_use]\n    pub fn built_in() -> Self"));
}
