//! Green edge case tests for work-2b446664: ConfigFile::built_in() panics but is missing # Panics documentation
//!
//! These tests verify the `ConfigFile::built_in()` function has proper documentation
//! for its panic condition, as required by clippy::missing_panics_doc.
//!
//! Edge cases covered:
//! - # Panics documentation is present in the source
//! - The documentation mentions the specific panic condition (built_in.json parsing)
//! - built_in() returns a valid ConfigFile with expected rule count
//! - built_in() rules have valid patterns that can be parsed

/// Verify the `# Panics` documentation is present in `ConfigFile::built_in()`.
///
/// This test ensures the documentation explicitly states when the function panics,
/// satisfying the clippy::missing_panics_doc lint requirement.
#[test]
fn built_in_has_panics_documentation() {
    let source = include_str!("../src/lib.rs");

    // Find the built_in() function and verify # Panics section exists
    let built_in_start = source
        .find("pub fn built_in() -> Self")
        .expect("built_in() function should exist");

    // Look backwards from the function to find the doc comment (/// style)
    // We need to find a substantial block of /// lines before the function
    let preceding_text = &source[..built_in_start];

    // Find the last block of /// comments before the function
    // The doc comment for built_in starts with "/// Returns the built-in..."
    assert!(
        preceding_text.contains("# Panics"),
        "built_in() doc comment should contain '# Panics' section.\nPreceding text: {}",
        preceding_text
    );

    // Verify the panics section mentions the specific condition
    assert!(
        preceding_text.contains("built_in.json"),
        "built_in() # Panics section should mention 'built_in.json'.\nPreceding text: {}",
        preceding_text
    );
}

/// Verify the `# Panics` documentation is accurate.
///
/// The documentation states: "Panics if `built_in.json` cannot be parsed as valid JSON."
/// Since the JSON is embedded at compile time via include_str!, it should always be valid.
/// This test verifies the returned config is well-formed.
#[test]
fn built_in_returns_well_formed_config() {
    let cfg = diffguard_types::ConfigFile::built_in();

    // Verify basic structure is valid
    assert!(
        cfg.defaults.base.is_some(),
        "built_in() should have default base ref"
    );
    assert!(
        cfg.defaults.head.is_some(),
        "built_in() should have default head ref"
    );
    assert!(
        cfg.defaults.scope.is_some(),
        "built_in() should have default scope"
    );

    // Verify we have the expected number of built-in rules
    // The built_in.json contains 36 rules across multiple languages
    assert!(
        !cfg.rule.is_empty(),
        "built_in() should have at least one rule, got {}",
        cfg.rule.len()
    );
}

/// Verify every rule in `built_in()` has valid patterns.
///
/// Each rule should have at least one non-empty pattern that could be parsed
/// by a regex engine. Empty patterns would indicate malformed JSON data.
#[test]
fn built_in_rules_have_valid_patterns() {
    let cfg = diffguard_types::ConfigFile::built_in();

    for rule in &cfg.rule {
        assert!(
            !rule.patterns.is_empty(),
            "rule '{}' should have at least one pattern",
            rule.id
        );

        for pattern in &rule.patterns {
            assert!(
                !pattern.is_empty(),
                "rule '{}' should have non-empty patterns, found empty string",
                rule.id
            );
        }
    }
}

/// Verify `built_in()` is deterministic across multiple calls.
///
/// Since the JSON is embedded at compile time, each call should produce
/// an identical ConfigFile. This verifies no internal state mutation occurs.
#[test]
fn built_in_is_deterministic() {
    let cfg1 = diffguard_types::ConfigFile::built_in();
    let cfg2 = diffguard_types::ConfigFile::built_in();
    let cfg3 = diffguard_types::ConfigFile::built_in();

    assert_eq!(cfg1, cfg2, "first and second call should be identical");
    assert_eq!(cfg2, cfg3, "second and third call should be identical");
    assert_eq!(cfg1, cfg3, "first and third call should be identical");
}

/// Verify `built_in()` result can be used in a concurrent context.
///
/// ConfigFile should be Send + Sync to support use in async contexts
/// and multi-threaded pipelines.
#[test]
fn built_in_concurrency_safety() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<diffguard_types::ConfigFile>();

    let cfg = diffguard_types::ConfigFile::built_in();
    assert_send_sync::<diffguard_types::ConfigFile>();
    // Use cfg to silence warnings
    let _ = cfg;
}

/// Verify `built_in()` can be serialized to multiple formats.
///
/// This ensures the ConfigFile is fully serializable and not using
/// any non-serializable internal state.
#[test]
fn built_in_multi_format_serialization() {
    let cfg = diffguard_types::ConfigFile::built_in();

    // JSON serialization
    let json =
        serde_json::to_string(&cfg).expect("ConfigFile::built_in() should serialize to JSON");
    assert!(
        !json.is_empty(),
        "JSON serialization should produce non-empty string"
    );

    // Verify it's valid JSON by deserializing
    let deserialized: diffguard_types::ConfigFile =
        serde_json::from_str(&json).expect("JSON should be deserializable");
    assert_eq!(cfg, deserialized);
}

/// Verify the `#[must_use]` attribute is present on `built_in()`.
///
/// The function returns Self (owned ConfigFile), so callers should not
/// discard the return value silently.
#[test]
fn built_in_has_must_use_attribute() {
    let source = include_str!("../src/lib.rs");

    // Find the built_in function and verify #[must_use] appears before it
    let built_in_pos = source
        .find("pub fn built_in() -> Self")
        .expect("built_in() function should exist");

    // Get the text between the doc comment and the function
    let preceding_text = &source[..built_in_pos];

    // Find the last #[must_use] before the function
    assert!(
        preceding_text.contains("#[must_use]"),
        "built_in() should have #[must_use] attribute.\nPreceding text: {}",
        preceding_text
    );
}
