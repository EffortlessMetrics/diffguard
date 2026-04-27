// Red Test Builder: work-a98db3d3
// Tests for `ignore_comments` and `ignore_strings` fields in `Defaults` struct
//
// These tests define the expected behavior and will PASS once the implementation is complete.
// Currently they FAIL because:
// - `Defaults` struct lacks `ignore_comments` and `ignore_strings` fields
// - `Defaults::default()` doesn't return `None` for these fields
//
// Scope: These tests only cover the diffguard-types crate (schema-only change).
// The merge_configs() function lives in the diffguard crate and is tested separately.

use diffguard_types::{Defaults, FailOn, Scope};

/// Test that `Defaults::default()` returns `None` for `ignore_comments` and `ignore_strings`.
/// This verifies the schema change: these fields should be `Option<bool>` in `Defaults`.
#[test]
fn test_defaults_default_returns_none_for_ignore_comments_and_ignore_strings() {
    let defaults = Defaults::default();

    // These assertions will FAIL if the fields don't exist or aren't Option<bool>
    assert_eq!(
        defaults.ignore_comments, None,
        "Defaults::default().ignore_comments should be None"
    );
    assert_eq!(
        defaults.ignore_strings, None,
        "Defaults::default().ignore_strings should be None"
    );
}

/// Test that `Defaults` can hold `Some(true)` and `Some(false)` values for the new fields.
#[test]
fn test_defaults_serialization_json_with_ignore_flags_true() {
    // Test Some(true)
    let defaults_true = Defaults {
        ignore_comments: Some(true),
        ignore_strings: Some(true),
        ..Defaults::default()
    };
    let encoded = serde_json::to_string(&defaults_true).expect("serialize defaults");
    let decoded: Defaults = serde_json::from_str(&encoded).expect("deserialize defaults");
    assert_eq!(
        decoded.ignore_comments,
        Some(true),
        "ignore_comments should round-trip as Some(true)"
    );
    assert_eq!(
        decoded.ignore_strings,
        Some(true),
        "ignore_strings should round-trip as Some(true)"
    );
}

/// Test that `Defaults` can hold `Some(false)` for ignore fields.
#[test]
fn test_defaults_serialization_json_with_ignore_flags_false() {
    // Test Some(false)
    let defaults_false = Defaults {
        ignore_comments: Some(false),
        ignore_strings: Some(false),
        ..Defaults::default()
    };
    let encoded = serde_json::to_string(&defaults_false).expect("serialize defaults");
    let decoded: Defaults = serde_json::from_str(&encoded).expect("deserialize defaults");
    assert_eq!(
        decoded.ignore_comments,
        Some(false),
        "ignore_comments should round-trip as Some(false)"
    );
    assert_eq!(
        decoded.ignore_strings,
        Some(false),
        "ignore_strings should round-trip as Some(false)"
    );
}

/// Test that `Defaults` with `None` for ignore fields serializes without including them.
/// This verifies `#[serde(skip_serializing_if = "Option::is_none")]` is applied.
#[test]
fn test_defaults_none_ignore_flags_omitted_from_json() {
    let defaults = Defaults::default();
    let json = serde_json::to_value(&defaults).expect("serialize defaults");

    // When ignore_comments/ignore_strings are None, they should NOT appear in JSON
    assert!(
        !json
            .as_object()
            .expect("json should be object")
            .contains_key("ignore_comments"),
        "ignore_comments should be omitted from JSON when None"
    );
    assert!(
        !json
            .as_object()
            .expect("json should be object")
            .contains_key("ignore_strings"),
        "ignore_strings should be omitted from JSON when None"
    );
}

/// Test that `Defaults` can be constructed with explicit `None` for ignore fields.
#[test]
fn test_defaults_explicit_none_for_ignore_flags() {
    let defaults = Defaults {
        ignore_comments: None,
        ignore_strings: None,
        base: Some("origin/main".to_string()),
        head: Some("HEAD".to_string()),
        scope: Some(Scope::Added),
        fail_on: Some(FailOn::Error),
        max_findings: Some(200),
        diff_context: Some(0),
    };

    assert_eq!(defaults.ignore_comments, None);
    assert_eq!(defaults.ignore_strings, None);
}

/// Test TOML serialization round-trip for Defaults with ignore flags.
#[test]
fn test_defaults_toml_roundtrip_with_ignore_flags() {
    // Test Some(true)
    let defaults = Defaults {
        ignore_comments: Some(true),
        ignore_strings: Some(true),
        ..Defaults::default()
    };

    let toml_str = toml::to_string(&defaults).expect("serialize defaults to TOML");
    let decoded: Defaults = toml::from_str(&toml_str).expect("deserialize defaults from TOML");

    assert_eq!(decoded.ignore_comments, Some(true));
    assert_eq!(decoded.ignore_strings, Some(true));
}
