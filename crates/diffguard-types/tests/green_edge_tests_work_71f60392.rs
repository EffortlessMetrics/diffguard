//! Green edge tests for work-71f60392: `ConfigFile::built_in()` edge cases
//!
//! These tests verify the runtime behavior of `ConfigFile::built_in()`:
//! - Returns a valid ConfigFile
//! - Has expected defaults
//! - Has rules loaded
//! - Is idempotent (multiple calls return equivalent configs)
//! - Serialization roundtrip works
//!
//! Note: The panic case (malformed JSON) cannot be tested at runtime because
//! the JSON is embedded at compile time via `include_str!()`.

use diffguard_types::{ConfigFile, FailOn, Scope};

/// Test: `built_in()` returns a non-null ConfigFile.
/// This is the happy path - the most basic verification.
#[test]
fn built_in_returns_valid_config_file() {
    let _config = ConfigFile::built_in();
    // The function returns a valid ConfigFile - if it compiled and didn't panic,
    // the test passes. The #[must_use] ensures the return value isn't discarded.
}

/// Test: `built_in()` returns a ConfigFile with expected defaults.
/// Verifies that the embedded `built_in.json` was parsed correctly.
#[test]
fn built_in_has_expected_defaults() {
    let config = ConfigFile::built_in();

    // Verify defaults
    let defaults = &config.defaults;
    assert_eq!(defaults.base.as_deref(), Some("origin/main"));
    assert_eq!(defaults.head.as_deref(), Some("HEAD"));
    assert_eq!(defaults.scope, Some(Scope::Added));
    assert_eq!(defaults.fail_on, Some(FailOn::Error));
    assert_eq!(defaults.max_findings, Some(200));
    assert_eq!(defaults.diff_context, Some(0));
}

/// Test: `built_in()` returns a ConfigFile with rules loaded.
/// Verifies that the `rules/built_in.json` was successfully parsed.
#[test]
fn built_in_has_rules_loaded() {
    let config = ConfigFile::built_in();
    assert!(
        !config.rule.is_empty(),
        "built_in() should have at least one rule"
    );
}

/// Test: `built_in()` rules have valid structure.
/// Each rule should have a non-empty id, valid severity, and at least one pattern.
#[test]
fn built_in_rules_have_valid_structure() {
    let config = ConfigFile::built_in();

    for rule in &config.rule {
        assert!(!rule.id.is_empty(), "Rule ID should not be empty");
        // Severity is an enum, so it's always valid if the JSON parsed
        assert!(
            !rule.patterns.is_empty(),
            "Rule '{}' should have at least one pattern",
            rule.id
        );
    }
}

/// Test: `built_in()` includes at least one rule for Rust files.
/// The `rust.no_unwrap` rule should be present and target `*.rs` files.
#[test]
fn built_in_has_rust_rules() {
    let config = ConfigFile::built_in();

    let rust_rules: Vec<_> = config
        .rule
        .iter()
        .filter(|r| r.languages.contains(&"rust".to_string()))
        .collect();

    assert!(
        !rust_rules.is_empty(),
        "built_in() should have at least one Rust rule"
    );

    // Verify rust.no_unwrap is present
    let has_unwrap_rule = rust_rules.iter().any(|r| r.id == "rust.no_unwrap");
    assert!(
        has_unwrap_rule,
        "built_in() should contain 'rust.no_unwrap' rule"
    );
}

/// Test: `built_in()` is idempotent - multiple calls return equivalent configs.
/// Since the JSON is embedded at compile time, this should always be true.
#[test]
fn built_in_is_idempotent() {
    let config1 = ConfigFile::built_in();
    let config2 = ConfigFile::built_in();

    assert_eq!(config1.includes, config2.includes);
    assert_eq!(config1.defaults, config2.defaults);
    assert_eq!(config1.rule.len(), config2.rule.len());

    // Verify each rule is identical
    for (r1, r2) in config1.rule.iter().zip(config2.rule.iter()) {
        assert_eq!(r1.id, r2.id);
        assert_eq!(r1.severity, r2.severity);
        assert_eq!(r1.patterns, r2.patterns);
    }
}

/// Test: `built_in()` result can be serialized to JSON and back.
/// This verifies the ConfigFile is properly serializable.
#[test]
fn built_in_serialization_roundtrip() {
    let config1 = ConfigFile::built_in();

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&config1)
        .expect("built_in() ConfigFile should serialize to JSON");

    // Deserialize back
    let config2: ConfigFile =
        serde_json::from_str(&json).expect("serialized JSON should deserialize back to ConfigFile");

    // Verify they're equal
    assert_eq!(config1.includes, config2.includes);
    assert_eq!(config1.defaults, config2.defaults);
    assert_eq!(config1.rule.len(), config2.rule.len());
}

/// Test: `built_in()` defaults serialize correctly to JSON.
/// Verifies that the default values are preserved through serialization.
#[test]
fn built_in_defaults_serialize_correctly() {
    let config = ConfigFile::built_in();
    let json = serde_json::to_string(&config.defaults).expect("Defaults should serialize to JSON");

    // Verify key fields are present in JSON
    assert!(
        json.contains("\"base\""),
        "JSON should contain 'base' field"
    );
    assert!(
        json.contains("\"head\""),
        "JSON should contain 'head' field"
    );
    assert!(
        json.contains("\"scope\""),
        "JSON should contain 'scope' field"
    );
    assert!(
        json.contains("\"fail_on\""),
        "JSON should contain 'fail_on' field"
    );
}

/// Test: `built_in()` has no includes by default.
/// The base configuration should have empty includes.
#[test]
fn built_in_has_no_includes() {
    let config = ConfigFile::built_in();
    assert!(
        config.includes.is_empty(),
        "built_in() should have empty includes by default"
    );
}

/// Test: `built_in()` includes secret detection rules.
/// Verifies that the security rules are included in the built-in config.
#[test]
fn built_in_has_secret_rules() {
    let config = ConfigFile::built_in();

    let secret_rules: Vec<_> = config
        .rule
        .iter()
        .filter(|r| r.id.starts_with("secrets."))
        .collect();

    assert!(
        !secret_rules.is_empty(),
        "built_in() should have at least one secrets rule"
    );

    // Verify AWS secret rule is present
    let has_aws_rule = secret_rules
        .iter()
        .any(|r| r.id == "secrets.aws_access_key");
    assert!(
        has_aws_rule,
        "built_in() should contain 'secrets.aws_access_key' rule"
    );
}

/// Test: `built_in()` rules have valid regex patterns (can be parsed).
/// Invalid regex would cause issues at runtime when matching.
#[test]
fn built_in_rules_have_valid_regex_patterns() {
    use regex::Regex;

    let config = ConfigFile::built_in();

    for rule in &config.rule {
        for pattern in &rule.patterns {
            let result = Regex::new(pattern);
            assert!(
                result.is_ok(),
                "Rule '{}' has invalid regex pattern '{}': {:?}",
                rule.id,
                pattern,
                result.err()
            );
        }
    }
}

/// Test: `built_in()` rules with `exclude_paths` have valid patterns.
#[test]
fn built_in_exclude_path_patterns_are_valid() {
    let config = ConfigFile::built_in();

    for rule in &config.rule {
        for path_pattern in &rule.exclude_paths {
            // Exclude paths use glob-style patterns, but we can verify
            // they're non-empty and contain expected wildcards
            assert!(
                !path_pattern.is_empty(),
                "Rule '{}' has empty exclude_path",
                rule.id
            );
        }
    }
}

/// Test: `built_in()` rules specify `help` text for users.
/// Each rule should provide guidance on how to fix the issue.
#[test]
fn built_in_rules_have_help_text() {
    let config = ConfigFile::built_in();

    for rule in &config.rule {
        // help is Option<String> - verify it's Some and non-empty
        assert!(
            rule.help.as_ref().is_some_and(|h| !h.is_empty()),
            "Rule '{}' should have non-empty help text",
            rule.id
        );
    }
}

/// Test: `built_in()` severity levels are correctly parsed.
/// Verifies that severity enum parsing works correctly.
#[test]
fn built_in_severity_levels_are_valid() {
    let config = ConfigFile::built_in();

    for rule in &config.rule {
        match rule.severity {
            diffguard_types::Severity::Info
            | diffguard_types::Severity::Warn
            | diffguard_types::Severity::Error => {
                // All valid severities
            }
        }
    }
}

/// Test: `built_in()` can be cloned (is Clone).
#[test]
fn built_in_is_clone() {
    let config1 = ConfigFile::built_in();
    let config2 = config1.clone();

    assert_eq!(config1.includes, config2.includes);
    assert_eq!(config1.defaults, config2.defaults);
    assert_eq!(config1.rule.len(), config2.rule.len());
}

/// Test: `built_in()` implements Debug (can be formatted for debugging).
#[test]
fn built_in_implements_debug() {
    let config = ConfigFile::built_in();
    let debug_str = format!("{:?}", config);
    assert!(!debug_str.is_empty(), "Debug output should not be empty");
}
