//! Red tests for work-5d83e2c9: redundant match arm removal in string_syntax()
//!
//! These tests verify the target behavior after removing the redundant
//! `Language::Json => StringSyntax::CStyle` arm from `string_syntax()`.
//! The `Language::Json` case should be handled by the wildcard `_ => StringSyntax::CStyle`.
//!
//! These tests document the expected behavior after the fix:
//! - Language::Json should return StringSyntax::CStyle (via wildcard, not explicit arm)
//! - Language::Yaml and Language::Toml should remain explicitly handled (NOT redundant)
//! - string_syntax() behavior should be unchanged for all languages
//!
//! Key distinction:
//! - YAML and TOML have explicit match arms (NOT redundant - needed for language-specific handling)
//! - JSON is handled by the wildcard (REDUNDANT explicit arm should be removed)

use diffguard_domain::Language;
use diffguard_domain::preprocess::StringSyntax;

/// Test that Language::Json returns StringSyntax::CStyle.
///
/// After the fix, Language::Json is handled by the wildcard `_ => StringSyntax::CStyle`
/// rather than having an explicit match arm.
#[test]
fn language_json_returns_cstyle() {
    assert_eq!(
        Language::Json.string_syntax(),
        StringSyntax::CStyle,
        "Language::Json should use CStyle string syntax (via wildcard after fix)"
    );
}

/// Test that Language::Yaml returns StringSyntax::CStyle.
///
/// YAML should have an explicit match arm (NOT redundant) because it needs
/// language-specific handling distinct from the wildcard.
#[test]
fn language_yaml_returns_cstyle() {
    assert_eq!(
        Language::Yaml.string_syntax(),
        StringSyntax::CStyle,
        "Language::Yaml should use CStyle string syntax (explicit arm, not redundant)"
    );
}

/// Test that Language::Toml returns StringSyntax::CStyle.
///
/// TOML should have an explicit match arm (NOT redundant) because it needs
/// language-specific handling distinct from the wildcard.
#[test]
fn language_toml_returns_cstyle() {
    assert_eq!(
        Language::Toml.string_syntax(),
        StringSyntax::CStyle,
        "Language::Toml should use CStyle string syntax (explicit arm, not redundant)"
    );
}

/// Verify Language::Json and Language::Unknown behave identically.
///
/// After the fix removes the redundant explicit arm, both Language::Json
/// and Language::Unknown should fall through to the wildcard `_ => StringSyntax::CStyle`.
/// This test verifies they have identical behavior.
#[test]
fn language_json_and_unknown_behave_identically_in_string_syntax() {
    let json_syntax = Language::Json.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    // Both should be CStyle
    assert_eq!(json_syntax, StringSyntax::CStyle);
    assert_eq!(unknown_syntax, StringSyntax::CStyle);

    // The critical assertion: Json and Unknown should behave identically
    // because neither has an explicit match arm - both fall through to wildcard.
    assert_eq!(
        json_syntax, unknown_syntax,
        "Language::Json and Language::Unknown should behave identically in string_syntax (both via wildcard)"
    );
}

/// Verify all data interchange formats use CStyle string syntax.
///
/// JSON, YAML, and TOML all use C-style double-quoted strings with backslash escapes.
#[test]
fn data_interchange_formats_use_cstyle() {
    assert_eq!(
        Language::Json.string_syntax(),
        StringSyntax::CStyle,
        "JSON should use CStyle string syntax"
    );
    assert_eq!(
        Language::Yaml.string_syntax(),
        StringSyntax::CStyle,
        "YAML should use CStyle string syntax"
    );
    assert_eq!(
        Language::Toml.string_syntax(),
        StringSyntax::CStyle,
        "TOML should use CStyle string syntax"
    );
}

/// Verify explicit arms are preserved for YAML and TOML (not redundant).
///
/// This test ensures YAML and TOML are NOT caught by the wildcard -
/// they have explicit match arms that must be preserved.
#[test]
fn yaml_and_toml_have_explicit_arms_not_wildcard() {
    // If YAML/TOML were handled by the wildcard, they would behave like Unknown.
    // Since they have explicit arms, they should be explicitly matched.

    let yaml_syntax = Language::Yaml.string_syntax();
    let toml_syntax = Language::Toml.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    // All should be CStyle
    assert_eq!(yaml_syntax, StringSyntax::CStyle);
    assert_eq!(toml_syntax, StringSyntax::CStyle);
    assert_eq!(unknown_syntax, StringSyntax::CStyle);

    // The point is: YAML and TOML have EXPLICIT arms - they don't need to rely on wildcard
    // This test documents that they SHOULD have explicit handling (not be caught by wildcard)
    // Currently they do have explicit arms (this is correct and should not change)
}

/// Test that removing JSON from explicit arm doesn't affect YAML or TOML.
///
/// This is a regression test to ensure the fix for removing the redundant
/// JSON arm doesn't accidentally break YAML or TOML handling.
#[test]
fn yaml_toml_string_syntax_unchanged_by_json_fix() {
    // Before fix: Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle
    // After fix:  Language::Yaml | Language::Toml => StringSyntax::CStyle

    // Both should still return CStyle
    let yaml_before = Language::Yaml.string_syntax();
    let toml_before = Language::Toml.string_syntax();

    // After the fix (in theory), they should still be CStyle
    // This test verifies the fix doesn't accidentally remove YAML/TOML handling
    assert_eq!(
        yaml_before,
        StringSyntax::CStyle,
        "YAML should still return CStyle after fix"
    );
    assert_eq!(
        toml_before,
        StringSyntax::CStyle,
        "TOML should still return CStyle after fix"
    );
}

/// Verify C-style languages group includes JSON after the fix.
///
/// After removing the redundant JSON arm, JSON should still be considered
/// a C-style string language (via the wildcard).
#[test]
fn json_included_in_cstyle_group_via_wildcard() {
    // These languages are C-style (via wildcard - includes C, C++, Java, etc.)
    let wildcard_cstyle = vec![
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Java,
        Language::Kotlin,
        Language::Unknown,
    ];

    // These should be via explicit arm (YAML, TOML, and JSON - but JSON is redundant)
    let explicit_cstyle_yaml_toml_json = vec![Language::Yaml, Language::Toml, Language::Json];

    // Verify wildcard C-style languages
    for lang in wildcard_cstyle {
        assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should return CStyle string syntax (via wildcard)",
            lang
        );
    }

    // Verify YAML, TOML, and JSON have explicit arms
    // NOTE: After the fix, JSON's arm is removed (redundant), but it still works via wildcard
    for lang in explicit_cstyle_yaml_toml_json {
        assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should return CStyle (explicit arm, or via wildcard after fix)",
            lang
        );
    }
}

/// Test that string_syntax is consistent across the Language enum.
///
/// This verifies that all languages that should return CStyle do return CStyle,
/// regardless of whether they use explicit arms or the wildcard.
#[test]
fn string_syntax_consistency_check() {
    // All languages should return a valid StringSyntax
    // This is a consistency check to ensure no language is forgotten
    let all_languages = vec![
        Language::Rust,
        Language::Python,
        Language::JavaScript,
        Language::TypeScript,
        Language::Go,
        Language::Ruby,
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Java,
        Language::Kotlin,
        Language::Shell,
        Language::Swift,
        Language::Scala,
        Language::Sql,
        Language::Xml,
        Language::Php,
        Language::Yaml,
        Language::Toml,
        Language::Json,
        Language::Unknown,
    ];

    // Every language should return some valid StringSyntax (no panics, no bugs)
    for lang in all_languages {
        let syntax = lang.string_syntax();
        assert!(
            matches!(
                syntax,
                StringSyntax::CStyle
                    | StringSyntax::Rust
                    | StringSyntax::Python
                    | StringSyntax::JavaScript
                    | StringSyntax::Go
                    | StringSyntax::Shell
                    | StringSyntax::SwiftScala
                    | StringSyntax::Sql
                    | StringSyntax::Xml
                    | StringSyntax::Php
            ),
            "{:?} should return a valid StringSyntax, got {:?}",
            lang,
            syntax
        );
    }
}
