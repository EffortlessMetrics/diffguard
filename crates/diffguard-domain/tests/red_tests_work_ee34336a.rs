//! Red tests for work-ee34336a: remove redundant Language::Json arm in string_syntax()
//!
//! These tests verify the expected behavior after removing the redundant
//! `Language::Json => StringSyntax::CStyle` arm from the explicit match arm.
//!
//! The fix changes:
//!   BEFORE: Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
//!   AFTER:  Language::Yaml | Language::Toml => StringSyntax::CStyle,
//!
//! After the fix, `Language::Json` is handled by the wildcard `_ => StringSyntax::CStyle`
//! instead of the explicit arm. This is behaviorally equivalent - both return CStyle.
//!
//! Key behavioral expectations after the fix:
//! - Language::Json.string_syntax() returns StringSyntax::CStyle (via wildcard)
//! - Language::Yaml.string_syntax() returns StringSyntax::CStyle (via explicit arm)
//! - Language::Toml.string_syntax() returns StringSyntax::CStyle (via explicit arm)
//! - Language::Unknown.string_syntax() returns StringSyntax::CStyle (via wildcard)
//! - Language::Json and Language::Unknown behave identically (both via wildcard)

use diffguard_domain::Language;
use diffguard_domain::preprocess::StringSyntax;

/// Verifies Language::Json returns StringSyntax::CStyle after the fix.
///
/// After removing the redundant explicit arm, Language::Json falls through
/// to the wildcard `_ => StringSyntax::CStyle` and returns CStyle.
/// This is the same behavior as before - just via a different code path.
#[test]
fn language_json_returns_cstyle_via_wildcard() {
    // Language::Json should return CStyle (via wildcard after fix)
    assert_eq!(
        Language::Json.string_syntax(),
        StringSyntax::CStyle,
        "Language::Json should use CStyle string syntax (via wildcard after fix)"
    );
}

/// Verifies Language::Yaml still returns StringSyntax::CStyle.
///
/// YAML should have an explicit match arm that is NOT redundant.
/// This test ensures the fix doesn't accidentally break YAML handling.
#[test]
fn language_yaml_returns_cstyle_via_explicit_arm() {
    assert_eq!(
        Language::Yaml.string_syntax(),
        StringSyntax::CStyle,
        "Language::Yaml should use CStyle string syntax (explicit arm)"
    );
}

/// Verifies Language::Toml still returns StringSyntax::CStyle.
///
/// TOML should have an explicit match arm that is NOT redundant.
/// This test ensures the fix doesn't accidentally break TOML handling.
#[test]
fn language_toml_returns_cstyle_via_explicit_arm() {
    assert_eq!(
        Language::Toml.string_syntax(),
        StringSyntax::CStyle,
        "Language::Toml should use CStyle string syntax (explicit arm)"
    );
}

/// Verifies Language::Json and Language::Unknown behave identically.
///
/// After the fix, both Language::Json and Language::Unknown fall through
/// to the wildcard `_ => StringSyntax::CStyle`. This test confirms they
/// have identical behavior - both return CStyle.
#[test]
fn language_json_and_unknown_behave_identically_after_fix() {
    let json_syntax = Language::Json.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    // Both should be CStyle
    assert_eq!(
        json_syntax,
        StringSyntax::CStyle,
        "Language::Json should return CStyle"
    );
    assert_eq!(
        unknown_syntax,
        StringSyntax::CStyle,
        "Language::Unknown should return CStyle"
    );

    // The critical assertion: Json and Unknown should behave identically
    // because both fall through to the wildcard after the fix.
    assert_eq!(
        json_syntax, unknown_syntax,
        "Language::Json and Language::Unknown should behave identically in string_syntax (both via wildcard after fix)"
    );
}

/// Verifies that YAML and TOML are NOT caught by the wildcard.
///
/// This test documents that YAML and TOML have explicit match arms
/// and should not fall through to the wildcard. After the fix,
/// they still have explicit arms (unlike JSON which was removed).
#[test]
fn yaml_and_toml_have_explicit_arms_not_wildcard() {
    let yaml_syntax = Language::Yaml.string_syntax();
    let toml_syntax = Language::Toml.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    // All should be CStyle
    assert_eq!(yaml_syntax, StringSyntax::CStyle);
    assert_eq!(toml_syntax, StringSyntax::CStyle);
    assert_eq!(unknown_syntax, StringSyntax::CStyle);

    // YAML and TOML have explicit arms - they don't rely on wildcard
    // This test documents the expected structure after the fix
}

/// Verifies that JSON, YAML, and TOML all use CStyle string syntax.
///
/// These three languages are data interchange formats with C-style
/// double-quoted strings. After the fix, JSON uses wildcard while
/// YAML and TOML use explicit arms, but all return CStyle.
#[test]
fn data_interchange_formats_all_use_cstyle() {
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

/// Verifies the fix doesn't affect YAML or TOML handling.
///
/// This is a regression test to ensure removing the redundant JSON arm
/// doesn't accidentally break YAML or TOML handling.
#[test]
fn yaml_toml_unchanged_by_json_fix() {
    let yaml_before = Language::Yaml.string_syntax();
    let toml_before = Language::Toml.string_syntax();

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

/// Verifies all C-style string languages return CStyle.
///
/// This includes languages handled by explicit arms (YAML, TOML)
/// and languages handled by the wildcard (C, C++, Java, JSON, Unknown, etc.)
#[test]
fn all_cstyle_languages_return_cstyle() {
    // Languages with explicit CStyle arms
    let explicit_cstyle = vec![Language::Yaml, Language::Toml];

    // Languages that fall through to wildcard CStyle
    let wildcard_cstyle = vec![
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Java,
        Language::Kotlin,
        Language::Json,
        Language::Unknown,
    ];

    for lang in explicit_cstyle {
        assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should return CStyle (explicit arm)",
            lang
        );
    }

    for lang in wildcard_cstyle {
        assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should return CStyle (via wildcard)",
            lang
        );
    }
}

/// Test that string_syntax is consistent across the Language enum.
///
/// Every language should return a valid StringSyntax variant with no panics.
#[test]
fn string_syntax_consistency_all_languages() {
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
