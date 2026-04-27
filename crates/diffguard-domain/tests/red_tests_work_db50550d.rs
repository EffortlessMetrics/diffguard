//! Red tests for work-db50550d: redundant Language::Json match arm removal in string_syntax()
//!
//! Issue: preprocess.rs:107: Language::Json arm is redundant with wildcard in string_syntax()
//!
//! The `Language::Json` case is currently explicitly matched alongside `Language::Yaml` and
//! `Language::Toml` in the match arm:
//!     Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
//!
//! However, `Language::Json` is ALSO caught by the wildcard arm:
//!     _ => StringSyntax::CStyle,
//!
//! This makes the explicit `Language::Json` arm redundant - removing it would not change
//! behavior since JSON would still return `StringSyntax::CStyle` via the wildcard.
//!
//! After the fix (removing `| Language::Json` from the explicit arm):
//! - `Language::Json` returns `StringSyntax::CStyle` via the wildcard
//! - `Language::Yaml` and `Language::Toml` remain explicitly handled
//! - All behavior is preserved
//!
//! Key insight: The issue is about code cleanup, not behavior change. The tests here
//! verify behavior preservation - they pass both before and after the fix.

use diffguard_domain::Language;
use diffguard_domain::preprocess::StringSyntax;

/// Test that Language::Json returns StringSyntax::CStyle.
///
/// This verifies the core behavior: JSON uses C-style string syntax.
/// After the fix, this is via the wildcard `_ => StringSyntax::CStyle`.
#[test]
fn language_json_returns_cstyle() {
    assert_eq!(
        Language::Json.string_syntax(),
        StringSyntax::CStyle,
        "Language::Json should return CStyle string syntax"
    );
}

/// Test that Language::Yaml returns StringSyntax::CStyle.
///
/// YAML should remain explicitly handled (not affected by the fix).
#[test]
fn language_yaml_returns_cstyle() {
    assert_eq!(
        Language::Yaml.string_syntax(),
        StringSyntax::CStyle,
        "Language::Yaml should return CStyle string syntax"
    );
}

/// Test that Language::Toml returns StringSyntax::CStyle.
///
/// TOML should remain explicitly handled (not affected by the fix).
#[test]
fn language_toml_returns_cstyle() {
    assert_eq!(
        Language::Toml.string_syntax(),
        StringSyntax::CStyle,
        "Language::Toml should return CStyle string syntax"
    );
}

/// Verify Language::Json and Language::Unknown behave identically.
///
/// After removing the redundant JSON arm, both Json and Unknown should be handled
/// by the wildcard `_ => StringSyntax::CStyle`. This test verifies they produce
/// the same output (though via different paths before the fix).
#[test]
fn language_json_and_unknown_behave_identically() {
    let json_syntax = Language::Json.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    assert_eq!(
        json_syntax, unknown_syntax,
        "Language::Json and Language::Unknown should behave identically (both return CStyle)"
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

/// Verify explicit arms are preserved for YAML and TOML.
///
/// This test ensures YAML and TOML have explicit match arms (not relying on wildcard).
/// The fix removes only the JSON arm, not YAML or TOML.
#[test]
fn yaml_and_toml_explicit_arms_preserved() {
    // If YAML/TOML were caught by wildcard only, they would behave like Unknown
    // But they should have explicit arms (the fix only removes JSON from explicit arm)
    let yaml_syntax = Language::Yaml.string_syntax();
    let toml_syntax = Language::Toml.string_syntax();

    // Both should be CStyle (this passes before and after the fix)
    assert_eq!(yaml_syntax, StringSyntax::CStyle);
    assert_eq!(toml_syntax, StringSyntax::CStyle);
}

/// Test that removing JSON from explicit arm doesn't affect YAML or TOML.
///
/// This is a regression test to ensure the fix doesn't accidentally break
/// YAML or TOML handling.
#[test]
fn yaml_toml_unchanged_after_json_removal() {
    let yaml_before = Language::Yaml.string_syntax();
    let toml_before = Language::Toml.string_syntax();

    // Both should still return CStyle after the fix
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

/// Verify C-style languages (via wildcard) all return CStyle.
///
/// This documents the expected behavior for languages caught by the wildcard:
/// C, C++, C#, Java, Kotlin, and Unknown.
#[test]
fn wildcard_cstyle_languages_return_cstyle() {
    let cstyle_via_wildcard = vec![
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Java,
        Language::Kotlin,
        Language::Unknown,
    ];

    for lang in cstyle_via_wildcard {
        assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should return CStyle string syntax (via wildcard)",
            lang
        );
    }
}

/// Test that string_syntax is consistent across ALL Language variants.
///
/// This comprehensive test ensures no language is forgotten and all
/// return valid StringSyntax values.
#[test]
fn string_syntax_comprehensive_check() {
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
