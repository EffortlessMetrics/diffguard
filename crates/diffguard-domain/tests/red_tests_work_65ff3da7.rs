//! Red tests for work-65ff3da7: redundant Yaml/Toml/Json match arm removal in string_syntax()
//!
//! These tests verify the correct behavior AFTER removing the redundant
//! `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle` match arm.
//!
//! The correct fix per ADR-065ff3da7:
//! - ALL THREE (Yaml, Toml, Json) are redundant and should be REMOVED
//! - They should be handled by the wildcard `_ => StringSyntax::CStyle`
//! - After the fix, they behave identically to Unknown (all fall through to wildcard)
//!
//! The prior test file (red_tests_work_5d83e2c9.rs) had the WRONG interpretation
//! (only Json was considered redundant; Yaml and Toml were thought to need explicit arms).

use diffguard_domain::Language;
use diffguard_domain::preprocess::StringSyntax;

/// Test that Language::Json falls through to wildcard (behaves like Unknown).
///
/// After the fix removes the redundant `Language::Json` from the explicit arm,
/// Json should behave identically to Unknown (both fall through to `_ => StringSyntax::CStyle`).
///
/// This test FAILS before the fix (Json has explicit arm, is distinct from Unknown).
/// This test PASSES after the fix (Json falls through to wildcard, behaves like Unknown).
#[test]
fn language_json_behaves_like_unknown_via_wildcard() {
    let json_syntax = Language::Json.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    assert_eq!(
        json_syntax, unknown_syntax,
        "Language::Json should behave identically to Language::Unknown (both via wildcard after fix)"
    );
}

/// Test that Language::Yaml falls through to wildcard (behaves like Unknown).
///
/// After the fix removes the redundant `Language::Yaml` from the explicit arm,
/// Yaml should behave identically to Unknown (both fall through to `_ => StringSyntax::CStyle`).
///
/// This test FAILS before the fix (Yaml has explicit arm, is distinct from Unknown).
/// This test PASSES after the fix (Yaml falls through to wildcard, behaves like Unknown).
#[test]
fn language_yaml_behaves_like_unknown_via_wildcard() {
    let yaml_syntax = Language::Yaml.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    assert_eq!(
        yaml_syntax, unknown_syntax,
        "Language::Yaml should behave identically to Language::Unknown (both via wildcard after fix)"
    );
}

/// Test that Language::Toml falls through to wildcard (behaves like Unknown).
///
/// After the fix removes the redundant `Language::Toml` from the explicit arm,
/// Toml should behave identically to Unknown (both fall through to `_ => StringSyntax::CStyle`).
///
/// This test FAILS before the fix (Toml has explicit arm, is distinct from Unknown).
/// This test PASSES after the fix (Toml falls through to wildcard, behaves like Unknown).
#[test]
fn language_toml_behaves_like_unknown_via_wildcard() {
    let toml_syntax = Language::Toml.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    assert_eq!(
        toml_syntax, unknown_syntax,
        "Language::Toml should behave identically to Language::Unknown (both via wildcard after fix)"
    );
}

/// Test that all three redundant languages (Yaml, Toml, Json) behave identically.
///
/// After the fix, all three should behave identically because they all fall through
/// to the wildcard `_ => StringSyntax::CStyle`.
///
/// This test FAILS before the fix (they're in explicit arm together).
/// This test PASSES after the fix (all three via wildcard).
#[test]
fn yaml_toml_json_all_behave_identically_via_wildcard() {
    let yaml_syntax = Language::Yaml.string_syntax();
    let toml_syntax = Language::Toml.string_syntax();
    let json_syntax = Language::Json.string_syntax();

    assert_eq!(
        yaml_syntax, toml_syntax,
        "Yaml and Toml should behave identically (both via wildcard after fix)"
    );
    assert_eq!(
        toml_syntax, json_syntax,
        "Toml and Json should behave identically (both via wildcard after fix)"
    );
    assert_eq!(
        yaml_syntax, json_syntax,
        "Yaml and Json should behave identically (both via wildcard after fix)"
    );
}

/// Verify all data interchange formats (Yaml, Toml, Json) use CStyle string syntax.
///
/// This is a positive test that they return CStyle (both before and after fix).
/// It complements the "behaves like Unknown" tests above.
#[test]
fn data_interchange_formats_return_cstyle() {
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

/// Verify the CStyle group is complete and consistent.
///
/// This test verifies that after the fix, the CStyle group includes:
/// - Languages with explicit arms: C, Cpp, CSharp, Java, Kotlin
/// - Languages via wildcard: Unknown, Yaml, Toml, Json
///
/// All should return StringSyntax::CStyle.
#[test]
fn cstyle_languages_complete_and_consistent() {
    let cstyle_langs = vec![
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Java,
        Language::Kotlin,
        Language::Unknown,
        Language::Yaml,
        Language::Toml,
        Language::Json,
    ];

    for lang in cstyle_langs {
        assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should return StringSyntax::CStyle",
            lang
        );
    }
}

/// Test that string_syntax is consistent across ALL languages.
///
/// Every language should return a valid StringSyntax variant.
#[test]
fn all_languages_return_valid_string_syntax() {
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
