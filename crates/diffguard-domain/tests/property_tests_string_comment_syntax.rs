//! Property-based tests for string_syntax() and comment_syntax() invariants
//!
//! These tests verify invariants for the Language enum's string_syntax() and
//! comment_syntax() methods, particularly around the YAML/TOML/JSON grouping.

use diffguard_domain::Language;
use diffguard_domain::preprocess::{CommentSyntax, StringSyntax};

/// All Language variants for exhaustive testing
const ALL_LANGUAGES: &[Language] = &[
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

// ==================== Property 1: string_syntax() Determinism ====================

#[test]
fn property_string_syntax_deterministic() {
    for lang in ALL_LANGUAGES {
        let result1 = lang.string_syntax();
        let result2 = lang.string_syntax();
        let result3 = lang.string_syntax();
        assert_eq!(result1, result2, "string_syntax() should be deterministic for {:?}", lang);
        assert_eq!(result2, result3, "string_syntax() should be deterministic for {:?}", lang);
    }
}

// ==================== Property 2: comment_syntax() Determinism ====================

#[test]
fn property_comment_syntax_deterministic() {
    for lang in ALL_LANGUAGES {
        let result1 = lang.comment_syntax();
        let result2 = lang.comment_syntax();
        let result3 = lang.comment_syntax();
        assert_eq!(result1, result2, "comment_syntax() should be deterministic for {:?}", lang);
        assert_eq!(result2, result3, "comment_syntax() should be deterministic for {:?}", lang);
    }
}

// ==================== Property 3: string_syntax() returns valid variant ====================

#[test]
fn property_string_syntax_returns_valid_variant() {
    for lang in ALL_LANGUAGES {
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
            "string_syntax() returned invalid variant {:?} for {:?}",
            syntax,
            lang
        );
    }
}

// ==================== Property 4: comment_syntax() returns valid variant ====================

#[test]
fn property_comment_syntax_returns_valid_variant() {
    for lang in ALL_LANGUAGES {
        let syntax = lang.comment_syntax();
        assert!(
            matches!(
                syntax,
                CommentSyntax::CStyle
                    | CommentSyntax::CStyleNested
                    | CommentSyntax::Hash
                    | CommentSyntax::Sql
                    | CommentSyntax::Xml
                    | CommentSyntax::Php
            ),
            "comment_syntax() returned invalid variant {:?} for {:?}",
            syntax,
            lang
        );
    }
}

// ==================== Property 5: YAML/TOML/JSON all return CStyle for string_syntax ====================

#[test]
fn property_yaml_toml_json_all_return_cstyle() {
    assert_eq!(
        Language::Yaml.string_syntax(),
        StringSyntax::CStyle,
        "YAML should return CStyle string syntax"
    );
    assert_eq!(
        Language::Toml.string_syntax(),
        StringSyntax::CStyle,
        "TOML should return CStyle string syntax"
    );
    assert_eq!(
        Language::Json.string_syntax(),
        StringSyntax::CStyle,
        "JSON should return CStyle string syntax"
    );
}

// ==================== Property 6: YAML and TOML behave identically for string_syntax ====================

#[test]
fn property_yaml_toml_identical_string_syntax() {
    assert_eq!(
        Language::Yaml.string_syntax(),
        Language::Toml.string_syntax(),
        "YAML and TOML should have identical string_syntax behavior"
    );
}

// ==================== Property 7: JSON behaves same as Unknown for string_syntax ====================

#[test]
fn property_json_behaves_like_unknown_when_via_wildcard() {
    // This property holds AFTER the fix: JSON should behave like Unknown if handled by wildcard
    // Currently JSON HAS an explicit arm, so this test documents the desired state
    assert_eq!(
        Language::Json.string_syntax(),
        Language::Unknown.string_syntax(),
        "JSON should behave like Unknown if handled by wildcard arm"
    );
}

// ==================== Property 8: Unknown falls through to wildcard ====================

#[test]
fn property_unknown_uses_wildcard_string_syntax() {
    assert_eq!(
        Language::Unknown.string_syntax(),
        StringSyntax::CStyle,
        "Unknown language should return CStyle (via wildcard)"
    );
}

// ==================== Property 9: YAML/TOML return Hash for comment_syntax ====================

#[test]
fn property_yaml_toml_comment_syntax_hash() {
    assert_eq!(
        Language::Yaml.comment_syntax(),
        CommentSyntax::Hash,
        "YAML should use Hash comment syntax"
    );
    assert_eq!(
        Language::Toml.comment_syntax(),
        CommentSyntax::Hash,
        "TOML should use Hash comment syntax"
    );
}

// ==================== Property 10: JSON comment syntax ====================

#[test]
fn property_json_comment_syntax() {
    // JSON via wildcard gets CStyle comment syntax
    assert_eq!(
        Language::Json.comment_syntax(),
        CommentSyntax::CStyle,
        "JSON should return CStyle comment syntax (via wildcard)"
    );
}

// ==================== Additional exhaustive tests ====================

/// Test all languages return valid syntaxes
#[test]
fn exhaustive_all_languages_return_valid_syntaxes() {
    for lang in ALL_LANGUAGES {
        let string_syntax = lang.string_syntax();
        let comment_syntax = lang.comment_syntax();

        assert!(
            matches!(
                string_syntax,
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
            "string_syntax() returned invalid variant {:?} for {:?}",
            string_syntax,
            lang
        );

        assert!(
            matches!(
                comment_syntax,
                CommentSyntax::CStyle
                    | CommentSyntax::CStyleNested
                    | CommentSyntax::Hash
                    | CommentSyntax::Sql
                    | CommentSyntax::Xml
                    | CommentSyntax::Php
            ),
            "comment_syntax() returned invalid variant {:?} for {:?}",
            comment_syntax,
            lang
        );
    }
}

/// Test that CStyle languages all return CStyle
#[test]
fn exhaustive_cstyle_languages_all_return_cstyle() {
    let cstyle_langs = vec![
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Java,
        Language::Kotlin,
        Language::Yaml,
        Language::Toml,
        Language::Json,
        Language::Unknown,
    ];

    for lang in cstyle_langs {
        assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should return CStyle string syntax",
            lang
        );
    }
}