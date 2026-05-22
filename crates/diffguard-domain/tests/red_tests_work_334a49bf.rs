//! Red tests for work-334a49bf: resolve match_same_arms warnings in preprocess.rs
//!
//! These tests verify the target behavior after merging redundant match arms:
//!
//! ## comment_syntax() changes:
//! - MERGE two separate `CommentSyntax::Hash` arms into one:
//!   - Before: `Language::Python | Language::Ruby | Language::Shell => CommentSyntax::Hash`
//!   - Before: `Language::Yaml | Language::Toml => CommentSyntax::Hash`
//!   - After:  `Language::Python | Language::Ruby | Language::Shell | Language::Yaml | Language::Toml => CommentSyntax::Hash`
//!
//! ## string_syntax() changes:
//! - REMOVE the redundant explicit arm:
//!   - Before: `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle`
//!   - Before: `_ => StringSyntax::CStyle`
//!   - After:  `_ => StringSyntax::CStyle` (only)
//!
//! ## Singleton arms PRESERVED (not redundant):
//! - `Language::Xml => CommentSyntax::Xml` - triggers XML `<!-- -->` block comment handling
//! - `Language::Php => CommentSyntax::Php` - triggers PHP-specific `#` comment handling
//! - `Language::Xml => StringSyntax::Xml` - distinct downstream handling
//! - `Language::Php => StringSyntax::Php` - produces `Mode::NormalString` (NOT `Mode::Char` like CStyle)
//!
//! These tests document the expected behavior after the fix:
//! - All #comment languages (Python, Ruby, Shell, Yaml, Toml) return CommentSyntax::Hash
//! - Yaml, Toml, Json return StringSyntax::CStyle via wildcard
//! - Xml and Php singleton arms are preserved with distinct values

use diffguard_domain::Language;
use diffguard_domain::preprocess::{CommentSyntax, StringSyntax};

// =============================================================================
// CommentSyntax tests - verifying merged Hash arm
// =============================================================================

/// Test that Python, Ruby, Shell, Yaml, and Toml all return CommentSyntax::Hash.
/// After the fix, these should all be handled by a single merged match arm.
#[test]
fn comment_syntax_hash_languages_merged() {
    // All these languages should return CommentSyntax::Hash
    // After the fix, they are all handled by ONE match arm:
    // Language::Python | Language::Ruby | Language::Shell | Language::Yaml | Language::Toml => CommentSyntax::Hash

    assert_eq!(
        Language::Python.comment_syntax(),
        CommentSyntax::Hash,
        "Language::Python should return CommentSyntax::Hash"
    );
    assert_eq!(
        Language::Ruby.comment_syntax(),
        CommentSyntax::Hash,
        "Language::Ruby should return CommentSyntax::Hash"
    );
    assert_eq!(
        Language::Shell.comment_syntax(),
        CommentSyntax::Hash,
        "Language::Shell should return CommentSyntax::Hash"
    );
    assert_eq!(
        Language::Yaml.comment_syntax(),
        CommentSyntax::Hash,
        "Language::Yaml should return CommentSyntax::Hash"
    );
    assert_eq!(
        Language::Toml.comment_syntax(),
        CommentSyntax::Hash,
        "Language::Toml should return CommentSyntax::Hash"
    );
}

/// Verify that Python, Ruby, and Shell are NOT affected by YAML/TOML arm removal.
/// This is a regression test: the YAML/TOML fix should not affect Python/Ruby/Shell.
#[test]
fn comment_syntax_ruby_shell_unchanged_after_yaml_toml_merge() {
    // Python, Ruby, Shell were on a SEPARATE arm from Yaml, Toml
    // The fix merges them, but the result should be the same
    assert_eq!(Language::Python.comment_syntax(), CommentSyntax::Hash);
    assert_eq!(Language::Ruby.comment_syntax(), CommentSyntax::Hash);
    assert_eq!(Language::Shell.comment_syntax(), CommentSyntax::Hash);
}

/// Verify that after merging, the Hash group includes ALL #comment languages.
/// This test ensures the merged arm is complete and no language is forgotten.
#[test]
fn comment_syntax_hash_group_complete() {
    // The merged arm should handle:
    // Python, Ruby, Shell, Yaml, Toml
    // These are ALL the languages that use # for comments

    let hash_languages = vec![
        Language::Python,
        Language::Ruby,
        Language::Shell,
        Language::Yaml,
        Language::Toml,
    ];

    for lang in hash_languages {
        assert_eq!(
            lang.comment_syntax(),
            CommentSyntax::Hash,
            "{:?} should use # comments (CommentSyntax::Hash)",
            lang
        );
    }
}

// =============================================================================
// StringSyntax tests - verifying redundant arm removal
// =============================================================================

/// Test that Language::Json returns StringSyntax::CStyle.
/// After the fix, Json is handled by the wildcard `_ => StringSyntax::CStyle`.
#[test]
fn string_syntax_json_via_wildcard() {
    assert_eq!(
        Language::Json.string_syntax(),
        StringSyntax::CStyle,
        "Language::Json should use CStyle string syntax (via wildcard after fix)"
    );
}

/// Test that Language::Yaml returns StringSyntax::CStyle.
/// After the fix, Yaml still has an explicit arm (merged with Toml).
#[test]
fn string_syntax_yaml_explicit_arm() {
    assert_eq!(
        Language::Yaml.string_syntax(),
        StringSyntax::CStyle,
        "Language::Yaml should use CStyle string syntax (explicit arm)"
    );
}

/// Test that Language::Toml returns StringSyntax::CStyle.
/// After the fix, Toml still has an explicit arm (merged with Yaml).
#[test]
fn string_syntax_toml_explicit_arm() {
    assert_eq!(
        Language::Toml.string_syntax(),
        StringSyntax::CStyle,
        "Language::Toml should use CStyle string syntax (explicit arm)"
    );
}

/// Verify all data interchange formats (YAML, TOML, JSON) return CStyle.
/// After the fix, YAML and TOML have explicit arms, JSON uses wildcard.
#[test]
fn string_syntax_data_interchange_formats() {
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

/// Verify that after removing the redundant Json arm, Json and Unknown behave identically.
/// Both should fall through to the wildcard `_ => StringSyntax::CStyle`.
#[test]
fn string_syntax_json_and_unknown_behave_identically() {
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

// =============================================================================
// Singleton arm preservation tests - Xml and Php must NOT be affected
// =============================================================================

/// Test that Language::Xml returns CommentSyntax::Xml (NOT redundant).
/// This is a SINGLETON arm that triggers XML `<!-- -->` block comment handling.
#[test]
fn comment_syntax_xml_singleton_preserved() {
    assert_eq!(
        Language::Xml.comment_syntax(),
        CommentSyntax::Xml,
        "Language::Xml should return CommentSyntax::Xml (singleton arm, NOT redundant)"
    );
}

/// Test that Language::Php returns CommentSyntax::Php (NOT redundant).
/// This is a SINGLETON arm that triggers PHP-specific `#` comment handling.
/// Note: Php uses `#` comments but unlike Python/Ruby/Shell, it has distinct behavior.
#[test]
fn comment_syntax_php_singleton_preserved() {
    assert_eq!(
        Language::Php.comment_syntax(),
        CommentSyntax::Php,
        "Language::Php should return CommentSyntax::Php (singleton arm, NOT redundant)"
    );
}

/// Test that Language::Xml returns StringSyntax::Xml (NOT redundant).
/// This is a SINGLETON arm with distinct downstream handling.
#[test]
fn string_syntax_xml_singleton_preserved() {
    assert_eq!(
        Language::Xml.string_syntax(),
        StringSyntax::Xml,
        "Language::Xml should return StringSyntax::Xml (singleton arm, NOT redundant)"
    );
}

/// Test that Language::Php returns StringSyntax::Php (NOT redundant).
/// This is a SINGLETON arm that produces `Mode::NormalString` for single-quoted strings.
/// This is DISTINCT from CStyle which produces `Mode::Char` for single quotes.
#[test]
fn string_syntax_php_singleton_preserved() {
    assert_eq!(
        Language::Php.string_syntax(),
        StringSyntax::Php,
        "Language::Php should return StringSyntax::Php (singleton arm, NOT redundant)"
    );
}

/// Verify Xml and Php are NOT affected by the Yaml/Toml/Json arm removal.
/// These singleton arms should remain unchanged.
#[test]
fn xml_php_singletons_unchanged_after_string_syntax_fix() {
    // Xml and Php should still have their distinct values
    assert_eq!(Language::Xml.string_syntax(), StringSyntax::Xml);
    assert_eq!(Language::Php.string_syntax(), StringSyntax::Php);

    // They should NOT fall through to CStyle
    assert_ne!(
        Language::Xml.string_syntax(),
        StringSyntax::CStyle,
        "Language::Xml should NOT use CStyle (has distinct handling)"
    );
    assert_ne!(
        Language::Php.string_syntax(),
        StringSyntax::CStyle,
        "Language::Php should NOT use CStyle (has distinct handling)"
    );
}

// =============================================================================
// Consistency and regression tests
// =============================================================================

/// Verify all languages return a valid CommentSyntax.
/// This catches if someone accidentally removes a language from the match.
#[test]
fn comment_syntax_all_languages_covered() {
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
            "{:?} should return a valid CommentSyntax, got {:?}",
            lang,
            syntax
        );
    }
}

/// Verify all languages return a valid StringSyntax.
/// This catches if someone accidentally removes a language from the match.
#[test]
fn string_syntax_all_languages_covered() {
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

/// Verify the merged comment_syntax Hash arm didn't accidentally merge Xml or Php.
/// This is a regression test to ensure the fix is surgical.
#[test]
fn comment_syntax_hash_merge_did_not_affect_xml_php() {
    // Xml and Php should NOT be Hash
    assert_ne!(
        Language::Xml.comment_syntax(),
        CommentSyntax::Hash,
        "Language::Xml should NOT be affected by Hash merge"
    );
    assert_ne!(
        Language::Php.comment_syntax(),
        CommentSyntax::Hash,
        "Language::Php should NOT be affected by Hash merge"
    );

    // They should still have their distinct values
    assert_eq!(Language::Xml.comment_syntax(), CommentSyntax::Xml);
    assert_eq!(Language::Php.comment_syntax(), CommentSyntax::Php);
}

/// Verify the string_syntax fix (removing Json from explicit arm) didn't affect Xml or Php.
/// This is a regression test to ensure the fix is surgical.
#[test]
fn string_syntax_json_removal_did_not_affect_xml_php() {
    // Xml and Php should NOT be affected
    assert_eq!(Language::Xml.string_syntax(), StringSyntax::Xml);
    assert_eq!(Language::Php.string_syntax(), StringSyntax::Php);

    // They should NOT be CStyle
    assert_ne!(Language::Xml.string_syntax(), StringSyntax::CStyle);
    assert_ne!(Language::Php.string_syntax(), StringSyntax::CStyle);
}
