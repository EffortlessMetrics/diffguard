//! Edge case tests for work-334a49bf: merged match arms in comment_syntax() and string_syntax()
//!
//! These tests verify that the refactoring to merge duplicate match arms did not introduce
//! behavioral changes. The refactoring merged:
//! - comment_syntax(): Python | Ruby | Shell | Yaml | Toml => CommentSyntax::Hash
//! - string_syntax(): Removed redundant Yaml | Toml | Json arm (now handled by wildcard)
//!
//! Edge cases covered:
//! - Hash comment masking for YAML and TOML (merged Hash arm)
//! - YAML/TOML preprocessor correctly handles # comments
//! - JSON falls through to CStyle for string_syntax (wildcard arm)
//! - PHP and XML singleton arms still produce distinct syntaxes

use diffguard_domain::preprocess::{
    CommentSyntax, Language, PreprocessOptions, Preprocessor, StringSyntax,
};

// ==================== comment_syntax edge cases ====================

/// Verify that Shell is included in the merged Hash arm (regression test)
#[test]
fn edge_shell_comment_syntax_is_hash() {
    assert_eq!(
        Language::Shell.comment_syntax(),
        CommentSyntax::Hash,
        "Shell should return CommentSyntax::Hash after merging with Python/Ruby/Yaml/Toml"
    );
}

/// Verify all hash-comment languages return Hash after merge
#[test]
fn edge_all_hash_comment_languages() {
    let hash_langs = [
        Language::Python,
        Language::Ruby,
        Language::Shell,
        Language::Yaml,
        Language::Toml,
    ];
    for lang in hash_langs {
        assert_eq!(
            lang.comment_syntax(),
            CommentSyntax::Hash,
            "{:?} should return CommentSyntax::Hash",
            lang
        );
    }
}

/// Verify PHP singleton arm is preserved (distinct from Hash)
#[test]
fn edge_php_comment_syntax_is_php() {
    assert_eq!(
        Language::Php.comment_syntax(),
        CommentSyntax::Php,
        "PHP should return CommentSyntax::Php (singleton arm, distinct from wildcard)"
    );
}

/// Verify XML singleton arm is preserved (distinct from CStyle wildcard)
#[test]
fn edge_xml_comment_syntax_is_xml() {
    assert_eq!(
        Language::Xml.comment_syntax(),
        CommentSyntax::Xml,
        "XML should return CommentSyntax::Xml (singleton arm, distinct from wildcard)"
    );
}

/// Verify YAML preprocessor correctly masks # comments (merged Hash arm)
#[test]
fn edge_yaml_masks_hash_comments() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Yaml);
    // YAML uses # for comments
    let s = p.sanitize_line("key: value  # this is a comment");
    assert!(s.contains("key: value"), "key:value should remain");
    assert!(
        !s.contains("this is a comment"),
        "comment after # should be masked"
    );
}

/// Verify TOML preprocessor correctly masks # comments (merged Hash arm)
#[test]
fn edge_toml_masks_hash_comments() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Toml);
    // TOML uses # for comments
    let s = p.sanitize_line("name = \"test\"  # this is a comment");
    assert!(s.contains("name = \"test\""), "key should remain");
    assert!(
        !s.contains("this is a comment"),
        "comment after # should be masked"
    );
}

// ==================== string_syntax edge cases ====================

/// Verify YAML falls through to CStyle (wildcard arm)
#[test]
fn edge_yaml_string_syntax_is_cstyle() {
    assert_eq!(
        Language::Yaml.string_syntax(),
        StringSyntax::CStyle,
        "YAML should return StringSyntax::CStyle via wildcard"
    );
}

/// Verify TOML falls through to CStyle (wildcard arm)
#[test]
fn edge_toml_string_syntax_is_cstyle() {
    assert_eq!(
        Language::Toml.string_syntax(),
        StringSyntax::CStyle,
        "TOML should return StringSyntax::CStyle via wildcard"
    );
}

/// Verify JSON falls through to CStyle (wildcard arm)
#[test]
fn edge_json_string_syntax_is_cstyle() {
    assert_eq!(
        Language::Json.string_syntax(),
        StringSyntax::CStyle,
        "JSON should return StringSyntax::CStyle via wildcard"
    );
}

/// Verify PHP singleton arm is preserved (distinct from CStyle)
#[test]
fn edge_php_string_syntax_is_php() {
    assert_eq!(
        Language::Php.string_syntax(),
        StringSyntax::Php,
        "PHP should return StringSyntax::Php (singleton arm, distinct from wildcard CStyle)"
    );
}

/// Verify XML singleton arm is preserved (distinct from CStyle)
#[test]
fn edge_xml_string_syntax_is_xml() {
    assert_eq!(
        Language::Xml.string_syntax(),
        StringSyntax::Xml,
        "XML should return StringSyntax::Xml (singleton arm, distinct from wildcard CStyle)"
    );
}

/// Verify JSON and Unknown behave identically (both via wildcard)
#[test]
fn edge_json_and_unknown_string_syntax_identical() {
    assert_eq!(
        Language::Json.string_syntax(),
        Language::Unknown.string_syntax(),
        "JSON and Unknown should behave identically in string_syntax (both via wildcard)"
    );
}

/// Verify YAML and TOML string behavior matches pre-fix baseline
#[test]
fn edge_yaml_toml_string_syntax_matches_unknown() {
    // After removing the redundant arm, Yaml/Toml should match Unknown (wildcard) behavior
    assert_eq!(
        Language::Yaml.string_syntax(),
        Language::Unknown.string_syntax(),
        "YAML string_syntax should match Unknown (both via wildcard)"
    );
    assert_eq!(
        Language::Toml.string_syntax(),
        Language::Unknown.string_syntax(),
        "TOML string_syntax should match Unknown (both via wildcard)"
    );
}

// ==================== Preprocessing edge cases ====================

/// Verify YAML preprocessor masks double-quoted strings (CStyle via wildcard)
#[test]
fn edge_yaml_masks_double_quoted_strings() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Yaml);
    let s = p.sanitize_line("message: \"hello, world\"");
    assert!(s.contains("message:"), "key should remain");
    assert!(!s.contains("hello, world"), "string value should be masked");
}

/// Verify TOML preprocessor masks double-quoted strings (CStyle via wildcard)
#[test]
fn edge_toml_masks_double_quoted_strings() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Toml);
    let s = p.sanitize_line(r#"name = "diffguard""#);
    assert!(s.contains("name ="), "key should remain");
    assert!(!s.contains("diffguard"), "string value should be masked");
}

/// Verify JSON preprocessor masks double-quoted strings (CStyle via wildcard)
#[test]
fn edge_json_masks_double_quoted_strings() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Json);
    // JSON uses double quotes for string values
    // The double quotes themselves get masked to spaces
    let s = p.sanitize_line(r#"{"key": "value"}"#);
    // After masking, we expect:
    // {"key": "value"} -> {      : "value"} (quotes masked to spaces, key and : remain visible in object syntax)
    // Actually, let's verify the string "value" is masked
    assert!(!s.contains("value"), "JSON string value should be masked");
}

/// Verify PHP string syntax is distinct from CStyle (PHP uses NormalString mode)
#[test]
fn edge_php_single_quoted_strings_are_normal_strings() {
    // PHP '...' is Mode::NormalString, not Mode::Char like CStyle
    // This is a behavioral distinction that the singleton arm preserves
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Php);
    let s = p.sanitize_line("echo 'hello';");
    assert!(s.contains("echo"), "keyword should remain");
    // The single-quoted string should be masked (not treated as char literal)
    assert!(
        !s.contains("hello"),
        "PHP single-quoted string should be masked"
    );
}

/// Verify all Language variants return a valid CommentSyntax
#[test]
fn edge_all_languages_return_valid_comment_syntax() {
    let languages = [
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
    for lang in languages {
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
            "{:?} returned invalid CommentSyntax: {:?}",
            lang,
            syntax
        );
    }
}

/// Verify all Language variants return a valid StringSyntax
#[test]
fn edge_all_languages_return_valid_string_syntax() {
    let languages = [
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
    for lang in languages {
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
            "{:?} returned invalid StringSyntax: {:?}",
            lang,
            syntax
        );
    }
}
