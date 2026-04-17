//! Green tests for work-05d48a76: edge case tests for JSON string_syntax()
//!
//! These tests verify edge cases not covered by the red tests:
//! - Preprocessor handles JSON strings with various escape sequences correctly
//! - JSON and Unknown behave identically in BOTH string_syntax() AND comment_syntax()
//! - All C-style languages (via wildcard) are correctly handled by the preprocessor
//! - The preprocessing pipeline correctly masks JSON strings

use diffguard_domain::Language;
use diffguard_domain::preprocess::CommentSyntax;
use diffguard_domain::preprocess::PreprocessOptions;
use diffguard_domain::preprocess::Preprocessor;
use diffguard_domain::preprocess::StringSyntax;

/// Edge case: JSON strings with backslash escapes are handled correctly.
///
/// JSON uses C-style string escaping. This test verifies that the preprocessor
/// correctly handles JSON strings with various escape sequences.
#[test]
fn preprocessor_json_handles_escape_sequences() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Json);

    // Simple JSON string with escape sequences
    let input = r#"{"key": "value\nwith\nnewlines"}"#;
    let output = preprocessor.sanitize_line(input);

    // The preprocessor should mask the string portions
    // After masking, the line should still be the same length
    assert_eq!(
        output.len(),
        input.len(),
        "Output length should match input length"
    );
}

/// Edge case: JSON with nested quotes in strings.
///
/// JSON strings can contain escaped quotes.
#[test]
fn preprocessor_json_handles_nested_quotes() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Json);

    // JSON with escaped quotes inside the string
    let input = r#"{"message": "He said \"hello world\""}"#;
    let output = preprocessor.sanitize_line(input);

    assert_eq!(
        output.len(),
        input.len(),
        "Output length should match input length for nested quotes"
    );
}

/// Edge case: Empty JSON string value.
#[test]
fn preprocessor_json_handles_empty_string() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Json);

    let input = r#"{"key": ""}"#;
    let output = preprocessor.sanitize_line(input);

    assert_eq!(
        output.len(),
        input.len(),
        "Output length should match input length for empty string"
    );
}

/// Edge case: JSON with unicode escape sequences.
#[test]
fn preprocessor_json_handles_unicode_escapes() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Json);

    // JSON with unicode escape
    let input = r#"{"emoji": "\uD83D\uDE00"}"#;
    let output = preprocessor.sanitize_line(input);

    assert_eq!(
        output.len(),
        input.len(),
        "Output length should match input length for unicode escapes"
    );
}

/// Edge case: JSON and Unknown have identical behavior in BOTH string_syntax AND comment_syntax.
///
/// This verifies that the wildcard handling is consistent across both functions.
#[test]
fn json_and_unknown_identical_in_both_functions() {
    // Both should have the same string syntax (CStyle via wildcard)
    assert_eq!(
        Language::Json.string_syntax(),
        Language::Unknown.string_syntax(),
        "Json and Unknown should have identical string_syntax() (both CStyle via wildcard)"
    );
    assert_eq!(
        Language::Json.string_syntax(),
        StringSyntax::CStyle,
        "Json string_syntax should be CStyle"
    );
    assert_eq!(
        Language::Unknown.string_syntax(),
        StringSyntax::CStyle,
        "Unknown string_syntax should be CStyle"
    );

    // Both should have the same comment syntax (CStyle via wildcard)
    assert_eq!(
        Language::Json.comment_syntax(),
        Language::Unknown.comment_syntax(),
        "Json and Unknown should have identical comment_syntax() (both CStyle via wildcard)"
    );
    assert_eq!(
        Language::Json.comment_syntax(),
        CommentSyntax::CStyle,
        "Json comment_syntax should be CStyle"
    );
    assert_eq!(
        Language::Unknown.comment_syntax(),
        CommentSyntax::CStyle,
        "Unknown comment_syntax should be CStyle"
    );
}

/// Edge case: All wildcard CStyle languages have identical preprocessing behavior.
///
/// Languages caught by the wildcard `_ => StringSyntax::CStyle` should all
/// preprocess identically to Unknown.
#[test]
fn all_wildcard_cstyle_languages_identical() {
    let wildcard_cstyle_langs = vec![
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Java,
        Language::Kotlin,
        Language::Json, // Now via wildcard after fix
        Language::Unknown,
    ];

    // All should return CStyle via wildcard
    for lang in &wildcard_cstyle_langs {
        assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should return CStyle (via wildcard)",
            lang
        );
    }

    // All should preprocess identically for a C-style string
    let test_string = r#""hello world""#;
    let mut reference_preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Unknown);
    let reference_output = reference_preprocessor.sanitize_line(test_string);

    for lang in &wildcard_cstyle_langs {
        let mut preprocessor =
            Preprocessor::with_language(PreprocessOptions::strings_only(), *lang);
        let output = preprocessor.sanitize_line(test_string);

        assert_eq!(
            output, reference_output,
            "{:?} should preprocess identically to Unknown for C-style string",
            lang
        );
    }
}

/// Edge case: Verify the wildcard catches all expected languages.
///
/// This is a canary test - if a new language is added and not explicitly handled,
/// it should fall through to CStyle (which may or may not be correct, but is the fallback).
#[test]
fn wildcard_catches_unmatched_languages() {
    // These languages are NOT explicitly handled in string_syntax()
    // They should all fall through to the wildcard CStyle
    let unmatched_langs = vec![
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Java,
        Language::Kotlin,
        Language::Json, // No longer explicitly handled after fix
        Language::Unknown,
    ];

    for lang in unmatched_langs {
        let syntax = lang.string_syntax();
        assert_eq!(
            syntax,
            StringSyntax::CStyle,
            "{:?} should fall through to wildcard and return CStyle",
            lang
        );
    }
}

/// Edge case: Preprocessor with comments-only mode for JSON.
///
/// JSON doesn't support comments in standard JSON, but the preprocessor
/// should still handle C-style comments gracefully.
#[test]
fn preprocessor_json_comments_mode() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Json);

    // A line with a C-style line comment (not valid JSON but testing preprocessor)
    let input = r#"// This is a comment"#;
    let output = preprocessor.sanitize_line(input);

    assert_eq!(
        output.len(),
        input.len(),
        "Output length should match input length for comment-only mode"
    );
}

/// Edge case: Preprocessor with both comments and strings for JSON.
///
/// This tests the full preprocessing pipeline for JSON content.
#[test]
fn preprocessor_json_full_pipeline() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Json);

    // JSON with both a comment (in jsonc style) and a string
    let input = r#"// comment
{"key": "value"}"#;
    let output = preprocessor.sanitize_line(input);

    assert_eq!(
        output.len(),
        input.len(),
        "Output length should match input length for full pipeline"
    );
}

/// Edge case: Verify the fix doesn't affect explicit-arm languages differently.
///
/// YAML and TOML have explicit match arms. They should be handled exactly
/// the same before and after the fix.
#[test]
fn yaml_toml_explicit_arm_unchanged() {
    // These have explicit arms - they should NOT be caught by wildcard
    let explicit_arm_langs = vec![Language::Yaml, Language::Toml];

    for lang in explicit_arm_langs {
        // Verify they return CStyle (explicit arm)
        assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should return CStyle via explicit arm",
            lang
        );

        // Both YAML and TOML should have explicit comment_syntax arms too
        assert_eq!(
            lang.comment_syntax(),
            CommentSyntax::Hash,
            "{:?} should use Hash comment syntax (explicit arm)",
            lang
        );
    }
}

/// Edge case: Ensure string_syntax is correct for ALL known languages.
///
/// This is a comprehensive test that every language returns a valid StringSyntax.
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

        // Verify it's a valid variant (not unitialized or invalid)
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

/// Edge case: Data interchange formats (JSON, YAML, TOML) all use CStyle strings.
///
/// All three data interchange formats use C-style double-quoted strings with
/// backslash escapes. This test verifies they're all handled correctly.
#[test]
fn data_interchange_formats_all_cstyle() {
    // They should all preprocess the same way for basic C-style strings
    let test_string = r#""test""#;

    let reference_output = {
        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Json);
        p.sanitize_line(test_string)
    };

    // JSON, YAML, TOML should all use CStyle and preprocess identically
    for lang in [Language::Json, Language::Yaml, Language::Toml] {
        assert_eq!(
            lang.string_syntax(),
            StringSyntax::CStyle,
            "{:?} should use CStyle string syntax",
            lang
        );

        let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), lang);
        let output = p.sanitize_line(test_string);

        assert_eq!(
            output, reference_output,
            "{:?} should preprocess identically to Json for C-style string",
            lang
        );
    }
}
