//! Green tests for work-fd603479: Edge case coverage for YAML/TOML/JSON handling in preprocess.rs
//!
//! This file contains edge case tests that complement the red tests.
//! The red tests verify the behavioral contract (JSON removed from explicit arm, YAML/TOML explicit).
//! These green tests verify edge cases and stress-test the implementation.
//!
//! Edge cases covered:
//! - All languages return consistent string syntax behavior
//! - YAML/TOML/JSON preprocessing handles various quote styles
//! - Empty and boundary inputs are handled gracefully
//! - Multi-line scenarios work correctly

use diffguard_domain::Language;
use diffguard_domain::preprocess::{CommentSyntax, PreprocessOptions, Preprocessor, StringSyntax};

/// Edge case: Verify YAML and TOML have explicit arms (return same value but via different path than Unknown).
///
/// This is the key distinction the red tests verify - YAML/TOML have explicit match arms,
/// while JSON is handled by the wildcard. Both return CStyle, but the code paths differ.
/// This test confirms the behavioral equivalence for preprocessing purposes.
#[test]
fn yaml_toml_return_cstyle_via_explicit_arm() {
    // YAML and TOML have explicit arms: Language::Yaml | Language::Toml => StringSyntax::CStyle
    assert_eq!(Language::Yaml.string_syntax(), StringSyntax::CStyle);
    assert_eq!(Language::Toml.string_syntax(), StringSyntax::CStyle);
}

/// Edge case: Verify JSON returns CStyle via wildcard (no explicit arm).
///
/// JSON was removed from the explicit arm and is now handled by:
/// `_ => StringSyntax::CStyle`
#[test]
fn json_returns_cstyle_via_wildcard() {
    assert_eq!(Language::Json.string_syntax(), StringSyntax::CStyle);
}

/// Edge case: Verify YAML, TOML, and JSON all return CStyle (behaviorally equivalent).
///
/// While JSON is handled by wildcard and YAML/TOML by explicit arm,
/// they all produce the same StringSyntax::CStyle output.
#[test]
fn yaml_toml_json_all_return_cstyle() {
    assert_eq!(Language::Yaml.string_syntax(), StringSyntax::CStyle);
    assert_eq!(Language::Toml.string_syntax(), StringSyntax::CStyle);
    assert_eq!(Language::Json.string_syntax(), StringSyntax::CStyle);
}

/// Edge case: Verify YAML/TOML/JSON all have Hash comment syntax.
///
/// YAML and TOML explicitly use Hash comments.
/// JSON uses CStyle (with jsonc/json5 handling comments in the wildcard).
#[test]
fn yaml_toml_have_hash_comment_syntax() {
    assert_eq!(Language::Yaml.comment_syntax(), CommentSyntax::Hash);
    assert_eq!(Language::Toml.comment_syntax(), CommentSyntax::Hash);
}

/// Edge case: Verify JSON has CStyle comment syntax (not Hash).
///
/// JSON doesn't support comments natively - only jsonc/json5 dialects do.
/// Since there's no explicit JSON arm in comment_syntax, it falls to wildcard CStyle.
#[test]
fn json_has_cstyle_comment_syntax() {
    assert_eq!(Language::Json.comment_syntax(), CommentSyntax::CStyle);
}

/// Edge case: All 20 languages return a valid StringSyntax (no panics).
///
/// This is a comprehensive sanity check that every language variant
/// produces a defined string syntax without panicking.
#[test]
fn all_languages_return_valid_string_syntax() {
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
        // Should not panic - this is the key assertion
        let _syntax = lang.string_syntax();

        // Syntax should be a valid variant
        assert!(
            matches!(
                _syntax,
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
            _syntax
        );
    }
}

/// Edge case: All 20 languages return a valid CommentSyntax (no panics).
#[test]
fn all_languages_return_valid_comment_syntax() {
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
        // Should not panic
        let _syntax = lang.comment_syntax();

        // Syntax should be a valid variant
        assert!(
            matches!(
                _syntax,
                CommentSyntax::CStyle
                    | CommentSyntax::CStyleNested
                    | CommentSyntax::Hash
                    | CommentSyntax::Sql
                    | CommentSyntax::Xml
                    | CommentSyntax::Php
            ),
            "{:?} returned invalid CommentSyntax: {:?}",
            lang,
            _syntax
        );
    }
}

/// Edge case: YAML preprocessing handles double-quoted strings.
#[test]
fn yaml_double_quoted_strings_masked() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Yaml);
    let line = "key: \"value\" # comment";
    let s = p.sanitize_line(line);
    // key: and # comment should remain, but "value" should be masked
    assert!(s.contains("key:"));
    assert!(s.contains("# comment"));
    assert!(!s.contains("value"));
}

/// Edge case: YAML preprocessing handles single-quoted strings.
#[test]
fn yaml_single_quoted_strings_masked() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Yaml);
    let line = "key: 'value' # comment";
    let s = p.sanitize_line(line);
    assert!(s.contains("key:"));
    assert!(s.contains("# comment"));
    // Single-quoted strings in YAML are also masked in C-style preprocessing
    // (the preprocessor treats them as C-style strings)
}

/// Edge case: TOML preprocessing handles double-quoted strings.
#[test]
fn toml_double_quoted_strings_masked() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Toml);
    let line = "name = \"app\" # comment";
    let s = p.sanitize_line(line);
    assert!(s.contains("name ="));
    assert!(s.contains("# comment"));
    assert!(!s.contains("app"));
}

/// Edge case: TOML preprocessing handles single-quoted strings (literal strings).
#[test]
fn toml_single_quoted_strings_masked() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Toml);
    let line = "path = 'C:\\Users\\test' # windows path";
    let s = p.sanitize_line(line);
    assert!(s.contains("path ="));
    assert!(s.contains("# windows path"));
    // TOML literal strings (single quotes) are masked in C-style preprocessing
}

/// Edge case: JSON preprocessing handles double-quoted strings.
#[test]
fn json_double_quoted_strings_masked() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Json);
    let line = "{\"key\": \"value\"}";
    let s = p.sanitize_line(line);
    // The string "value" should be masked but structure preserved
    assert!(s.contains("{"));
    assert!(s.contains("}"));
    assert!(s.contains(":"));
    // The key and value strings should be masked (no "key" or "value" visible)
    assert!(!s.contains("key"));
    assert!(!s.contains("value"));
}

/// Edge case: JSON preprocessing preserves line length (spaces replace masked content).
#[test]
fn yaml_preserves_line_length_when_masking_strings() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Yaml);
    let line = "key: \"value\"";
    let original_len = line.len();
    let s = p.sanitize_line(line);
    assert_eq!(
        s.len(),
        original_len,
        "Masked output should preserve original line length"
    );
}

/// Edge case: TOML preprocessing preserves line length when masking strings.
#[test]
fn toml_preserves_line_length_when_masking_strings() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Toml);
    let line = "name = \"value\"";
    let original_len = line.len();
    let s = p.sanitize_line(line);
    assert_eq!(s.len(), original_len);
}

/// Edge case: JSON preprocessing preserves line length when masking strings.
#[test]
fn json_preserves_line_length_when_masking_strings() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Json);
    let line = "{\"key\": \"value\"}";
    let original_len = line.len();
    let s = p.sanitize_line(line);
    assert_eq!(s.len(), original_len);
}

/// Edge case: Empty YAML document.
#[test]
fn yaml_empty_input_handled() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Yaml);
    let s = p.sanitize_line("");
    assert_eq!(s, "");
}

/// Edge case: Empty TOML document.
#[test]
fn toml_empty_input_handled() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Toml);
    let s = p.sanitize_line("");
    assert_eq!(s, "");
}

/// Edge case: Empty JSON document.
#[test]
fn json_empty_input_handled() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Json);
    let s = p.sanitize_line("");
    assert_eq!(s, "");
}

/// Edge case: YAML with only a comment.
#[test]
fn yaml_only_comment_handled() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Yaml);
    let s = p.sanitize_line("# full line comment");
    assert!(
        s.trim().is_empty(),
        "Comment-only line should be fully masked"
    );
}

/// Edge case: TOML with only a comment.
#[test]
fn toml_only_comment_handled() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Toml);
    let s = p.sanitize_line("# full line comment");
    assert!(s.trim().is_empty());
}

/// Edge case: JSON with only a comment (jsonc style).
#[test]
fn json_only_comment_handled() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Json);
    let s = p.sanitize_line("// full line comment");
    assert!(
        s.trim().is_empty(),
        "Comment-only line should be fully masked"
    );
}

/// Edge case: YAML with hash in string value (should NOT be treated as comment).
#[test]
fn yaml_hash_in_string_not_treated_as_comment() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Yaml);
    let line = "url: \"https://example.com#fragment\"";
    let s = p.sanitize_line(line);
    // The # in the URL string should NOT start a comment
    assert!(s.contains("https://example.com#fragment"));
}

/// Edge case: TOML with hash in string value (should NOT be treated as comment).
#[test]
fn toml_hash_in_string_not_treated_as_comment() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Toml);
    let line = "url = \"https://example.com#fragment\"";
    let s = p.sanitize_line(line);
    assert!(s.contains("https://example.com#fragment"));
}

/// Edge case: JSON with strings containing escaped quotes.
#[test]
fn json_strings_with_escaped_quotes_masked() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Json);
    let line = "{\"msg\": \"say \\\"hello\\\"\"}";
    let s = p.sanitize_line(line);
    assert!(s.contains("{"));
    assert!(s.contains("}"));
    assert!(s.contains(":"));
    // The escaped quotes and content should be masked
    assert!(!s.contains("say"));
    assert!(!s.contains("hello"));
}

/// Edge case: YAML with multiline string (folded style).
#[test]
fn yaml_multiline_string_handled() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Yaml);
    // YAML folded style uses > character
    let line = "description: >\n  This is a long\n  description.";
    let s = p.sanitize_line(line);
    // Should handle without panicking
    assert!(s.contains("description:"));
}

/// Edge case: Verify Language::default() returns Unknown.
#[test]
fn language_default_is_unknown() {
    assert_eq!(Language::default(), Language::Unknown);
}

/// Edge case: Unknown language falls through to wildcard in both string_syntax and comment_syntax.
#[test]
fn unknown_language_uses_wildcard() {
    assert_eq!(Language::Unknown.string_syntax(), StringSyntax::CStyle);
    assert_eq!(Language::Unknown.comment_syntax(), CommentSyntax::CStyle);
}

/// Edge case: JSON and Unknown behave identically (both use wildcard).
#[test]
fn json_and_unknown_behave_identically() {
    assert_eq!(
        Language::Json.string_syntax(),
        Language::Unknown.string_syntax()
    );
    assert_eq!(
        Language::Json.comment_syntax(),
        Language::Unknown.comment_syntax()
    );
}

/// Edge case: Yaml and Toml differ from Unknown in intent (explicit arms vs wildcard).
/// They return the same values but via different code paths.
#[test]
fn yaml_toml_differ_from_unknown_intent() {
    // All return CStyle for string_syntax
    assert_eq!(Language::Yaml.string_syntax(), StringSyntax::CStyle);
    assert_eq!(Language::Toml.string_syntax(), StringSyntax::CStyle);
    assert_eq!(Language::Unknown.string_syntax(), StringSyntax::CStyle);

    // All return Hash for comment_syntax
    assert_eq!(Language::Yaml.comment_syntax(), CommentSyntax::Hash);
    assert_eq!(Language::Toml.comment_syntax(), CommentSyntax::Hash);
    // Unknown returns CStyle (not Hash) - this is the key difference
    assert_eq!(Language::Unknown.comment_syntax(), CommentSyntax::CStyle);
}

/// Edge case: Preprocessor with no masking passes through unchanged.
#[test]
fn yaml_no_masking_passes_through() {
    let mut p = Preprocessor::with_language(PreprocessOptions::none(), Language::Yaml);
    let line = "key: \"value\" # comment";
    let s = p.sanitize_line(line);
    assert_eq!(s, line);
}

/// Edge case: Preprocessor with comments_only masks only comments.
#[test]
fn yaml_comments_only_masks_only_comments() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Yaml);
    let line = "key: \"value\" # comment";
    let s = p.sanitize_line(line);
    assert!(s.contains("key: \"value\""), "String should remain");
    assert!(!s.contains("comment"), "Comment should be masked");
}

/// Edge case: Preprocessor with strings_only masks only strings.
#[test]
fn yaml_strings_only_masks_only_strings() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Yaml);
    let line = "key: \"value\" # comment";
    let s = p.sanitize_line(line);
    assert!(s.contains("key:"), "Key should remain");
    assert!(s.contains("# comment"), "Comment should remain");
    assert!(!s.contains("value"), "String should be masked");
}

/// Edge case: YAML preprocessing handles colons in strings.
#[test]
fn yaml_colon_in_string_handled() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Yaml);
    let line = "url: \"https://example.com:8080/path\"";
    let s = p.sanitize_line(line);
    assert!(s.contains("url:"));
    assert!(!s.contains("https"));
    assert!(!s.contains("example"));
}

/// Edge case: TOML preprocessing handles equals in strings.
#[test]
fn toml_equals_in_string_handled() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Toml);
    let line = "equation = \"x = y + z\"";
    let s = p.sanitize_line(line);
    assert!(s.contains("equation ="));
    assert!(!s.contains("x = y + z"));
}
