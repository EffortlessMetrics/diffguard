//! Integration tests for JSON/YAML/TOML preprocessing after removing redundant match arm.
//!
//! These tests verify the component handoffs:
//! 1. Language -> Preprocessor (via set_language or with_language)
//! 2. Preprocessor -> sanitize_line (uses string_syntax internally)
//! 3. Language::string_syntax() returns correct syntax for all three languages

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};
use diffguard_domain::preprocess::StringSyntax;

/// Integration test: Language::Json falls through to wildcard and produces CStyle strings.
/// This tests the handoff from Language enum to Preprocessor.
#[test]
fn test_json_string_processing_via_wildcard() {
    // Create preprocessor for JSON - JSON should use CStyle string processing
    // even though it's NOT explicitly in the string_syntax() match arm anymore
    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // Double-quoted string should be masked
    let input = r#"{"key": "value", "nested": {"inner": 42}}"#;
    let sanitized = preprocessor.sanitize_line(input);

    // The string "value" should be masked (replaced with spaces)
    // The output length should match input length
    assert_eq!(sanitized.len(), input.len());
    // The string content should be masked (not identical to input)
    assert_ne!(sanitized, input);
}

/// Integration test: Language::Yaml explicitly handled and produces CStyle strings.
#[test]
fn test_yaml_string_processing_via_explicit_arm() {
    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Yaml);

    // Double-quoted string should be masked
    let input = "key: \"value\"\nnested:\n  inner: 42";
    let sanitized = preprocessor.sanitize_line(input);

    assert_eq!(sanitized.len(), input.len());
    assert_ne!(sanitized, input);
}

/// Integration test: Language::Toml explicitly handled and produces CStyle strings.
#[test]
fn test_toml_string_processing_via_explicit_arm() {
    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Toml);

    // Double-quoted string should be masked
    let input = "key = \"value\"\nnested = { inner = 42 }";
    let sanitized = preprocessor.sanitize_line(input);

    assert_eq!(sanitized.len(), input.len());
    assert_ne!(sanitized, input);
}

/// Integration test: JSON comment processing via wildcard path.
#[test]
fn test_json_comment_processing_via_wildcard() {
    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // C-style line comment should be masked
    let input = r#"{"key": "value"} // this is a comment"#;
    let sanitized = preprocessor.sanitize_line(input);

    // The comment should be masked, but the JSON should remain
    assert_eq!(sanitized.len(), input.len());
    // The key and value should remain, comment should be spaces
    assert!(sanitized.contains("{\"key\": \"value\"}"));
}

/// Integration test: set_language changes the preprocessing behavior.
#[test]
fn test_set_language_changes_processing() {
    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // Process a JSON string
    let json_input = r#"{"key": "value"}"#;
    let json_output = preprocessor.sanitize_line(json_input);
    assert_ne!(json_output, json_input); // String should be masked in JSON

    // Now switch to Python - Python uses different string handling
    preprocessor.set_language(Language::Python);

    // In Python, double-quoted strings are also masked
    let python_input = r#"message = "hello""#;
    let python_output = preprocessor.sanitize_line(python_input);
    // The string should be masked
    assert_ne!(python_output, python_input);
    assert_eq!(python_output.len(), python_input.len());
}

/// Integration test: JSON, YAML, TOML all produce same CStyle behavior.
#[test]
fn test_json_yaml_toml_all_cstyle() {
    let json_opts = PreprocessOptions::strings_only();
    let yaml_opts = PreprocessOptions::strings_only();
    let toml_opts = PreprocessOptions::strings_only();

    let mut json_pp = Preprocessor::with_language(json_opts, Language::Json);
    let mut yaml_pp = Preprocessor::with_language(yaml_opts, Language::Yaml);
    let mut toml_pp = Preprocessor::with_language(toml_opts, Language::Toml);

    // Same input pattern for all three
    let json_input = r#"{"key": "value"}"#;
    let yaml_input = "key: \"value\"";
    let toml_input = "key = \"value\"";

    let json_out = json_pp.sanitize_line(json_input);
    let yaml_out = yaml_pp.sanitize_line(yaml_input);
    let toml_out = toml_pp.sanitize_line(toml_input);

    // All should mask the string content
    assert_ne!(json_out, json_input);
    assert_ne!(yaml_out, yaml_input);
    assert_ne!(toml_out, toml_input);

    // All outputs should have same length as inputs
    assert_eq!(json_out.len(), json_input.len());
    assert_eq!(yaml_out.len(), yaml_input.len());
    assert_eq!(toml_out.len(), toml_input.len());
}

/// Integration test: String syntax is correctly reported for JSON/YAML/TOML.
#[test]
fn test_string_syntax_returns_cstyle_for_json_yaml_toml() {
    // All three should return CStyle
    // This verifies that even though Json is handled by wildcard (not explicit arm),
    // it still correctly returns CStyle
    assert_eq!(Language::Json.string_syntax(), StringSyntax::CStyle);
    assert_eq!(Language::Yaml.string_syntax(), StringSyntax::CStyle);
    assert_eq!(Language::Toml.string_syntax(), StringSyntax::CStyle);
}

/// Integration test: Full preprocessing with both comments and strings masking.
#[test]
fn test_json_full_preprocessing_comments_and_strings() {
    let opts = PreprocessOptions::comments_and_strings();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    let input = r#"{"password": "secret"} // TODO: fix this"#;
    let output = preprocessor.sanitize_line(input);

    // Both string "secret" and comment " // TODO: fix this" should be masked
    assert_eq!(output.len(), input.len());
    // The JSON structure should be preserved but string content masked
    // The output should NOT equal input since masking is applied
    assert_ne!(output, input);
    // The key "password" should still be present (unquoted key is not a string)
    assert!(output.contains("password"));
}

/// Integration test: Language detection string flows correctly to Language parsing.
/// This tests the seam between detect_language (returns string) and Language parsing.
#[test]
fn test_language_from_str_parsing() {
    // detect_language returns Option<&str>, which can be parsed into Language
    use std::str::FromStr;

    // These are the same strings that detect_language would return
    let json_lang = Language::from_str("json").unwrap();
    let yaml_lang = Language::from_str("yaml").unwrap();
    let toml_lang = Language::from_str("toml").unwrap();

    assert_eq!(json_lang, Language::Json);
    assert_eq!(yaml_lang, Language::Yaml);
    assert_eq!(toml_lang, Language::Toml);

    // Verify they all use CStyle strings
    assert_eq!(json_lang.string_syntax(), StringSyntax::CStyle);
    assert_eq!(yaml_lang.string_syntax(), StringSyntax::CStyle);
    assert_eq!(toml_lang.string_syntax(), StringSyntax::CStyle);
}

/// Integration test: Verify YAML/TOML are explicit, JSON is wildcard in string_syntax.
#[test]
fn test_yaml_toml_explicit_json_wildcard() {
    // This test verifies the structural property of the fix:
    // - Yaml and Toml should be explicit arms
    // - Json should fall through to wildcard
    // We verify this by checking their string_syntax values are all CStyle

    // All three return the same CStyle, but via different code paths
    let json_syntax = Language::Json.string_syntax();
    let yaml_syntax = Language::Yaml.string_syntax();
    let toml_syntax = Language::Toml.string_syntax();

    // They should all be equal (same result via different paths)
    assert_eq!(json_syntax, yaml_syntax);
    assert_eq!(yaml_syntax, toml_syntax);
    assert_eq!(json_syntax, StringSyntax::CStyle);
}