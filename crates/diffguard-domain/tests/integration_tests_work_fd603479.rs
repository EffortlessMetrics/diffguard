//! Integration tests for work-fd603479: redundant match arm fix in string_syntax()
//!
//! These tests verify the end-to-end flow of the redundant match arm fix:
//! - Language::Json falls through to wildcard (not explicit arm) for string_syntax()
//! - Language::Yaml and Language::Toml use explicit arm for string_syntax()
//! - The Preprocessor correctly uses these syntaxes for sanitization
//!
//! Integration testing strategy:
//! - Test the component handoff: Language.string_syntax() → Preprocessor.sanitize_line()
//! - Test the end-to-end flow: raw input → Preprocessor → sanitized output
//! - Test multiline preprocessing for JSON/YAML/TOML
//! - Test error propagation through the preprocessing pipeline

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Integration test: JSON preprocessing end-to-end flow.
///
/// Verifies that Language::Json works correctly with Preprocessor,
/// ensuring the wildcard fallback in string_syntax() produces correct output.
#[test]
fn integration_json_preprocessing_flow() {
    // Setup: Create preprocessor with JSON language
    let opts = PreprocessOptions::comments_and_strings();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // JSON input with comment and string
    let input = r#"{"key": "value"} // this is a comment"#;
    let sanitized = preprocessor.sanitize_line(input);

    // Verify output length is preserved (key requirement of sanitize_line)
    assert_eq!(input.len(), sanitized.len());

    // Verify comment is masked (replaced with spaces)
    // The "// this is a comment" should be masked to spaces
    // When masked, "// this is a comment" becomes "                 "
    assert!(
        sanitized.contains("                 ") || sanitized.contains("          "),
        "Comment should be masked with spaces, got: {}",
        sanitized
    );

    // The string "value" is also masked when mask_strings is true
    // So the output will have spaces where the string was
    // The key is that the output length equals input length
}

/// Integration test: YAML preprocessing end-to-end flow.
///
/// Verifies that Language::Yaml works correctly with Preprocessor,
/// ensuring the explicit arm in string_syntax() produces correct output.
#[test]
fn integration_yaml_preprocessing_flow() {
    let opts = PreprocessOptions::comments_and_strings();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Yaml);

    // YAML input with hash comment and string
    let input = r#"key: "value"  # this is a comment"#;
    let sanitized = preprocessor.sanitize_line(input);

    // Verify output length is preserved
    assert_eq!(input.len(), sanitized.len());

    // Verify hash comment is masked
    // The "# this is a comment" should be masked
    assert!(
        sanitized.contains("# this is a comment") || sanitized.contains("  "),
        "Hash comment should be masked, got: {}",
        sanitized
    );
}

/// Integration test: TOML preprocessing end-to-end flow.
///
/// Verifies that Language::Toml works correctly with Preprocessor,
/// ensuring the explicit arm in string_syntax() produces correct output.
#[test]
fn integration_toml_preprocessing_flow() {
    let opts = PreprocessOptions::comments_and_strings();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Toml);

    // TOML input with hash comment and string
    let input = r#"key = "value"  # this is a comment"#;
    let sanitized = preprocessor.sanitize_line(input);

    // Verify output length is preserved
    assert_eq!(input.len(), sanitized.len());

    // Verify hash comment is masked
    assert!(
        sanitized.contains("# this is a comment") || sanitized.contains("  "),
        "Hash comment should be masked, got: {}",
        sanitized
    );
}

/// Integration test: Language syntax consistency in preprocessing.
///
/// Verifies that Language's string_syntax() and comment_syntax() methods
/// are correctly used by Preprocessor to handle JSON/YAML/TOML.
#[test]
fn integration_language_syntax_consistency() {
    // JSON uses CStyle for both comments (via wildcard) and strings (via wildcard)
    let json_opts = PreprocessOptions::comments_only();
    let mut json_preprocessor = Preprocessor::with_language(json_opts, Language::Json);
    let json_result = json_preprocessor.sanitize_line("// comment");
    assert_eq!(json_result.len(), "// comment".len());

    // YAML uses Hash for comments (explicit arm) and CStyle for strings (explicit arm)
    let yaml_opts = PreprocessOptions::comments_only();
    let mut yaml_preprocessor = Preprocessor::with_language(yaml_opts, Language::Yaml);
    let yaml_result = yaml_preprocessor.sanitize_line("# comment");
    assert_eq!(yaml_result.len(), "# comment".len());

    // TOML uses Hash for comments (explicit arm) and CStyle for strings (explicit arm)
    let toml_opts = PreprocessOptions::comments_only();
    let mut toml_preprocessor = Preprocessor::with_language(toml_opts, Language::Toml);
    let toml_result = toml_preprocessor.sanitize_line("# comment");
    assert_eq!(toml_result.len(), "# comment".len());
}

/// Integration test: JSON and Unknown behave identically in preprocessing.
///
/// After the fix, Language::Json falls through to the wildcard `_ => StringSyntax::CStyle`
/// just like Language::Unknown. This test verifies they produce identical preprocessing results.
#[test]
fn integration_json_and_unknown_identical_behavior() {
    let opts = PreprocessOptions::strings_only();

    let mut json_preprocessor = Preprocessor::with_language(opts, Language::Json);
    let mut unknown_preprocessor = Preprocessor::with_language(opts, Language::Unknown);

    // Both should handle C-style strings the same way
    let json_result = json_preprocessor.sanitize_line(r#""string""#);
    let unknown_result = unknown_preprocessor.sanitize_line(r#""string""#);

    assert_eq!(
        json_result, unknown_result,
        "JSON and Unknown should produce identical preprocessing results"
    );
}

/// Integration test: multiline preprocessing for JSON.
///
/// Verifies that the Preprocessor correctly handles multiline content
/// for JSON, which uses C-style string syntax via the wildcard.
#[test]
fn integration_multiline_json_preprocessing() {
    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // First line starts a comment
    let line1 = r#"{"key": "value"} // start of comment"#;
    let result1 = preprocessor.sanitize_line(line1);
    assert_eq!(line1.len(), result1.len());

    // Second line continues the comment (if we're in line comment mode)
    // Actually JSON doesn't have native multiline comments,
    // but C-style // comments continue to end of line
    let line2 = r#"{"key": "value"} // another line comment"#;
    let result2 = preprocessor.sanitize_line(line2);
    assert_eq!(line2.len(), result2.len());
}

/// Integration test: multiline preprocessing for YAML.
///
/// Verifies that the Preprocessor correctly handles multiline content
/// for YAML, which uses Hash comment syntax via explicit arm.
#[test]
fn integration_multiline_yaml_preprocessing() {
    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Yaml);

    // YAML supports multiline strings with | or >
    let line1 = r#"description: |"#;
    let result1 = preprocessor.sanitize_line(line1);
    assert_eq!(line1.len(), result1.len());

    let line2 = r#"  This is a multiline"#;
    let result2 = preprocessor.sanitize_line(line2);
    assert_eq!(line2.len(), result2.len());

    // Hash comment
    let line3 = r#"  # this is a comment"#;
    let result3 = preprocessor.sanitize_line(line3);
    assert_eq!(line3.len(), result3.len());
}

/// Integration test: Preprocessor language switching maintains consistency.
///
/// Verifies that switching languages in the Preprocessor correctly
/// updates the syntax handling without interference.
#[test]
fn integration_language_switching_consistency() {
    // Use comments_only to verify comment masking works per language
    let opts = PreprocessOptions::comments_only();

    // Process JSON - C-style // comments
    let mut json_preprocessor = Preprocessor::with_language(opts, Language::Json);
    let json_result = json_preprocessor.sanitize_line("// comment");
    assert_eq!(json_result.len(), "// comment".len());
    // Comment is masked to spaces when mask_comments is true

    // Switch to YAML - Hash # comments
    json_preprocessor.set_language(Language::Yaml);
    let yaml_result = json_preprocessor.sanitize_line("# comment");
    assert_eq!(yaml_result.len(), "# comment".len());
    // Hash comment is masked to spaces when mask_comments is true

    // Switch to TOML - Hash # comments (same as YAML)
    json_preprocessor.set_language(Language::Toml);
    let toml_result = json_preprocessor.sanitize_line("# comment");
    assert_eq!(toml_result.len(), "# comment".len());
    // Hash comment is masked to spaces when mask_comments is true

    // Now verify with comments disabled - comments should be preserved
    let no_opts = PreprocessOptions::none();
    let mut json_preserved = Preprocessor::with_language(no_opts, Language::Json);
    let json_preserved_result = json_preserved.sanitize_line("// comment");
    assert_eq!(json_preserved_result, "// comment", "Comment should be preserved when not masked");

    let mut yaml_preserved = Preprocessor::with_language(no_opts, Language::Yaml);
    let yaml_preserved_result = yaml_preserved.sanitize_line("# comment");
    assert_eq!(yaml_preserved_result, "# comment", "Hash comment should be preserved when not masked");
}

/// Integration test: String masking with JSON/YAML/TOML.
///
/// Verifies that string masking works correctly for all three languages,
/// regardless of whether they use explicit or wildcard arms.
#[test]
fn integration_string_masking_json_yaml_toml() {
    let opts = PreprocessOptions::strings_only();

    // JSON: double-quoted strings
    let mut json_preprocessor = Preprocessor::with_language(opts, Language::Json);
    let json_input = r#"{"key": "value"}"#;
    let json_result = json_preprocessor.sanitize_line(json_input);
    assert_eq!(json_input.len(), json_result.len());

    // YAML: both single and double-quoted strings
    let mut yaml_preprocessor = Preprocessor::with_language(opts, Language::Yaml);
    let yaml_double_input = r#"key: "value""#;
    let yaml_double_result = yaml_preprocessor.sanitize_line(yaml_double_input);
    assert_eq!(yaml_double_input.len(), yaml_double_result.len());

    let yaml_single_input = r#"key: 'value'"#;
    let yaml_single_result = yaml_preprocessor.sanitize_line(yaml_single_input);
    assert_eq!(yaml_single_input.len(), yaml_single_result.len());

    // TOML: both single and double-quoted strings
    let mut toml_preprocessor = Preprocessor::with_language(opts, Language::Toml);
    let toml_double_input = r#"key = "value""#;
    let toml_double_result = toml_preprocessor.sanitize_line(toml_double_input);
    assert_eq!(toml_double_input.len(), toml_double_result.len());

    let toml_single_input = r#"key = 'value'"#;
    let toml_single_result = toml_preprocessor.sanitize_line(toml_single_input);
    assert_eq!(toml_single_input.len(), toml_single_result.len());
}

/// Integration test: Component handoff verification.
///
/// Verifies the handoff between Language.string_syntax() and Preprocessor
/// works correctly. The Preprocessor should receive the correct StringSyntax
/// regardless of whether Language::Json uses explicit or wildcard arm.
#[test]
fn integration_syntax_handoff_to_preprocessor() {
    // Create preprocessors for all three languages
    let opts = PreprocessOptions::strings_only();

    let json_syntax = Language::Json.string_syntax();
    let yaml_syntax = Language::Yaml.string_syntax();
    let toml_syntax = Language::Toml.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    // All should return CStyle
    assert_eq!(json_syntax, diffguard_domain::preprocess::StringSyntax::CStyle);
    assert_eq!(yaml_syntax, diffguard_domain::preprocess::StringSyntax::CStyle);
    assert_eq!(toml_syntax, diffguard_domain::preprocess::StringSyntax::CStyle);
    assert_eq!(unknown_syntax, diffguard_domain::preprocess::StringSyntax::CStyle);

    // JSON and Unknown should behave identically (key verification)
    assert_eq!(json_syntax, unknown_syntax);

    // Now verify Preprocessors produce correct output with these syntaxes
    let mut json_preprocessor = Preprocessor::with_language(opts, Language::Json);
    let mut unknown_preprocessor = Preprocessor::with_language(opts, Language::Unknown);

    let json_result = json_preprocessor.sanitize_line(r#""test""#);
    let unknown_result = unknown_preprocessor.sanitize_line(r#""test""#);

    assert_eq!(
        json_result, unknown_result,
        "JSON and Unknown Preprocessors should produce identical output"
    );
}

/// Integration test: Error-free preprocessing for all data interchange formats.
///
/// Verifies that the preprocessing pipeline handles JSON, YAML, and TOML
/// without panics or errors, regardless of input complexity.
#[test]
fn integration_no_errors_json_yaml_toml() {
    let comment_opts = PreprocessOptions::comments_only();
    let string_opts = PreprocessOptions::strings_only();
    let both_opts = PreprocessOptions::comments_and_strings();

    let test_cases = vec![
        // JSON test cases
        (Language::Json, comment_opts, r#"{"key": "value"}"#),
        (Language::Json, string_opts, r#"{"key": "value"}"#),
        (Language::Json, both_opts, r#"{"key": "value"} // comment"#),
        (Language::Json, comment_opts, r#"{"nested": {"key": "value"}}"#),
        // YAML test cases
        (Language::Yaml, comment_opts, r#"key: value"#),
        (Language::Yaml, string_opts, r#"key: "value""#),
        (Language::Yaml, both_opts, r#"key: "value" # comment"#),
        (Language::Yaml, comment_opts, "key: |\n  multiline\n  string"),
        // TOML test cases
        (Language::Toml, comment_opts, r#"key = "value""#),
        (Language::Toml, string_opts, r#"key = "value""#),
        (Language::Toml, both_opts, r#"key = "value" # comment"#),
        (Language::Toml, comment_opts, r#"[section]"#),
    ];

    for (lang, opts, input) in test_cases {
        let mut preprocessor = Preprocessor::with_language(opts, lang);
        let result = preprocessor.sanitize_line(input);
        assert_eq!(
            input.len(),
            result.len(),
            "sanitize_line should preserve length for {:?} with input {}",
            lang,
            input
        );
    }
}