//! Integration tests for work-ee34336a: remove redundant Language::Json arm in string_syntax()
//!
//! This change removes `Language::Json` from the explicit match arm in `string_syntax()`,
//! relying on the wildcard `_ => StringSyntax::CStyle` to handle it instead.
//!
//! These integration tests verify the end-to-end behavior:
//! - Language detection for JSON files produces Language::Json
//! - Preprocessor with Language::Json correctly masks strings (C-style)
//! - Preprocessor with Language::Json correctly masks comments (C-style)
//! - Language::Json.string_syntax() returns StringSyntax::CStyle (via wildcard)
//!
//! The key behavioral invariant: after removing the explicit arm, Language::Json
//! should still behave identically - returning StringSyntax::CStyle.

use diffguard_domain::Language;
use diffguard_domain::preprocess::{CommentSyntax, PreprocessOptions, Preprocessor, StringSyntax};
use diffguard_domain::rules::detect_language;
use std::path::Path;

// =============================================================================
// Integration Test: Language::Json.string_syntax() via wildcard
// =============================================================================

/// Test that Language::Json returns StringSyntax::CStyle after the fix.
///
/// This is the key behavioral test: removing the explicit match arm should NOT
/// change the behavior - Language::Json should still return StringSyntax::CStyle,
/// but now via the wildcard `_ => StringSyntax::CStyle` instead of via explicit arm.
#[test]
fn integration_language_json_string_syntax_is_cstyle() {
    // The fix removes: Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle
    // And replaces with: Language::Yaml | Language::Toml => StringSyntax::CStyle
    // Language::Json is now handled by: _ => StringSyntax::CStyle (wildcard)

    let json_syntax = Language::Json.string_syntax();
    assert_eq!(
        json_syntax,
        StringSyntax::CStyle,
        "Language::Json.string_syntax() should return StringSyntax::CStyle (via wildcard after fix)"
    );
}

// =============================================================================
// Integration Test: JSON Language Detection Pipeline
// =============================================================================

/// Test that detect_language returns "json" for .json, .jsonc, and .json5 files.
#[test]
fn integration_detect_language_json_extensions() {
    // JSON variants - should detect as "json"
    assert_eq!(detect_language(Path::new("config.json")), Some("json"));
    assert_eq!(detect_language(Path::new("data.jsonc")), Some("json"));
    assert_eq!(detect_language(Path::new("data.json5")), Some("json"));

    // Case insensitivity
    assert_eq!(detect_language(Path::new("config.JSON")), Some("json"));
    assert_eq!(detect_language(Path::new("config.JsonC")), Some("json"));
    assert_eq!(detect_language(Path::new("data.JSON5")), Some("json"));
}

/// Test that detected JSON language produces correct string_syntax.
#[test]
fn integration_detected_json_has_cstyle_string_syntax() {
    // Simulate the full pipeline: detect language from path -> parse -> use
    let json_path = Path::new("config.json");
    let detected = detect_language(json_path)
        .and_then(|s| s.parse().ok())
        .unwrap_or(Language::Unknown);

    assert_eq!(
        detected,
        Language::Json,
        "detect_language should produce Language::Json for .json files"
    );

    // The detected language should have CStyle string syntax
    assert_eq!(
        detected.string_syntax(),
        StringSyntax::CStyle,
        "Language::Json (detected) should have CStyle string syntax"
    );
}

// =============================================================================
// Integration Test: JSON Preprocessing Full Pipeline
// =============================================================================

/// Test that JSON files with strings are preprocessed correctly.
///
/// In JSON, BOTH keys and values are strings. With strings_only() mode,
/// all string content (both keys and values) gets masked.
#[test]
fn integration_json_preprocessing_masks_all_strings() {
    let mut preprocessor = Preprocessor::with_language(
        PreprocessOptions::strings_only(),
        Language::Json,
    );

    // JSON with double-quoted strings - both key and value are masked
    // Input: {"key": "value"}
    // Output: {      :       } (structure preserved, string content masked)
    let input = r#"{"key": "value"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    // JSON structure preserved
    assert!(sanitized.contains("{"), "Opening brace preserved");
    assert!(sanitized.contains("}"), "Closing brace preserved");
    assert!(sanitized.contains(":"), "Colon preserved");

    // String content masked
    assert!(!sanitized.contains("key"), "Key string masked");
    assert!(!sanitized.contains("value"), "Value string masked");

    // Length should be preserved
    assert_eq!(sanitized.len(), input.len());
}

/// Test that JSON files with C-style line comments are preprocessed correctly.
#[test]
fn integration_json_preprocessing_masks_cstyle_line_comments() {
    let mut preprocessor = Preprocessor::with_language(
        PreprocessOptions::comments_only(),
        Language::Json,
    );

    // JSON with C-style line comment (common in jsonc/json5)
    // This test is based on the existing unit test: jsonc_double_slash_comment_ignored
    let input = r#"{"key": "value" // trailing note}"#;
    let sanitized = preprocessor.sanitize_line(input);

    // The JSON should be preserved, comment should be masked
    assert!(sanitized.contains(r#"{"key": "value""#), "JSON content should be preserved");
    assert!(!sanitized.contains("trailing note"), "Line comment should be masked");

    // Length should be preserved
    assert_eq!(sanitized.len(), input.len());
}

/// Test that JSON files with C-style block comments are preprocessed correctly.
#[test]
fn integration_json_preprocessing_masks_cstyle_block_comments() {
    let mut preprocessor = Preprocessor::with_language(
        PreprocessOptions::comments_only(),
        Language::Json,
    );

    // JSON with C-style block comment (common in jsonc/json5)
    let input = r#"{"key": "value"} /* block comment */"#;
    let sanitized = preprocessor.sanitize_line(input);

    // The JSON should be preserved, block comment should be masked
    assert!(sanitized.contains(r#"{"key": "value"}"#), "JSON content should be preserved");
    assert!(!sanitized.contains("block comment"), "Block comment should be masked");

    // Length should be preserved
    assert_eq!(sanitized.len(), input.len());
}

/// Test that JSON without comments remains unchanged.
#[test]
fn integration_json_without_comments_unchanged() {
    let mut preprocessor = Preprocessor::with_language(
        PreprocessOptions::comments_only(),
        Language::Json,
    );

    let input = r#"{"key": "value", "number": 42}"#;
    let sanitized = preprocessor.sanitize_line(input);

    // Pure JSON without comments should be unchanged
    assert_eq!(sanitized, input);
    assert_eq!(sanitized.len(), input.len());
}

/// Test combined comment and string masking for JSON.
#[test]
fn integration_json_combined_masks_strings_and_comments() {
    let mut preprocessor = Preprocessor::with_language(
        PreprocessOptions::comments_and_strings(),
        Language::Json,
    );

    // JSON with both strings and comments
    let input = r#"{"password": "secret"} // remove before shipping"#;
    let sanitized = preprocessor.sanitize_line(input);

    // Both string and comment should be masked
    // JSON structure preserved, content masked
    assert!(sanitized.contains("{"), "Opening brace preserved");
    assert!(sanitized.contains("}"), "Closing brace preserved");
    assert!(sanitized.contains(":"), "Colon preserved");
    assert!(!sanitized.contains("password"), "String value should be masked");
    assert!(!sanitized.contains("secret"), "String value should be masked");
    assert!(!sanitized.contains("remove before shipping"), "Comment should be masked");

    // Length should be preserved
    assert_eq!(sanitized.len(), input.len());
}

// =============================================================================
// Integration Test: Language::Json Comment Syntax
// =============================================================================

/// Test that Language::Json has CStyle comment syntax.
///
/// Note: This is separate from string_syntax - Language::Json intentionally
/// has CStyle comment syntax (via wildcard) to handle jsonc/json5 which allow
/// C-style comments.
#[test]
fn integration_language_json_comment_syntax_is_cstyle() {
    let comment_syntax = Language::Json.comment_syntax();
    assert_eq!(
        comment_syntax,
        CommentSyntax::CStyle,
        "Language::Json.comment_syntax() should return CommentSyntax::CStyle"
    );
}

// =============================================================================
// Integration Test: Behavioral Equivalence (Json via wildcard, Unknown via wildcard)
// =============================================================================

/// Verify Language::Json and Language::Unknown behave identically in string_syntax.
///
/// After the fix removes the redundant explicit arm, both Language::Json
/// and Language::Unknown fall through to the wildcard `_ => StringSyntax::CStyle`.
/// This test verifies they have identical behavior.
#[test]
fn integration_json_and_unknown_string_syntax_identical() {
    let json_syntax = Language::Json.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    // Both should be CStyle
    assert_eq!(json_syntax, StringSyntax::CStyle);
    assert_eq!(unknown_syntax, StringSyntax::CStyle);

    // The critical assertion: Json and Unknown should behave identically
    // because neither has an explicit match arm - both fall through to wildcard.
    assert_eq!(
        json_syntax, unknown_syntax,
        "Language::Json and Language::Unknown should behave identically (both via wildcard)"
    );
}

/// Verify Language::Json, Language::Yaml, and Language::Toml all return CStyle.
///
/// All three data interchange formats use C-style string syntax.
/// YAML and TOML have explicit arms (not redundant), JSON uses wildcard.
#[test]
fn integration_data_interchange_formats_all_cstyle() {
    assert_eq!(
        Language::Json.string_syntax(),
        StringSyntax::CStyle,
        "JSON should use CStyle string syntax"
    );
    assert_eq!(
        Language::Yaml.string_syntax(),
        StringSyntax::CStyle,
        "YAML should use CStyle string syntax (explicit arm)"
    );
    assert_eq!(
        Language::Toml.string_syntax(),
        StringSyntax::CStyle,
        "TOML should use CStyle string syntax (explicit arm)"
    );
}

// =============================================================================
// Integration Test: End-to-End JSON File Processing
// =============================================================================

/// Test the complete workflow: detect JSON file language -> create preprocessor -> process
#[test]
fn integration_complete_json_file_workflow() {
    // Step 1: Detect language from file path
    let file_path = Path::new("package.json");
    let detected_lang = detect_language(file_path)
        .and_then(|s| s.parse().ok())
        .unwrap_or(Language::Unknown);

    assert_eq!(detected_lang, Language::Json);

    // Step 2: Create preprocessor with detected language
    let mut preprocessor = Preprocessor::with_language(
        PreprocessOptions::comments_and_strings(),
        detected_lang,
    );

    // Step 3: Process realistic JSON content (package.json style)
    // Comments only mode should preserve the JSON structure
    let line = r#"{"name": "my-package"} // package info"#;

    let sanitized = preprocessor.sanitize_line(line);

    // Verify: structure preserved, values and comments masked
    assert!(sanitized.contains("{"), "Opening brace preserved");
    assert!(sanitized.contains("}"), "Closing brace preserved");
    assert!(sanitized.contains(":"), "Colon preserved");
    assert!(!sanitized.contains("my-package"), "String value masked");
    assert!(!sanitized.contains("package info"), "Comment masked");

    // Verify line length preserved
    assert_eq!(line.len(), sanitized.len());
}

/// Test JSON preprocessing with escape sequences in strings.
#[test]
fn integration_json_string_with_escapes() {
    let mut preprocessor = Preprocessor::with_language(
        PreprocessOptions::strings_only(),
        Language::Json,
    );

    // JSON with escaped characters in string
    let input = r#"{"path": "C:\\Users\\name"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    // JSON structure preserved
    assert!(sanitized.contains("{"), "Opening brace preserved");
    assert!(sanitized.contains("}"), "Closing brace preserved");
    assert!(sanitized.contains(":"), "Colon preserved");

    // String content should be masked (including escape sequences)
    assert!(!sanitized.contains("path"), "key masked");
    assert!(!sanitized.contains("C:"), "path value masked");
    assert!(!sanitized.contains("Users"), "path value masked");

    // Length preserved
    assert_eq!(sanitized.len(), input.len());
}

/// Test that multiple JSON files processed sequentially maintain correct behavior.
#[test]
fn integration_multiple_json_files_sequential_processing() {
    let mut preprocessor = Preprocessor::with_language(
        PreprocessOptions::comments_and_strings(),
        Language::Json,
    );

    // Simulate processing multiple JSON files sequentially
    let files = vec![
        r#"{"name": "file1"} // config"#,
        r#"{"name": "file2"} // config"#,
        r#"{"name": "file3"} // config"#,
    ];

    for (i, input) in files.iter().enumerate() {
        let sanitized = preprocessor.sanitize_line(input);
        assert!(
            sanitized.contains("{"),
            "File {}: opening brace preserved",
            i + 1
        );
        assert!(
            sanitized.contains("}"),
            "File {}: closing brace preserved",
            i + 1
        );
        assert!(
            sanitized.contains(":"),
            "File {}: colon preserved",
            i + 1
        );
        assert!(!sanitized.contains("file"), "File {}: value masked", i + 1);
        assert!(!sanitized.contains("config"), "File {}: comment masked", i + 1);
        assert_eq!(input.len(), sanitized.len(), "File {}: length preserved", i + 1);
    }
}

/// Verify that Language::Json and Language::C behave identically in string masking.
///
/// Both use CStyle string syntax. This test verifies the preprocessing behavior
/// is consistent between JSON (via wildcard) and C (via wildcard) languages.
#[test]
fn integration_json_and_c_behave_identically_for_strings() {
    let mut json_preprocessor = Preprocessor::with_language(
        PreprocessOptions::strings_only(),
        Language::Json,
    );
    let mut c_preprocessor = Preprocessor::with_language(
        PreprocessOptions::strings_only(),
        Language::C,
    );

    // Same string content in both languages
    let json_input = r#"{"key": "value"}"#;
    let c_input = r#"{"key": "value"}"#;

    let json_sanitized = json_preprocessor.sanitize_line(json_input);
    let c_sanitized = c_preprocessor.sanitize_line(c_input);

    // Both should mask string content identically (since both use CStyle)
    assert_eq!(json_sanitized, c_sanitized,
        "JSON and C should mask strings identically (both use CStyle)");
}
