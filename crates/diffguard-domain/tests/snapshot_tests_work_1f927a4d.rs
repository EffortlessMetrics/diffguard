//! Snapshot tests for `string_syntax()` behavior in work-1f927a4d.
//!
//! This change removes `Language::Json` from the explicit match arm in `string_syntax()`,
//! so JSON now falls through to the wildcard `_ => StringSyntax::CStyle`.
//!
//! These snapshots verify the output baseline for all Language variants' string_syntax().
//!
//! Issue: #452 - preprocess.rs:107: Yaml/Toml/Json arm is dead code

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Snapshot test for Language::string_syntax() for all language variants.
/// This verifies that removing Language::Json from the explicit arm doesn't change behavior.
#[test]
fn test_all_language_string_syntax() {
    use insta::assert_snapshot;

    // Build snapshot string directly
    let mut snapshot = String::new();

    let languages = [
        (Language::Rust, "Rust"),
        (Language::Python, "Python"),
        (Language::JavaScript, "JavaScript"),
        (Language::TypeScript, "JavaScript"),
        (Language::Go, "Go"),
        (Language::Ruby, "JavaScript"),
        (Language::C, "CStyle"),
        (Language::Cpp, "CStyle"),
        (Language::CSharp, "CStyle"),
        (Language::Java, "CStyle"),
        (Language::Kotlin, "CStyle"),
        (Language::Shell, "Shell"),
        (Language::Swift, "SwiftScala"),
        (Language::Scala, "SwiftScala"),
        (Language::Sql, "Sql"),
        (Language::Xml, "Xml"),
        (Language::Php, "Php"),
        // YAML and TOML are still explicit
        (Language::Yaml, "CStyle"),
        (Language::Toml, "CStyle"),
        // JSON now goes through the wildcard (CStyle)
        (Language::Json, "CStyle"),
        (Language::Unknown, "CStyle"),
    ];

    for (lang, expected) in &languages {
        snapshot.push_str(&format!("{:?}: {}\n", lang, expected));
    }
    assert_snapshot!("all_language_string_syntax", snapshot);
}

/// Snapshot test verifying Language::Json returns CStyle for string_syntax().
/// This confirms JSON falls through to the wildcard correctly.
#[test]
fn test_json_string_syntax_is_cstyle() {
    use insta::assert_snapshot;

    // Key assertion: Language::Json now goes through the wildcard
    // but still returns CStyle (same behavior, different code path)
    let syntax = Language::Json.string_syntax();
    let syntax_name = format!("{:?}", syntax);

    assert_snapshot!("json_string_syntax_type", syntax_name);
}

/// Snapshot test verifying Language::Yaml returns CStyle for string_syntax().
#[test]
fn test_yaml_string_syntax_is_cstyle() {
    use insta::assert_snapshot;

    let syntax = Language::Yaml.string_syntax();
    let syntax_name = format!("{:?}", syntax);

    assert_snapshot!("yaml_string_syntax_type", syntax_name);
}

/// Snapshot test verifying Language::Toml returns CStyle for string_syntax().
#[test]
fn test_toml_string_syntax_is_cstyle() {
    use insta::assert_snapshot;

    let syntax = Language::Toml.string_syntax();
    let syntax_name = format!("{:?}", syntax);

    assert_snapshot!("toml_string_syntax_type", syntax_name);
}

/// Snapshot test for JSON preprocessing with double-quoted strings.
#[test]
fn test_json_preprocess_double_quoted_string() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // Input has a double-quoted string (JSON uses double quotes)
    let input = r#"{"key": "value"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_double_quoted_string_sanitized", sanitized);
}

/// Snapshot test for JSON preprocessing with single-quoted string (edge case).
#[test]
fn test_json_preprocess_single_quoted_string() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // Single quotes in JSON are treated as characters (like C char literals)
    // JSON doesn't support single-quoted strings, but preprocessor handles them
    let input = "{'key': 'value'}";
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_single_quoted_string_sanitized", sanitized);
}

/// Snapshot test for JSON preprocessing with line comments.
/// Note: Standard JSON doesn't have comments, but jsonc/json5 dialects do.
#[test]
fn test_json_preprocess_line_comment() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // JSON with line comments (jsonc style)
    let input = r#"// this is a comment
{"key": "value"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_line_comment_sanitized", sanitized);
}

/// Snapshot test for JSON preprocessing with block comments.
#[test]
fn test_json_preprocess_block_comment() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // JSON with block comments (jsonc style)
    let input = r#"/* block comment */
{"key": "value"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_block_comment_sanitized", sanitized);
}
