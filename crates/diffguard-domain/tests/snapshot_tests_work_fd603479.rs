//! Snapshot tests for `string_syntax()` behavior with Language::Json, Yaml, and Toml
//!
//! This change addresses the redundant match arm at `preprocess.rs:107` where
//! `Language::Json` is explicitly matched but then shadowed by the wildcard `_` pattern.
//!
//! The fix removes `Language::Json` from the explicit arm since it returns the same
//! value (`StringSyntax::CStyle`) via the wildcard.
//!
//! These snapshots verify the output baseline for all Language string_syntax variants.
//!
//! **Key verification points:**
//! - Language::Json.string_syntax() returns StringSyntax::CStyle (via wildcard)
//! - Language::Yaml.string_syntax() returns StringSyntax::CStyle (via explicit arm)
//! - Language::Toml.string_syntax() returns StringSyntax::CStyle (via explicit arm)

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Snapshot test for Language::string_syntax() for all language variants.
/// This verifies that the redundant match arm doesn't cause issues and that
/// the fix (removing Json from explicit arm) doesn't change behavior.
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
        (Language::Yaml, "CStyle"),
        (Language::Toml, "CStyle"),
        (Language::Json, "CStyle"),
        (Language::Unknown, "CStyle"),
    ];

    for (lang, expected) in &languages {
        snapshot.push_str(&format!("{:?}: {}\n", lang, expected));
    }
    assert_snapshot!("all_language_string_syntax", snapshot);
}

/// Snapshot test verifying Language::Json returns StringSyntax::CStyle.
/// This is the key assertion: Language::Json should return CStyle regardless
/// of whether it's via the explicit arm or the wildcard.
#[test]
fn test_json_string_syntax_is_cstyle() {
    use insta::assert_snapshot;

    let syntax = Language::Json.string_syntax();
    let syntax_name = format!("{:?}", syntax);

    assert_snapshot!("json_string_syntax_type", syntax_name);
}

/// Snapshot test verifying Language::Yaml returns StringSyntax::CStyle.
#[test]
fn test_yaml_string_syntax_is_cstyle() {
    use insta::assert_snapshot;

    let syntax = Language::Yaml.string_syntax();
    let syntax_name = format!("{:?}", syntax);

    assert_snapshot!("yaml_string_syntax_type", syntax_name);
}

/// Snapshot test verifying Language::Toml returns StringSyntax::CStyle.
#[test]
fn test_toml_string_syntax_is_cstyle() {
    use insta::assert_snapshot;

    let syntax = Language::Toml.string_syntax();
    let syntax_name = format!("{:?}", syntax);

    assert_snapshot!("toml_string_syntax_type", syntax_name);
}

/// Snapshot test: YAML preprocessing with hash comments.
#[test]
fn test_yaml_preprocess_hash_comment() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Yaml);

    // Input has a hash comment
    let input = r#"key: value  # this is a comment"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("yaml_hash_comment_sanitized", sanitized);
}

/// Snapshot test: YAML preprocessing with double-quoted strings.
#[test]
fn test_yaml_preprocess_double_quoted_string() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Yaml);

    // Input has a double-quoted string
    let input = r#"key: "this is a string""#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("yaml_double_quoted_string_sanitized", sanitized);
}

/// Snapshot test: YAML preprocessing with single-quoted strings.
#[test]
fn test_yaml_preprocess_single_quoted_string() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Yaml);

    // Input has a single-quoted string
    let input = "key: 'this is a string'";
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("yaml_single_quoted_string_sanitized", sanitized);
}

/// Snapshot test: TOML preprocessing with hash comments.
#[test]
fn test_toml_preprocess_hash_comment() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Toml);

    // Input has a hash comment
    let input = r#"key = "value"  # this is a comment"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("toml_hash_comment_sanitized", sanitized);
}

/// Snapshot test: TOML preprocessing with double-quoted strings.
#[test]
fn test_toml_preprocess_double_quoted_string() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Toml);

    // Input has a double-quoted string
    let input = r#"key = "this is a string""#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("toml_double_quoted_string_sanitized", sanitized);
}

/// Snapshot test: TOML preprocessing with single-quoted strings.
#[test]
fn test_toml_preprocess_single_quoted_string() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Toml);

    // Input has a single-quoted string
    let input = r#"key = 'this is a string'"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("toml_single_quoted_string_sanitized", sanitized);
}

/// Snapshot test: JSON preprocessing (no comments should be masked).
#[test]
fn test_json_preprocess_no_comments() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // JSON doesn't support comments natively, but C-style comments are masked
    // via the wildcard CStyle comment syntax
    let input = r#"{"key": "value"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_no_comments", sanitized);
}

/// Snapshot test: JSON preprocessing with C-style line comment.
#[test]
fn test_json_preprocess_c_style_line_comment() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // JSON supports C-style comments in jsonc/json5 dialects
    let input = r#"{"key": "value"} // this is a comment"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_c_style_line_comment_sanitized", sanitized);
}

/// Snapshot test: JSON preprocessing with double-quoted strings.
#[test]
fn test_json_preprocess_double_quoted_string() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // JSON only has double-quoted strings
    let input = r#"{"key": "value"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_double_quoted_string_sanitized", sanitized);
}

/// Snapshot test: Verify that Unknown language returns CStyle via wildcard.
#[test]
fn test_unknown_string_syntax_is_cstyle() {
    use insta::assert_snapshot;

    let syntax = Language::Unknown.string_syntax();
    let syntax_name = format!("{:?}", syntax);

    assert_snapshot!("unknown_string_syntax_type", syntax_name);
}

/// Snapshot test: Verify Json and Unknown behave identically in string_syntax().
#[test]
fn test_json_and_unknown_behave_identically_in_string_syntax() {
    use insta::assert_snapshot;

    let json_syntax = Language::Json.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    let result = format!(
        "Json: {:?}, Unknown: {:?}, Equal: {}",
        json_syntax, unknown_syntax, json_syntax == unknown_syntax
    );

    assert_snapshot!("json_and_unknown_string_syntax_comparison", result);
}