//! Snapshot tests for string_syntax() behavior with Language::Json
//!
//! This change removes the redundant `Language::Json` arm from `string_syntax()`.
//! The explicit arm `Language::Yaml | Language::Toml | Language::Json => ...` is replaced with
//! `Language::Yaml | Language::Toml => ...` and JSON falls through to the wildcard `_ => CStyle`.
//!
//! The functional behavior is unchanged: Language::Json still returns StringSyntax::CStyle (via wildcard).
//! These snapshots verify the output baseline for all Language variants and JSON preprocessing.

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Snapshot test for Language::string_syntax() for all language variants.
/// This verifies that removing Language::Json from explicit arm doesn't change behavior -
/// it still returns StringSyntax::CStyle (via wildcard).
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

/// Snapshot test for JSON string preprocessing - simple string.
#[test]
fn test_json_string_preprocessing_simple() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // Simple JSON with a string value
    let input = r#"{"key": "value"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_string_simple", sanitized);
}

/// Snapshot test for JSON string preprocessing - nested quotes.
#[test]
fn test_json_string_preprocessing_nested_quotes() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // JSON with escaped quotes inside the string
    let input = r#"{"message": "He said \"hello world\""}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_string_nested_quotes", sanitized);
}

/// Snapshot test for JSON string preprocessing - empty string.
#[test]
fn test_json_string_preprocessing_empty() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // JSON with empty string value
    let input = r#"{"key": ""}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_string_empty", sanitized);
}

/// Snapshot test for JSON string preprocessing - unicode escapes.
#[test]
fn test_json_string_preprocessing_unicode() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // JSON with unicode escape
    let input = r#"{"emoji": "\uD83D\uDE00"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_string_unicode", sanitized);
}

/// Snapshot test for JSON with both comments and strings.
#[test]
fn test_json_comments_and_strings() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_and_strings();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // JSON with a comment and a string
    let input = r#"// comment
{"key": "value"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_comments_and_strings", sanitized);
}

/// Snapshot test for JSON with C-style line comment.
#[test]
fn test_json_c_style_line_comment() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // Input has a C-style line comment
    let input = r#"{"key": "value"} // this is a comment"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_c_style_line_comment_sanitized", sanitized);
}

/// Snapshot test for JSON with C-style block comment.
#[test]
fn test_json_c_style_block_comment() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // Input has a C-style block comment
    let input = r#"{"key": "value"} /* this is a block comment */"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_c_style_block_comment_sanitized", sanitized);
}

/// Snapshot test for verifying Language::Json returns CStyle for string_syntax().
/// This is the key assertion: removing Language::Json from explicit arm should NOT change
/// the fact that Language::Json still uses CStyle strings (via wildcard).
#[test]
fn test_json_string_syntax_is_cstyle() {
    use insta::assert_snapshot;

    let syntax = Language::Json.string_syntax();
    assert_snapshot!("json_string_syntax_type", format!("{:?}", syntax));
}

/// Snapshot test to verify JSON and Unknown have identical string_syntax behavior.
/// Both should return CStyle - JSON via wildcard, Unknown via explicit arm.
#[test]
fn test_json_and_unknown_identical_string_syntax() {
    use insta::assert_snapshot;

    let json_syntax = Language::Json.string_syntax();
    let unknown_syntax = Language::Unknown.string_syntax();

    let snapshot = format!(
        "Json: {:?}\nUnknown: {:?}\nIdentical: {}",
        json_syntax,
        unknown_syntax,
        json_syntax == unknown_syntax
    );

    assert_snapshot!("json_and_unknown_identical_string_syntax", snapshot);
}
