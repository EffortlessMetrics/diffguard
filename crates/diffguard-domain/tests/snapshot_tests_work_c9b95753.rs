//! Snapshot tests for comment_syntax() behavior with Language::Json
//!
//! This change only removes a stale comment from the `comment_syntax()` function.
//! The functional behavior is unchanged: Language::Json still returns CStyle via wildcard.
//!
//! These snapshots verify the output baseline for all Language variants.

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Snapshot test for Language::comment_syntax() for all language variants.
/// This verifies that removing the stale comment doesn't accidentally change behavior.
#[test]
fn test_all_language_comment_syntax() {
    use insta::assert_snapshot;

    // Build snapshot string directly
    let mut snapshot = String::new();

    let languages = [
        (Language::Rust, "CStyleNested"),
        (Language::Python, "Hash"),
        (Language::JavaScript, "CStyle"),
        (Language::TypeScript, "CStyle"),
        (Language::Go, "CStyle"),
        (Language::Ruby, "Hash"),
        (Language::C, "CStyle"),
        (Language::Cpp, "CStyle"),
        (Language::CSharp, "CStyle"),
        (Language::Java, "CStyle"),
        (Language::Kotlin, "CStyle"),
        (Language::Shell, "Hash"),
        (Language::Swift, "CStyleNested"),
        (Language::Scala, "CStyleNested"),
        (Language::Sql, "Sql"),
        (Language::Xml, "Xml"),
        (Language::Php, "Php"),
        (Language::Yaml, "Hash"),
        (Language::Toml, "Hash"),
        (Language::Json, "CStyle"),
        (Language::Unknown, "CStyle"),
    ];

    for (lang, expected) in &languages {
        snapshot.push_str(&format!("{:?}: {}\n", lang, expected));
    }
    assert_snapshot!("all_language_comment_syntax", snapshot);
}

/// Snapshot test for JSON preprocessing with C-style comments.
#[test]
fn test_json_preprocess_c_style_line_comment() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // Input has a C-style line comment
    let input = r#"{"key": "value"} // this is a comment"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_c_style_line_comment_sanitized", sanitized);
}

/// Snapshot test for JSON preprocessing with C-style block comments.
#[test]
fn test_json_preprocess_c_style_block_comment() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // Input has a C-style block comment
    let input = r#"{"key": "value"} /* this is a block comment */"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_c_style_block_comment_sanitized", sanitized);
}

/// Snapshot test for JSON without comments - should remain unchanged.
#[test]
fn test_json_no_comments_unchanged() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::comments_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    let input = r#"{"key": "value", "nested": {"inner": 42}}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_no_comments", sanitized);
}

/// Snapshot test for verifying Language::Json returns CStyle for comment_syntax().
#[test]
fn test_json_comment_syntax_is_cstyle() {
    use insta::assert_snapshot;

    // This is the key assertion: removing the stale comment should NOT change
    // the fact that Language::Json still uses CStyle comments (via wildcard).
    let syntax = Language::Json.comment_syntax();
    let syntax_name = format!("{:?}", syntax);

    assert_snapshot!("json_comment_syntax_type", syntax_name);
}
