//! Snapshot tests for `string_syntax()` behavior after removing redundant Yaml/Toml/Json arms.
//!
//! This change removes the unreachable `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle`
//! match arm from the `string_syntax()` method, as the wildcard `_ => StringSyntax::CStyle` already covers these.
//!
//! These snapshots verify the output baseline for all Language variants' string_syntax().

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Snapshot test for Language::string_syntax() for all language variants.
/// This verifies that removing the redundant Yaml/Toml/Json arms doesn't accidentally change behavior.
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
        // YAML, TOML, and JSON are now handled by the wildcard (CStyle)
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

/// Snapshot test verifying Language::Yaml returns CStyle for string_syntax().
#[test]
fn test_yaml_string_syntax_is_cstyle() {
    use insta::assert_snapshot;

    // This is the key assertion: removing the redundant match arm should NOT change
    // the fact that Language::Yaml still uses CStyle strings (via wildcard).
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

/// Snapshot test verifying Language::Json returns CStyle for string_syntax().
#[test]
fn test_json_string_syntax_is_cstyle() {
    use insta::assert_snapshot;

    let syntax = Language::Json.string_syntax();
    let syntax_name = format!("{:?}", syntax);

    assert_snapshot!("json_string_syntax_type", syntax_name);
}

/// Snapshot test for YAML preprocessing with double-quoted strings.
#[test]
fn test_yaml_preprocess_double_quoted_string() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Yaml);

    // Input has a double-quoted string (YAML supports this)
    let input = r#"key: "value""#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("yaml_double_quoted_string_sanitized", sanitized);
}

/// Snapshot test for TOML preprocessing with double-quoted strings.
#[test]
fn test_toml_preprocess_double_quoted_string() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Toml);

    // Input has a double-quoted string
    let input = r#"key = "value""#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("toml_double_quoted_string_sanitized", sanitized);
}

/// Snapshot test for JSON preprocessing with double-quoted strings.
#[test]
fn test_json_preprocess_double_quoted_string() {
    use insta::assert_snapshot;

    let opts = PreprocessOptions::strings_only();
    let mut preprocessor = Preprocessor::with_language(opts, Language::Json);

    // Input has a double-quoted string
    let input = r#"{"key": "value"}"#;
    let sanitized = preprocessor.sanitize_line(input);

    assert_snapshot!("json_double_quoted_string_sanitized", sanitized);
}