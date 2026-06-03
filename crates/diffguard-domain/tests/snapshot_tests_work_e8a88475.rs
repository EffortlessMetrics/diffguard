//! Snapshot tests for preprocess.rs #[must_use] factory/constructor methods
//!
//! These tests capture the baseline Debug output of the factory methods and constructors
//! that were annotated with #[must_use] in work-e8a88475.
//!
//! The #[must_use] attribute is purely a compile-time lint - it does not affect
//! runtime behavior. These snapshots verify the Debug formatting of the returned values.

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

// =============================================================================
// PreprocessOptions factory method Debug output snapshots
// =============================================================================

/// Snapshot for PreprocessOptions::none() Debug output
#[test]
fn snapshot_preprocess_options_none_debug() {
    use insta::assert_snapshot;
    let opts = PreprocessOptions::none();
    assert_snapshot!("preprocess_options_none_debug", format!("{:?}", opts));
}

/// Snapshot for PreprocessOptions::comments_only() Debug output
#[test]
fn snapshot_preprocess_options_comments_only_debug() {
    use insta::assert_snapshot;
    let opts = PreprocessOptions::comments_only();
    assert_snapshot!(
        "preprocess_options_comments_only_debug",
        format!("{:?}", opts)
    );
}

/// Snapshot for PreprocessOptions::strings_only() Debug output
#[test]
fn snapshot_preprocess_options_strings_only_debug() {
    use insta::assert_snapshot;
    let opts = PreprocessOptions::strings_only();
    assert_snapshot!(
        "preprocess_options_strings_only_debug",
        format!("{:?}", opts)
    );
}

/// Snapshot for PreprocessOptions::comments_and_strings() Debug output
#[test]
fn snapshot_preprocess_options_comments_and_strings_debug() {
    use insta::assert_snapshot;
    let opts = PreprocessOptions::comments_and_strings();
    assert_snapshot!(
        "preprocess_options_comments_and_strings_debug",
        format!("{:?}", opts)
    );
}

// =============================================================================
// Preprocessor constructor Debug output snapshots
// =============================================================================

/// Snapshot for Preprocessor::new() Debug output
#[test]
fn snapshot_preprocessor_new_debug() {
    use insta::assert_snapshot;
    let preprocessor = Preprocessor::new(PreprocessOptions::none());
    assert_snapshot!("preprocessor_new_debug", format!("{:?}", preprocessor));
}

/// Snapshot for Preprocessor::with_language() Debug output
#[test]
fn snapshot_preprocessor_with_language_debug() {
    use insta::assert_snapshot;
    let preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);
    assert_snapshot!(
        "preprocessor_with_language_debug",
        format!("{:?}", preprocessor)
    );
}

// =============================================================================
// sanitize_line output snapshots using #[must_use] factory methods
// =============================================================================

/// Snapshot: sanitize_line with PreprocessOptions::none() - no masking
#[test]
fn snapshot_sanitize_none_options_rust_comment() {
    use insta::assert_snapshot;
    let mut preprocessor = Preprocessor::with_language(PreprocessOptions::none(), Language::Rust);
    let input = "let x = 1; // comment";
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("sanitize_none_options_rust_comment", result);
}

/// Snapshot: sanitize_line with PreprocessOptions::comments_only()
#[test]
fn snapshot_sanitize_comments_only_rust_comment() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);
    let input = "let x = 1; // comment";
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("sanitize_comments_only_rust_comment", result);
}

/// Snapshot: sanitize_line with PreprocessOptions::strings_only()
#[test]
fn snapshot_sanitize_strings_only_rust_string() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);
    let input = r#"let s = "a string";"#;
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("sanitize_strings_only_rust_string", result);
}

/// Snapshot: sanitize_line with PreprocessOptions::comments_and_strings()
#[test]
fn snapshot_sanitize_comments_and_strings_mixed() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Rust);
    let input = r#"let s = "string"; // comment"#;
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("sanitize_comments_and_strings_mixed", result);
}

/// Snapshot: Python hash comment with PreprocessOptions::comments_only()
#[test]
fn snapshot_sanitize_python_hash_comment() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Python);
    let input = "x = 1  # this is a comment";
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("sanitize_python_hash_comment", result);
}

/// Snapshot: JavaScript template literal with PreprocessOptions::strings_only()
#[test]
fn snapshot_sanitize_js_template_literal() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);
    let input = r#"let greeting = `Hello, ${name}!`;"#;
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("sanitize_js_template_literal", result);
}

/// Snapshot: Rust raw string with PreprocessOptions::strings_only()
#[test]
fn snapshot_sanitize_rust_raw_string() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);
    let input = r##"let path = r#"C:\Users\name"#;"##;
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("sanitize_rust_raw_string", result);
}

/// Snapshot: Empty string with PreprocessOptions::none()
#[test]
fn snapshot_sanitize_empty_string_none_options() {
    use insta::assert_snapshot;
    let mut preprocessor = Preprocessor::with_language(PreprocessOptions::none(), Language::Rust);
    let result = preprocessor.sanitize_line("");
    assert_snapshot!("sanitize_empty_string_none_options", result);
}

/// Snapshot: Empty string with PreprocessOptions::comments_only()
#[test]
fn snapshot_sanitize_empty_string_comments_only() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);
    let result = preprocessor.sanitize_line("");
    assert_snapshot!("sanitize_empty_string_comments_only", result);
}

/// Snapshot: Multi-line state tracking with Preprocessor::new()
#[test]
fn snapshot_sanitize_multiline_block_comment_new() {
    use insta::assert_snapshot;
    let mut preprocessor = Preprocessor::new(PreprocessOptions::comments_only());

    // First line starts a block comment
    let line1 = "let x = 1; /* start";
    let r1 = preprocessor.sanitize_line(line1);

    // Second line continues the block comment
    let line2 = "let y = 2; middle";
    let r2 = preprocessor.sanitize_line(line2);

    // Third line closes the block comment
    let line3 = "let z = 3; */ end";
    let r3 = preprocessor.sanitize_line(line3);

    let combined = format!("{0}\n{1}\n{2}", r1, r2, r3);
    assert_snapshot!("sanitize_multiline_block_comment_new", combined);
}

/// Snapshot: Multi-line state tracking with Preprocessor::with_language()
#[test]
fn snapshot_sanitize_multiline_block_comment_with_language() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    // First line starts a block comment
    let line1 = "let x = 1; /* start";
    let r1 = preprocessor.sanitize_line(line1);

    // Second line continues the block comment
    let line2 = "let y = 2; middle";
    let r2 = preprocessor.sanitize_line(line2);

    // Third line closes the block comment
    let line3 = "let z = 3; */ end";
    let r3 = preprocessor.sanitize_line(line3);

    let combined = format!("{0}\n{1}\n{2}", r1, r2, r3);
    assert_snapshot!("sanitize_multiline_block_comment_with_language", combined);
}

// =============================================================================
// All supported languages with comments_and_strings() using with_language()
// =============================================================================

/// Snapshot: All Language variants with comments_and_strings() - Rust
#[test]
fn snapshot_all_languages_comments_and_strings_rust() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Rust);
    let input = r#"fn foo() { "string" } // comment"#;
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("all_languages_comments_and_strings_rust", result);
}

/// Snapshot: All Language variants with comments_and_strings() - Python
#[test]
fn snapshot_all_languages_comments_and_strings_python() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Python);
    let input = r#"x = "string"  # comment"#;
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("all_languages_comments_and_strings_python", result);
}

/// Snapshot: All Language variants with comments_and_strings() - JavaScript
#[test]
fn snapshot_all_languages_comments_and_strings_javascript() {
    use insta::assert_snapshot;
    let mut preprocessor = Preprocessor::with_language(
        PreprocessOptions::comments_and_strings(),
        Language::JavaScript,
    );
    let input = r#"let x = "string"; // comment"#;
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("all_languages_comments_and_strings_javascript", result);
}

/// Snapshot: All Language variants with comments_and_strings() - Go
#[test]
fn snapshot_all_languages_comments_and_strings_go() {
    use insta::assert_snapshot;
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Go);
    let input = r#"x := "string" // comment"#;
    let result = preprocessor.sanitize_line(input);
    assert_snapshot!("all_languages_comments_and_strings_go", result);
}
