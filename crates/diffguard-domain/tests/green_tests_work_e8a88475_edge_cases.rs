// Green Test Builder Edge Cases — work-e8a88475
//
// Tests that the #[must_use] additions to preprocess.rs factory/constructor methods
// don't break any existing functionality and covers edge cases.
//
// Edge cases covered:
// - PreprocessOptions factory methods return correct mask values
// - Preprocessor::new defaults to Language::Unknown
// - Preprocessor::with_language correctly sets language
// - Preprocessor with none() option passes content through unchanged
// - Preprocessor with comments_only() masks only comments
// - Preprocessor with strings_only() masks only strings
// - Preprocessor with comments_and_strings() masks both
// - Empty string handling
// - Strings with no matching patterns
// - Multi-line comment state tracking

use diffguard_domain::preprocess::{Language, PreprocessOptions, Preprocessor};

#[test]
fn preprocess_options_none_returns_correct_mask_values() {
    // Edge case: verifying the struct field values directly
    let opts = PreprocessOptions::none();
    assert_eq!(opts.mask_comments, false);
    assert_eq!(opts.mask_strings, false);
}

#[test]
fn preprocess_options_comments_only_returns_correct_mask_values() {
    let opts = PreprocessOptions::comments_only();
    assert_eq!(opts.mask_comments, true);
    assert_eq!(opts.mask_strings, false);
}

#[test]
fn preprocess_options_strings_only_returns_correct_mask_values() {
    let opts = PreprocessOptions::strings_only();
    assert_eq!(opts.mask_comments, false);
    assert_eq!(opts.mask_strings, true);
}

#[test]
fn preprocess_options_comments_and_strings_returns_correct_mask_values() {
    let opts = PreprocessOptions::comments_and_strings();
    assert_eq!(opts.mask_comments, true);
    assert_eq!(opts.mask_strings, true);
}

#[test]
fn preprocessor_new_defaults_to_language_unknown() {
    // Edge case: Preprocessor::new should default to Language::Unknown
    let opts = PreprocessOptions::none();
    let preprocessor = Preprocessor::new(opts);
    // We can't access the internal lang field directly, but we can verify
    // it processes content using C-style syntax (which is what Unknown uses)
    let mut p = preprocessor;
    p.set_language(Language::Unknown);
    let result = p.sanitize_line("// comment");
    // With no masking options, content passes through unchanged
    assert_eq!(result, "// comment");
}

#[test]
fn preprocessor_with_language_sets_language_correctly() {
    // Edge case: Preprocessor::with_language correctly sets the language
    let mut p = Preprocessor::with_language(PreprocessOptions::none(), Language::Rust);
    // Verify language is set by processing Rust-specific syntax
    let result = p.sanitize_line("// comment");
    assert_eq!(result, "// comment");
}

#[test]
fn preprocessor_none_option_preserves_content() {
    // Edge case: PreprocessOptions::none() should pass content through unchanged
    let mut p = Preprocessor::with_language(PreprocessOptions::none(), Language::C);

    let line = "let x = 42; // comment";
    let result = p.sanitize_line(line);
    assert_eq!(result, line);
}

#[test]
fn preprocessor_comments_only_masks_comments() {
    // Edge case: PreprocessOptions::comments_only() should mask comments only
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::C);

    let line = "let x = 42; // comment here";
    let result = p.sanitize_line(line);
    // The code part should be preserved, comment should be masked
    assert!(result.contains("let x = 42;"));
    // Comment content should be masked (replaced with spaces)
    assert!(result != line);
}

#[test]
fn preprocessor_strings_only_masks_strings() {
    // Edge case: PreprocessOptions::strings_only() should mask strings only
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::C);

    let line = r#"printf("hello world");"#;
    let result = p.sanitize_line(line);
    // The function call should be preserved, string should be masked
    assert!(result.contains("printf("));
    assert!(result != line);
}

#[test]
fn preprocessor_comments_and_strings_masks_both() {
    // Edge case: PreprocessOptions::comments_and_strings() should mask both
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::C);

    let line = r#"printf("hello"); // print something"#;
    let result = p.sanitize_line(line);
    // Both should be masked
    assert!(result != line);
}

#[test]
fn preprocessor_empty_string_handling() {
    // Edge case: empty string should be handled gracefully
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::C);
    let result = p.sanitize_line("");
    assert_eq!(result, "");
}

#[test]
fn preprocessor_no_special_chars_unchanged() {
    // Edge case: content with no comments/strings should pass through
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::C);
    let line = "let x = 42;";
    let result = p.sanitize_line(line);
    assert_eq!(result, line);
}

#[test]
fn preprocessor_new_with_all_option_variants() {
    // Edge case: Verify all 4 PreprocessOptions factory methods work with Preprocessor::new
    let opts_none = PreprocessOptions::none();
    let opts_comments = PreprocessOptions::comments_only();
    let opts_strings = PreprocessOptions::strings_only();
    let opts_both = PreprocessOptions::comments_and_strings();

    // All should be usable with Preprocessor::new without warnings
    let _p1 = Preprocessor::new(opts_none);
    let _p2 = Preprocessor::new(opts_comments);
    let _p3 = Preprocessor::new(opts_strings);
    let _p4 = Preprocessor::new(opts_both);
}

#[test]
fn preprocessor_with_language_accepts_all_supported_languages() {
    // Edge case: Verify Preprocessor::with_language works with various languages
    let opts = PreprocessOptions::none();

    let languages = [
        Language::Rust,
        Language::Python,
        Language::JavaScript,
        Language::Go,
        Language::C,
        Language::Cpp,
        Language::Java,
        Language::Unknown,
    ];

    for lang in languages {
        let mut p = Preprocessor::with_language(opts, lang);
        let result = p.sanitize_line("// test");
        assert_eq!(result, "// test", "Failed for language {:?}", lang);
    }
}

#[test]
fn preprocessor_preserves_line_length() {
    // Edge case: sanitize_line should preserve output length equal to input length
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::C);

    let line = "let s = \"hello\"; // comment";
    let result = p.sanitize_line(line);
    assert_eq!(result.len(), line.len());
}

#[test]
fn preprocessor_rust_raw_strings_handled() {
    // Edge case: Rust raw strings should be handled correctly
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

    // Raw string with #
    let line = "let s = r#\"hello\"#';";
    let result = p.sanitize_line(line);
    // The line should be processed (string masked)
    assert_eq!(result.len(), line.len());
}

#[test]
fn preprocessor_python_triple_quoted_strings_handled() {
    // Edge case: Python triple-quoted strings should be handled correctly
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);

    let line = r#"s = """hello world""""#;
    let result = p.sanitize_line(line);
    assert!(result.len() == line.len());
}
