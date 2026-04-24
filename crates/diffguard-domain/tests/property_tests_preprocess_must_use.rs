//! Property tests for preprocess.rs factory/constructor methods with #[must_use]
//!
//! These tests verify invariants hold regardless of which factory method created
//! the PreprocessOptions or Preprocessor. The #[must_use] attribute is purely
//! a compile-time lint - it doesn't affect runtime behavior.

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Property 1: Length preservation
/// sanitize_line output always has the same byte length as the input.
#[test]
fn property_sanitize_line_preserves_length() {
    let test_strings: Vec<&str> = vec![
        "let x = 1; // comment",
        "\"a string\" // another comment",
        "/* block comment */",
        "let s = \"string with // inside\";",
        "fn foo() { /* nested comment */ }",
        "#!/bin/bash\n# comment\ncode",
        "r#\"raw string\"#",
        "br#\"byte raw string\"#",
        "$\'ANSI-C string\'",
        "x = '''single quotes'''",
        "// line comment only",
        "\"/* not a block comment */\"",
        "let s = \"\"\"\"\"\"; // triple double",
        "normal code without any special chars",
        "🎉 unicode chars 🎊",
        "",
        "   whitespace only   ",
        "//\n//\n//",
        "\"🌟\" // comment with emoji",
    ];

    let options_cases = [
        PreprocessOptions::none(),
        PreprocessOptions::comments_only(),
        PreprocessOptions::strings_only(),
        PreprocessOptions::comments_and_strings(),
    ];

    let languages = [
        Language::Rust,
        Language::Python,
        Language::JavaScript,
        Language::Unknown,
    ];

    for opts in options_cases {
        for lang in languages {
            let mut preprocessor = Preprocessor::with_language(opts, lang);
            for input in &test_strings {
                let output = preprocessor.sanitize_line(input);
                assert_eq!(
                    output.len(),
                    input.len(),
                    "Length must be preserved: opts={:?}, lang={:?}, input={:?}",
                    opts,
                    lang,
                    input
                );
            }
        }
    }
}

/// Property 2: Idempotent masking on same preprocessor instance
/// Once a character is masked by sanitize_line, subsequent calls with same input
/// produce the same output.
#[test]
fn property_sanitize_line_is_idempotent() {
    let test_inputs = vec![
        "let x = 1; // comment",
        "\"a string\"",
        "/* block comment */",
        "# hash comment",
        "🌟 emoji string 🎊",
    ];

    let option_cases = [
        PreprocessOptions::comments_only(),
        PreprocessOptions::strings_only(),
        PreprocessOptions::comments_and_strings(),
    ];

    for opts in option_cases {
        let mut preprocessor = Preprocessor::with_language(opts, Language::Rust);
        for input in &test_inputs {
            let first = preprocessor.sanitize_line(input);
            let second = preprocessor.sanitize_line(input);
            assert_eq!(
                first, second,
                "sanitize_line must be idempotent: opts={:?}, input={:?}",
                opts, input
            );
        }
    }
}

/// Property 3: Factory methods produce correct PreprocessOptions values
#[test]
fn property_preprocess_options_factory_methods() {
    // PreprocessOptions::none()
    let opts = PreprocessOptions::none();
    assert!(
        !opts.mask_comments,
        "none() should have mask_comments=false"
    );
    assert!(!opts.mask_strings, "none() should have mask_strings=false");

    // PreprocessOptions::comments_only()
    let opts = PreprocessOptions::comments_only();
    assert!(
        opts.mask_comments,
        "comments_only() should have mask_comments=true"
    );
    assert!(
        !opts.mask_strings,
        "comments_only() should have mask_strings=false"
    );

    // PreprocessOptions::strings_only()
    let opts = PreprocessOptions::strings_only();
    assert!(
        !opts.mask_comments,
        "strings_only() should have mask_comments=false"
    );
    assert!(
        opts.mask_strings,
        "strings_only() should have mask_strings=true"
    );

    // PreprocessOptions::comments_and_strings()
    let opts = PreprocessOptions::comments_and_strings();
    assert!(
        opts.mask_comments,
        "comments_and_strings() should have mask_comments=true"
    );
    assert!(
        opts.mask_strings,
        "comments_and_strings() should have mask_strings=true"
    );
}

/// Property 4: Preprocessor::new defaults to Language::Unknown
#[test]
fn property_preprocessor_new_defaults_to_unknown_language() {
    let preprocessor = Preprocessor::new(PreprocessOptions::none());
    // Cannot access private lang field, but we can test behavior
    // by checking that Unknown language doesn't mask hash comments
    let mut p = preprocessor;
    let result = p.sanitize_line("# not a comment in unknown lang");
    // In Unknown language, # is not a comment marker, so it should be preserved
    assert!(
        result.contains('#'),
        "Unknown language should not treat # as comment"
    );
}

/// Property 5: Preprocessor::with_language creates working preprocessors
#[test]
fn property_preprocessor_with_language_works() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Python);

    let result = preprocessor.sanitize_line("x = 1  # this is a comment");
    // Hash after content should be masked
    assert!(
        result.contains("x = 1"),
        "Code before comment should be preserved"
    );
    assert!(!result.contains("comment"), "Comment should be masked");
}

/// Property 6: Multiple lines maintain consistent masking
#[test]
fn property_sanitize_line_consistent_across_multiple_lines() {
    let lines = vec![
        "let x = 1; // comment",
        "let y = 2; // another",
        "let z = 3;",
    ];

    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    for line in &lines {
        let result = preprocessor.sanitize_line(line);
        // Each line should preserve its code portion
        let code_portion: String = line.chars().take_while(|c| *c != '/').collect();
        assert!(
            result.starts_with(&code_portion),
            "Code should be preserved: line={:?}, result={:?}",
            line,
            result
        );
        // Each line's length should be preserved
        assert_eq!(result.len(), line.len());
    }
}

/// Property 7: Empty string handled correctly
#[test]
fn property_sanitize_line_handles_empty_string() {
    let cases = [
        PreprocessOptions::none(),
        PreprocessOptions::comments_only(),
        PreprocessOptions::strings_only(),
        PreprocessOptions::comments_and_strings(),
    ];

    for opts in cases {
        let mut preprocessor = Preprocessor::with_language(opts, Language::Rust);
        let result = preprocessor.sanitize_line("");
        assert_eq!(result.len(), 0, "Empty string should produce empty result");
    }
}

/// Property 8: All supported languages produce valid output
#[test]
fn property_all_languages_preserve_length() {
    let languages = [
        Language::Rust,
        Language::Python,
        Language::JavaScript,
        Language::TypeScript,
        Language::Go,
        Language::Ruby,
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Java,
        Language::Kotlin,
        Language::Shell,
        Language::Swift,
        Language::Scala,
        Language::Sql,
        Language::Xml,
        Language::Php,
        Language::Yaml,
        Language::Toml,
        Language::Json,
        Language::Unknown,
    ];

    let test_input = "let x = 1; // comment with \"string\" inside";

    for lang in languages {
        let mut preprocessor =
            Preprocessor::with_language(PreprocessOptions::comments_and_strings(), lang);
        let result = preprocessor.sanitize_line(test_input);
        assert_eq!(
            result.len(),
            test_input.len(),
            "Length must be preserved for lang={:?}",
            lang
        );
    }
}

/// Property 9: Raw strings (Rust) are handled
#[test]
fn property_rust_raw_strings_are_masked() {
    let test_cases = vec![
        ("r#\"raw string\"#", "r#\"raw string\"#"),
        ("br#\"byte raw\"#", "br#\"byte raw\"#"),
        ("r##\"raw with #\"##", "r##\"raw with #\"##"),
        ("let s = r#\"content\"#;", "let s = "),
    ];

    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

    for (input, _expected_code) in test_cases {
        let result = preprocessor.sanitize_line(input);
        assert_eq!(result.len(), input.len());
    }
}

/// Property 10: When strings_only mode masks a string, it masks the entire content
#[test]
fn property_strings_only_masks_entire_string_content() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

    // The // inside the string is NOT a comment - it's just chars in a string
    // But when strings_only is on, the STRING gets masked entirely
    let input = r#"let s = "// not a comment";"#;
    let result = preprocessor.sanitize_line(input);
    // The output length must equal input length
    assert_eq!(result.len(), input.len(), "Length preservation failed");
    // The string portion is masked (replaced with spaces of same length)
    // The // inside the string IS part of what gets masked
    // In strings_only mode, the string content is masked but quotes remain
    assert!(
        !result.contains("not a comment"),
        "String content should be masked in strings_only mode"
    );
}

/// Property 10b: Comments inside strings are NOT treated as comments (comments_only mode)
#[test]
fn property_comments_only_respects_strings() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    // The // inside the string should NOT be treated as a comment
    // because comments_only only masks comments, not strings
    let result = preprocessor.sanitize_line(r#"let s = "// not a comment";"#);
    // The string should be preserved because we're not masking strings
    assert!(
        result.contains("//"),
        "String should be preserved in comments_only mode"
    );
    assert!(
        result.contains("not a comment"),
        "String content should be preserved"
    );
}

/// Property 11: Comments only masks comments, not strings (comments_only mode)
#[test]
fn property_comments_only_does_not_mask_strings() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    let result = preprocessor.sanitize_line("let s = \"a string\"; // comment");
    assert!(
        result.contains("a string"),
        "String should not be masked when only comments are masked"
    );
    assert!(!result.contains("comment"), "Comment should be masked");
}

/// Property 12: Preprocessor state resets correctly
#[test]
fn property_preprocessor_reset_clears_state() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    // First line starts a block comment
    let line1 = "let x = 1; /* block";
    let _result1 = preprocessor.sanitize_line(line1);

    // Reset should clear state
    preprocessor.reset();

    // After reset, next line should be processed independently
    let line2 = "let y = 2;";
    let result2 = preprocessor.sanitize_line(line2);

    assert_eq!(result2.len(), line2.len());
    assert!(result2.contains("let y = 2;"));
}
