//! Integration tests for Preprocessor component handoffs
//!
//! These tests verify that Preprocessor integrates correctly with:
//! - PreprocessOptions factory methods
//! - Language-specific syntax handling
//! - Multi-line state persistence
//!
//! The #[must_use] attribute on factory/constructor methods is purely
//! a compile-time lint and does not affect runtime behavior. These tests
//! verify the runtime integration of the components.

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Test 1: PreprocessOptions factory methods create valid configurations
/// that can be used to construct Preprocessors.
#[test]
fn integration_preprocess_options_factory_creates_valid_preprocessor() {
    // All four factory methods should produce PreprocessOptions that
    // can be used to create a working Preprocessor.
    let options_cases = [
        PreprocessOptions::none(),
        PreprocessOptions::comments_only(),
        PreprocessOptions::strings_only(),
        PreprocessOptions::comments_and_strings(),
    ];

    for opts in options_cases {
        let mut preprocessor = Preprocessor::new(opts);
        // Should be able to call sanitize_line without panicking
        // Length should be preserved
        let input = "let x = 1;";
        let result = preprocessor.sanitize_line(input);
        assert_eq!(result.len(), input.len());
    }
}

/// Test 2: Preprocessor::with_language works with all factory methods
#[test]
fn integration_with_language_accepts_all_factory_methods() {
    let languages = [
        Language::Rust,
        Language::Python,
        Language::JavaScript,
        Language::Go,
        Language::Unknown,
    ];

    let options_cases = [
        PreprocessOptions::none(),
        PreprocessOptions::comments_only(),
        PreprocessOptions::strings_only(),
        PreprocessOptions::comments_and_strings(),
    ];

    for opts in options_cases {
        for lang in languages {
            let mut preprocessor = Preprocessor::with_language(opts, lang);
            let input = "let x = 1;";
            let result = preprocessor.sanitize_line(input);
            assert_eq!(result.len(), input.len());
        }
    }
}

/// Test 3: Preprocessor::new defaults to Language::Unknown
/// In Unknown language, # is NOT a comment marker (hash comments are Python/Ruby/Shell specific).
/// However, // IS treated as a comment in Unknown language because Unknown uses CStyle comment syntax.
#[test]
fn integration_preprocessor_new_defaults_unknown_language() {
    let mut preprocessor = Preprocessor::new(PreprocessOptions::comments_only());
    // In Unknown language, # is not a comment marker, so should be preserved
    let input1 = "# this is not a comment in Unknown language";
    let result1 = preprocessor.sanitize_line(input1);
    assert_eq!(
        result1, input1,
        "Hash should not be masked in Unknown language"
    );

    // However, // IS treated as a comment in Unknown language (CStyle syntax)
    let input2 = "// this IS a comment in Unknown language";
    let result2 = preprocessor.sanitize_line(input2);
    assert_ne!(
        result2, input2,
        "// should be masked in Unknown language with comments_only"
    );
}

/// Test 4: Preprocessor::with_language correctly applies Rust comment syntax
#[test]
fn integration_with_language_applies_rust_syntax() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);
    let input = "let x = 1; // comment here";
    let result = preprocessor.sanitize_line(input);
    // The // comment should be masked
    assert!(
        !result.contains("comment here"),
        "Comment should be masked in Rust mode"
    );
    // But the code before the comment should remain
    assert!(
        result.contains("let x = 1;"),
        "Code before comment should be preserved"
    );
}

/// Test 5: Preprocessor::with_language correctly handles Python hash comments
#[test]
fn integration_with_language_applies_python_syntax() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Python);
    let input = "x = 1  # comment here";
    let result = preprocessor.sanitize_line(input);
    // The # comment should be masked
    assert!(
        !result.contains("comment here"),
        "Hash comment should be masked in Python mode"
    );
    // But the code before the comment should remain
    assert!(
        result.contains("x = 1"),
        "Code before comment should be preserved"
    );
}

/// Test 6: Multiple Preprocessors can be created and used independently
#[test]
fn integration_multiple_preprocessors_independent() {
    let mut p1 = Preprocessor::with_language(PreprocessOptions::none(), Language::Rust);
    let mut p2 = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);
    let mut p3 = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);
    let mut p4 =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Rust);

    // Input with both string and comment
    let input = r#"let s = "hello"; // world"#;
    let input_len = input.len();

    // none() - nothing masked
    let r1 = p1.sanitize_line(input);
    assert_eq!(r1.len(), input_len, "none() should preserve length");
    assert!(
        r1.contains("hello") && r1.contains("world"),
        "none() should mask nothing"
    );

    // comments_only() - comment masked, string preserved
    let r2 = p2.sanitize_line(input);
    assert_eq!(
        r2.len(),
        input_len,
        "comments_only() should preserve length"
    );
    assert!(
        r2.contains("hello"),
        "comments_only() should preserve string"
    );
    assert!(!r2.contains("world"), "comments_only() should mask comment");

    // strings_only() - string masked, comment preserved
    let r3 = p3.sanitize_line(input);
    assert_eq!(r3.len(), input_len, "strings_only() should preserve length");
    assert!(
        r3.contains("world"),
        "strings_only() should preserve comment"
    );
    assert!(!r3.contains("hello"), "strings_only() should mask string");

    // comments_and_strings() - both masked
    let r4 = p4.sanitize_line(input);
    assert_eq!(
        r4.len(),
        input_len,
        "comments_and_strings() should preserve length"
    );
    assert!(
        !r4.contains("hello"),
        "comments_and_strings() should mask string"
    );
    assert!(
        !r4.contains("world"),
        "comments_and_strings() should mask comment"
    );
}

/// Test 7: Preprocessor state persists correctly across multiple sanitize_line calls
/// (important for multi-line comments/strings)
#[test]
fn integration_preprocessor_state_persists_across_lines() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    // Line 1: starts a block comment
    let r1 = preprocessor.sanitize_line("let x = 1; /* start");
    // The /* should be masked
    assert!(
        !r1.contains("start"),
        "Block comment start should be masked"
    );

    // Line 2: continues the block comment (state persists)
    let r2 = preprocessor.sanitize_line("let y = 2; middle");
    // Should still be in block comment mode
    assert!(
        !r2.contains("middle"),
        "Continued block comment should still be masked"
    );

    // Line 3: ends the block comment with */
    // After */ the block comment ends, so text after */ is NOT masked
    let r3 = preprocessor.sanitize_line("let z = 3; */ after");
    // The text after */ is visible (not in comment anymore)
    assert!(
        r3.contains("after"),
        "Text after */ should not be masked (block comment ended)"
    );
    // But code before */ should be masked
    assert!(
        !r3.contains("let z = 3;"),
        "Code before */ should be masked (still in block comment)"
    );

    // Line 4: after block ends, normal code is preserved
    let r4 = preprocessor.sanitize_line("let w = 4;");
    assert!(
        r4.contains("let w = 4;"),
        "Code after block comment should be preserved"
    );
}

/// Test 8: PreprocessOptions::comments_only and strings_only are distinct
#[test]
fn integration_comments_only_differs_from_strings_only() {
    let mut p_comments =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);
    let mut p_strings =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

    // Input: comment contains text, string also contains text
    let input = r#"let msg = "hello"; // world"#;

    let r_comments = p_comments.sanitize_line(input);
    let r_strings = p_strings.sanitize_line(input);

    // comments_only: masks // comment but not "string"
    assert!(
        r_comments.contains("hello"),
        "comments_only should preserve string"
    );
    assert!(
        !r_comments.contains("world"),
        "comments_only should mask comment"
    );

    // strings_only: masks "string" but not // comment
    assert!(
        !r_strings.contains("hello"),
        "strings_only should mask string"
    );
    assert!(
        r_strings.contains("world"),
        "strings_only should preserve comment"
    );
}

/// Test 9: Factory methods produce consistent results across multiple calls
#[test]
fn integration_factory_methods_produce_consistent_results() {
    // Calling the same factory method multiple times should produce
    // PreprocessOptions that behave identically
    let input = "let x = 1; // test";

    for _ in 0..10 {
        let opts1 = PreprocessOptions::comments_only();
        let opts2 = PreprocessOptions::comments_only();

        let mut p1 = Preprocessor::with_language(opts1, Language::Rust);
        let mut p2 = Preprocessor::with_language(opts2, Language::Rust);

        let r1 = p1.sanitize_line(input);
        let r2 = p2.sanitize_line(input);

        assert_eq!(
            r1, r2,
            "Same factory method should produce identical behavior"
        );
    }
}

/// Test 10: Raw strings (Rust) are correctly masked with strings_only
#[test]
fn integration_rust_raw_strings_masked() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

    // Raw strings like r#"..."# should be masked
    let input = r##"let path = r#"C:\Users\name"#;"##;
    let result = preprocessor.sanitize_line(input);

    // The raw string content should be masked (but length preserved)
    assert_eq!(result.len(), input.len(), "Length must be preserved");
    // The content should be masked (replaced with spaces)
    assert!(
        !result.contains("C:\\Users\\name"),
        "Raw string content should be masked"
    );
}

/// Test 11: Template literals (JavaScript) are correctly masked
#[test]
fn integration_js_template_literals_masked() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);

    let input = r#"let greeting = `Hello, ${name}!`;"#;
    let result = preprocessor.sanitize_line(input);

    // Template literal content should be masked
    assert_eq!(result.len(), input.len(), "Length must be preserved");
    assert!(
        !result.contains("Hello"),
        "Template literal should be masked"
    );
}

/// Test 12: Preprocessor reset clears state correctly
#[test]
fn integration_preprocessor_reset_clears_state() {
    let mut preprocessor =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    // Start a block comment
    preprocessor.sanitize_line("let x = 1; /* start");
    preprocessor.sanitize_line("let y = 2; middle");

    // Reset should clear the block comment state
    preprocessor.reset();

    // After reset, this line should NOT be in a block comment
    let result = preprocessor.sanitize_line("let z = 3;");
    assert!(
        result.contains("let z = 3;"),
        "After reset, code should not be in block comment"
    );
}

/// Test 13: All supported languages can be instantiated with all factory methods
#[test]
fn integration_all_languages_work_with_factory_methods() {
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

    let factory_methods = [
        ("none", PreprocessOptions::none()),
        ("comments_only", PreprocessOptions::comments_only()),
        ("strings_only", PreprocessOptions::strings_only()),
        (
            "comments_and_strings",
            PreprocessOptions::comments_and_strings(),
        ),
    ];

    for (factory_name, opts) in factory_methods {
        for lang in languages {
            let mut preprocessor = Preprocessor::with_language(opts, lang);
            let input = "let x = 1;";
            let result = preprocessor.sanitize_line(input);
            // Just verify it doesn't panic and produces output of same length
            assert_eq!(
                result.len(),
                input.len(),
                "Length preservation failed for {}/{:?}",
                factory_name,
                lang
            );
        }
    }
}

/// Test 14: Factory methods can be chained with Preprocessor::new and Preprocessor::with_language
#[test]
fn integration_factory_methods_chained_with_constructors() {
    // Test that factory methods work with both Preprocessor::new and Preprocessor::with_language

    // Preprocessor::new
    let p1 = Preprocessor::new(PreprocessOptions::none());
    let p2 = Preprocessor::new(PreprocessOptions::comments_only());
    let p3 = Preprocessor::new(PreprocessOptions::strings_only());
    let p4 = Preprocessor::new(PreprocessOptions::comments_and_strings());

    // All should be valid and usable
    let mut pp1 = p1;
    let mut pp2 = p2;
    let mut pp3 = p3;
    let mut pp4 = p4;

    pp1.sanitize_line("test");
    pp2.sanitize_line("test");
    pp3.sanitize_line("test");
    pp4.sanitize_line("test");

    // Preprocessor::with_language
    let p5 = Preprocessor::with_language(PreprocessOptions::none(), Language::Rust);
    let p6 = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);
    let p7 = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);
    let p8 = Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Rust);

    let mut pp5 = p5;
    let mut pp6 = p6;
    let mut pp7 = p7;
    let mut pp8 = p8;

    pp5.sanitize_line("test");
    pp6.sanitize_line("test");
    pp7.sanitize_line("test");
    pp8.sanitize_line("test");
}
