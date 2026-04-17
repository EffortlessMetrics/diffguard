//! Tests for `sanitize_line()` handler extraction refactoring.
//!
//! This test module verifies that the handler extraction from `sanitize_line()`
//! maintains identical behavior while improving code structure.

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

// =============================================================================
// Handler: handle_line_comment (Mode::LineComment)
// =============================================================================

#[test]
fn test_handler_line_comment_masks_remaining_line() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);
    let result = p.sanitize_line("let x = 1; // this is a comment");
    assert!(result.contains("let x = 1;"));
    assert!(!result.contains("this is a comment"));
}

#[test]
fn test_handler_line_comment_resets_at_eol() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);
    let result1 = p.sanitize_line("let x = 1; // comment");
    assert!(!result1.contains("comment"));
    let result2 = p.sanitize_line("let y = 2;");
    assert!(result2.contains("let y = 2;"));
}

// =============================================================================
// Handler: handle_block_comment (Mode::BlockComment { depth })
// =============================================================================

#[test]
fn test_handler_block_comment_masks_content() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);
    let result = p.sanitize_line("let x = /* comment */ 1;");
    assert!(result.contains("let x ="));
    assert!(result.contains("1;"));
    assert!(!result.contains("comment"));
}

#[test]
fn test_handler_block_comment_multiline() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::JavaScript);
    let s1 = p.sanitize_line("let x = /* start");
    assert!(s1.contains("let x ="));
    assert!(!s1.contains("start"));
    let s2 = p.sanitize_line("middle of comment");
    assert!(!s2.contains("middle"));
    let s3 = p.sanitize_line("end of comment */ let y = 2;");
    assert!(!s3.contains("end of comment"));
    assert!(s3.contains("let y = 2;"));
}

// =============================================================================
// Handler: handle_normal_string (Mode::NormalString)
// =============================================================================

#[test]
fn test_handler_normal_string_masks_double_quoted() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);
    let result = p.sanitize_line(r#"let x = "hello world";"#);
    assert!(result.contains("let x ="));
    assert!(!result.contains("hello"));
}

#[test]
fn test_handler_normal_string_masks_single_quoted() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);
    let result = p.sanitize_line("let x = 'hello world';");
    assert!(result.contains("let x ="));
    assert!(!result.contains("hello"));
}

// =============================================================================
// Handler: handle_char (Mode::Char)
// =============================================================================

#[test]
fn test_handler_char_masks_content() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::C);
    let result = p.sanitize_line("char c = 'x';");
    assert!(result.contains("char c ="));
    assert!(!result.contains("x"));
}

// =============================================================================
// Handler: handle_raw_string (Mode::RawString)
// =============================================================================

#[test]
fn test_handler_raw_string_rust_simple() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);
    let result = p.sanitize_line("let s = r\"hello\";");
    assert!(result.contains("let s ="));
    assert!(!result.contains("hello"));
}

#[test]
fn test_handler_raw_string_rust_with_hash() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);
    let result = p.sanitize_line(r##"let s = r#"raw"#;"##);
    assert!(result.contains("let s ="));
    assert!(!result.contains("raw"));
}

// =============================================================================
// Handler: handle_shell_literal_string (Mode::ShellLiteralString)
// =============================================================================

#[test]
fn test_handler_shell_literal_string_masks() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);
    let result = p.sanitize_line("echo 'hello world'");
    assert!(result.contains("echo"));
    assert!(!result.contains("hello"));
}

// =============================================================================
// Handler: handle_xml_comment (Mode::XmlComment)
// =============================================================================

#[test]
fn test_handler_xml_comment_masks() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Xml);
    let result = p.sanitize_line("<div><!-- secret comment --></div>");
    assert!(result.contains("<div>"));
    assert!(result.contains("</div>"));
    assert!(!result.contains("secret"));
}

#[test]
fn test_handler_xml_comment_multiline() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Xml);
    let s1 = p.sanitize_line("<div><!-- start comment");
    assert!(s1.contains("<div>"));
    assert!(!s1.contains("start"));
    let s2 = p.sanitize_line("hidden content");
    assert!(!s2.contains("hidden"));
    let s3 = p.sanitize_line("end comment --></div>");
    assert!(!s3.contains("end comment"));
    assert!(s3.contains("</div>"));
}

// =============================================================================
// Integration tests
// =============================================================================

#[test]
fn test_handler_state_persistence() {
    let mut p = Preprocessor::with_language(
        PreprocessOptions::comments_and_strings(),
        Language::JavaScript,
    );
    let r1 = p.sanitize_line(r#"let x = "start"#);
    assert!(!r1.contains("start"));
    let r2 = p.sanitize_line("middle");
    assert!(!r2.contains("middle"));
    let r3 = p.sanitize_line(r#"end"; // comment"#);
    assert!(!r3.contains("end"));
    assert!(!r3.contains("comment"));
}

#[test]
fn test_all_handlers_preserve_line_length() {
    let opts = PreprocessOptions::comments_and_strings();
    let test_cases: Vec<(Language, &str)> = vec![
        (Language::JavaScript, "let x = 1; // comment"),
        (Language::JavaScript, "let x = /* comment */ 1;"),
        (Language::JavaScript, r#"let x = "string";"#),
        (Language::JavaScript, "let x = 'char';"),
        (Language::Xml, "<div><!-- comment --></div>"),
    ];
    for (lang, line) in test_cases {
        let mut p = Preprocessor::with_language(opts, lang);
        let result = p.sanitize_line(line);
        assert_eq!(result.len(), line.len());
    }
}

#[test]
fn test_all_handlers_exist_and_work_via_sanitize_line() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Unknown);
    // Line comment
    let r = p.sanitize_line("code // comment");
    assert!(r.contains("code"));
    assert!(!r.contains("comment"));
    // Block comment
    let r = p.sanitize_line("code /* comment */ more");
    assert!(r.contains("code"));
    assert!(!r.contains("comment"));
    assert!(r.contains("more"));
    // String
    let r = p.sanitize_line(r#""hello world""#);
    assert!(!r.contains("hello"));
}
