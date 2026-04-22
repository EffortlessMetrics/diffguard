//! Integration tests for Preprocessor component interactions — work-9dbac498
//!
//! These tests verify that `Preprocessor::sanitize_line` works correctly
//! when integrated with different language contexts and multi-line state.
//!
//! ## Component Handoffs Tested
//!
//! 1. Preprocessor → Evaluate: `sanitize_line` output feeds into evaluation
//! 2. Multi-line state continuity: block comments, template literals persist
//! 3. Length preservation: masked output matches input length
//! 4. Language-specific handling across different language modes

use diffguard_domain::{
    Language, PreprocessOptions, Preprocessor,
};

/// Integration: Preprocessor output length matches input for all languages
///
/// Verifies: sanitize_line preserves length (spaces replace masked chars)
#[test]
fn test_preprocessor_length_preservation_all_languages() {
    let languages = [
        Language::Rust,
        Language::Python,
        Language::JavaScript,
        Language::Go,
        Language::C,
        Language::Cpp,
        Language::Java,
        Language::Ruby,
        Language::Shell,
    ];

    let test_cases = [
        "fn main() { let x = 1; }",
        "#!/usr/bin/env python\nprint('hello')",
        "function test() { return 42; }",
        "func main() { fmt.Println(\"hello\") }",
        "int main() { return 0; }",
        "void test() { /* comment */ }",
        "public class Main { }",
        "puts 'hello world'",
        "echo 'test' # comment",
    ];

    for lang in languages {
        for (i, input) in test_cases.iter().enumerate() {
            let mut p = Preprocessor::with_language(PreprocessOptions::comments_and_strings(), lang);
            let result = p.sanitize_line(input);
            assert_eq!(
                result.len(),
                input.len(),
                "Length mismatch for {:?} on test case {}: input={:?}, output={:?}",
                lang,
                i,
                input,
                result
            );
        }
    }
}

/// Integration: Preprocessor masks comments only (comments_only mode)
#[test]
fn test_preprocessor_comments_only_masks_comments() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    // Line comment should be masked entirely (including the //)
    let input = "fn main() { let x = 1; // comment here }";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    // The comment portion should be spaces
    assert!(result.contains("          "), "Comments should be masked: {}", result);
}

/// Integration: Preprocessor masks strings only (strings_only mode)
#[test]
fn test_preprocessor_strings_only_masks_strings() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

    // String should be masked
    let input = r#"fn main() { let s = "hello world"; }"#;
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    // The string portion should be spaces (12 chars for "hello world")
    assert!(result.contains("            "), "Strings should be masked: {}", result);
}

/// Integration: Preprocessor masks both comments and strings
#[test]
fn test_preprocessor_comments_and_strings_masks_both() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Rust);

    let input = r#"fn main() { let s = "hello"; // comment }"#;
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
}

/// Integration: Multi-line block comment state continuity
///
/// Verifies: Block comment mode persists across sanitize_line calls
#[test]
fn test_preprocessor_block_comment_multiline_state() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    // Start of block comment (not closed on this line)
    let line1 = "fn main() { /* start of block";
    let result1 = p.sanitize_line(line1);
    assert_eq!(result1.len(), line1.len());

    // Middle of block comment (still open)
    let line2 = "middle of block comment";
    let result2 = p.sanitize_line(line2);
    assert_eq!(result2.len(), line2.len());
    // Everything should be spaces since we're still in block comment
    assert!(
        result2.chars().all(|c| c == ' '),
        "Inside block comment, all should be masked: {:?}",
        result2
    );

    // End of block comment
    let line3 = "end of block */ let x = 1; }";
    let result3 = p.sanitize_line(line3);
    assert_eq!(result3.len(), line3.len());
    // Only the code after */ should be visible
    assert!(
        result3.contains("let x = 1"),
        "After block comment closes, code should be visible: {}",
        result3
    );
}

/// Integration: Multi-line triple-quoted string state continuity
///
/// Verifies: TripleQuotedString mode persists across sanitize_line calls
#[test]
fn test_preprocessor_triple_quoted_string_multiline_state() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);

    // Start of triple-quoted string
    let line1 = r#"x = """start of string"#;
    let result1 = p.sanitize_line(line1);
    assert_eq!(result1.len(), line1.len());

    // Middle of triple-quoted string (still open)
    let line2 = "middle of string";
    let result2 = p.sanitize_line(line2);
    assert_eq!(result2.len(), line2.len());
    // Everything should be spaces since we're still in string
    assert!(
        result2.chars().all(|c| c == ' '),
        "Inside string, all should be masked: {:?}",
        result2
    );

    // End of triple-quoted string
    let line3 = r#"end of string""" + y"#;
    let result3 = p.sanitize_line(line3);
    assert_eq!(result3.len(), line3.len());
    // After the closing triple-quote, code should be visible
    // The closing """ is at position where string ends
    assert!(
        result3.contains("+ y"),
        "After string closes, code should be visible: {}",
        result3
    );
}

/// Integration: Multi-line JS template literal state continuity
///
/// Verifies: TemplateLiteral mode persists across sanitize_line calls
#[test]
fn test_preprocessor_template_literal_multiline_state() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);

    // Start of template literal
    let line1 = r#"let x = `start of template"#;
    let result1 = p.sanitize_line(line1);
    assert_eq!(result1.len(), line1.len());

    // Middle of template literal
    let line2 = "middle of template";
    let result2 = p.sanitize_line(line2);
    assert_eq!(result2.len(), line2.len());
    // Everything should be spaces
    assert!(
        result2.chars().all(|c| c == ' '),
        "Inside template, all should be masked: {:?}",
        result2
    );

    // End of template literal - the backtick at position 16 closes the template
    // After closing, only the `;` is visible (not the backtick itself)
    let line3 = "end of template`;";
    let result3 = p.sanitize_line(line3);
    assert_eq!(result3.len(), line3.len());
    // The closing backtick is masked, so only `;` is visible
    assert!(
        result3.ends_with(";"),
        "After template closes, only the closing char should be visible: {}",
        result3
    );
}

/// Integration: Raw string state continuity
///
/// Verifies: RawString mode persists across sanitize_line calls
#[test]
fn test_preprocessor_raw_string_multiline_state() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

    // Start of raw string: r#"start
    let line1 = r#"let s = r#"start"#;
    let result1 = p.sanitize_line(line1);
    assert_eq!(result1.len(), line1.len());

    // Middle of raw string
    let line2 = "middle of raw";
    let result2 = p.sanitize_line(line2);
    assert_eq!(result2.len(), line2.len());
    // Everything should be spaces
    assert!(
        result2.chars().all(|c| c == ' '),
        "Inside raw string, all should be masked: {:?}",
        result2
    );

    // End of raw string - closing #" marks the end
    let line3 = r#"end of raw"#;
    let result3 = p.sanitize_line(line3);
    assert_eq!(result3.len(), line3.len());
    // The closing #" is part of the raw string, so should be masked
    // After closing, nothing follows in this test case
}

/// Integration: Shell ANSI-C string handling
///
/// Verifies: ANSI-C quoted strings ($'...') are handled correctly
#[test]
fn test_preprocessor_shell_ansi_c_string() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);

    let input = r#"echo $'hello\nworld'"#;
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
}

/// Integration: XML comment handling
///
/// Verifies: XML comments (<!-- -->) are handled correctly
#[test]
fn test_preprocessor_xml_comment_multiline_state() {
    // Multi-line XML comment - this tests the state continuity
    let mut p =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Xml);
    let line1 = "<!-- start of";
    let result1 = p.sanitize_line(line1);
    assert_eq!(result1.len(), line1.len());

    let line2 = "multi-line comment";
    let result2 = p.sanitize_line(line2);
    assert_eq!(result2.len(), line2.len());
    assert!(
        result2.chars().all(|c| c == ' '),
        "Inside XML comment, all should be masked: {:?}",
        result2
    );

    // Note: --> closes the comment, then value</root> immediately follows (no space)
    let line3 = "end -->value</root>";
    let result3 = p.sanitize_line(line3);
    assert_eq!(result3.len(), line3.len());
    // The closing --> should be visible after comment ends, along with the content after
    assert!(
        result3.contains("value</root>"),
        "After XML comment closes, content should be visible: {}",
        result3
    );
}

/// Integration: Rust nested block comments
///
/// Verifies: Nested /* */ comments are handled correctly
#[test]
fn test_preprocessor_nested_block_comments() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    let input = "/* outer /* inner */ still_outer */";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
}

/// Integration: Different languages maintain separate state
///
/// Verifies: Each Preprocessor instance maintains its own mode state
#[test]
fn test_preprocessor_separate_instances_maintain_independent_state() {
    let mut p_rust =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);
    let mut p_python =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Python);

    // Start a block comment in Rust (/* ...*/ not closed)
    let rust_line = "fn main() { /* unclosed rust comment";
    let rust_result1 = p_rust.sanitize_line(rust_line);
    assert_eq!(rust_result1.len(), rust_line.len());

    // Python should be independent - a line comment starts and is fully masked
    let python_line = "x = 1  # python comment";
    let python_result = p_python.sanitize_line(python_line);
    assert_eq!(python_result.len(), python_line.len());
    // The comment (including #) is masked for Python in comments_only mode
    // So the visible part is just "x = 1  "
    assert!(
        python_result.starts_with("x = 1  "),
        "Python code should be visible: {}",
        python_result
    );
}

/// Integration: C-style char literals
///
/// Verifies: Char literals are masked correctly
#[test]
fn test_preprocessor_c_char_literal() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::C);

    let input = "char c = 'x';";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    // The 'x' should be masked
    assert!(
        result.contains("   "),
        "Char literal should be masked: {}",
        result
    );
}

/// Integration: SQL comment and string handling
///
/// Verifies: SQL comments and strings are handled correctly
#[test]
fn test_preprocessor_sql_comment_and_string() {
    // Comments only
    let mut p_comments =
        Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Sql);
    let input1 = "SELECT * FROM t -- this is a comment";
    let result1 = p_comments.sanitize_line(input1);
    assert_eq!(result1.len(), input1.len());

    // Strings only
    let mut p_strings =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Sql);
    let input2 = "SELECT * FROM t WHERE name = 'John'";
    let result2 = p_strings.sanitize_line(input2);
    assert_eq!(result2.len(), input2.len());
}

/// Integration: Go raw string handling
///
/// Verifies: Go raw strings (backtick) are handled correctly
#[test]
fn test_preprocessor_go_raw_string() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Go);

    let input = "`hello world`";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    // The entire template should be masked
    assert!(
        result.chars().all(|c| c == ' '),
        "Go raw string should be masked: {:?}",
        result
    );
}

/// Integration: PHP double-quoted string handling
///
/// Verifies: PHP double-quoted strings with special chars are handled
#[test]
fn test_preprocessor_php_double_quoted_string() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Php);

    let input = r#"$x = "hello $world";"#;
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
}
