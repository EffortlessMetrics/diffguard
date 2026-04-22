//! Snapshot tests for `sanitize_line` baseline behavior — work-9dbac498
//!
//! These tests capture the baseline output of `sanitize_line` BEFORE the mode-handler
//! extraction refactoring. They ensure that any output changes after refactoring are
//! immediately detected.
//!
//! ## Coverage
//!
//! - Single-line sanitize behavior for all supported languages
//! - Multi-line state continuity (block comments, triple-quoted strings, template literals)
//! - Edge cases: empty input, escaped characters, nested constructs

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Helper to create a preprocessor with given options and language
fn make_preprocessor(opts: PreprocessOptions, lang: Language) -> Preprocessor {
    Preprocessor::with_language(opts, lang)
}

// =============================================================================
// RUST LANGUAGE SNAPSHOTS
// =============================================================================

/// Rust: Line comment masking
#[test]
fn rust_line_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Rust);
    let input = "fn main() { let x = 1; // comment here }";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("rust_line_comment_comments_only", result);
}

/// Rust: Block comment masking (single line)
#[test]
fn rust_block_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Rust);
    let input = "fn main() { let x = /* block comment */ 1; }";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("rust_block_comment_comments_only", result);
}

/// Rust: Block comment multi-line continuity
#[test]
fn rust_block_comment_multiline_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Rust);

    let l1 = "fn main() { let x = /* start";
    let s1 = p.sanitize_line(l1);
    assert_eq!(s1.len(), l1.len());

    let l2 = "middle of comment";
    let s2 = p.sanitize_line(l2);
    assert_eq!(s2.len(), l2.len());

    let l3 = "end of comment */ let y = 2; }";
    let s3 = p.sanitize_line(l3);
    assert_eq!(s3.len(), l3.len());

    assert_snapshot!("rust_block_comment_multiline_comments_only_l1", s1);
    assert_snapshot!("rust_block_comment_multiline_comments_only_l2", s2);
    assert_snapshot!("rust_block_comment_multiline_comments_only_l3", s3);
}

/// Rust: Double-quoted string masking
#[test]
fn rust_string_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Rust);
    let input = "let s = \"hello world\";";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("rust_string_strings_only", result);
}

/// Rust: Raw string masking
#[test]
fn rust_raw_string_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Rust);
    // Use simple raw string without inner #
    let input = "let s = r\"raw string\";";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("rust_raw_string_strings_only", result);
}

/// Rust: Char literal masking
#[test]
fn rust_char_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Rust);
    let input = "let c = 'x';";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("rust_char_strings_only", result);
}

/// Rust: Combined comments and strings
#[test]
fn rust_comments_and_strings() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_and_strings(), Language::Rust);
    let input = "fn main() { let s = \"string\"; /* comment */ }";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("rust_comments_and_strings", result);
}

// =============================================================================
// PYTHON LANGUAGE SNAPSHOTS
// =============================================================================

/// Python: Hash line comment
#[test]
fn python_line_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Python);
    let input = "x = 1  # this is a comment";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("python_line_comment_comments_only", result);
}

/// Python: Triple-quoted string single line
#[test]
fn python_triple_quote_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Python);
    // Triple double-quoted string
    let input = "x = \"\"\"hello world\"\"\"";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("python_triple_quote_strings_only", result);
}

/// Python: Triple-quoted string multi-line continuity
#[test]
fn python_triple_quote_multiline_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Python);

    let l1 = "x = \"\"\"start";
    let s1 = p.sanitize_line(l1);
    assert_eq!(s1.len(), l1.len());

    let l2 = "middle of string";
    let s2 = p.sanitize_line(l2);
    assert_eq!(s2.len(), l2.len());

    let l3 = "end\"\"\"";
    let s3 = p.sanitize_line(l3);
    assert_eq!(s3.len(), l3.len());

    assert_snapshot!("python_triple_quote_multiline_strings_only_l1", s1);
    assert_snapshot!("python_triple_quote_multiline_strings_only_l2", s2);
    assert_snapshot!("python_triple_quote_multiline_strings_only_l3", s3);
}

/// Python: Single-quoted string
#[test]
fn python_single_quote_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Python);
    let input = "x = 'hello world'";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("python_single_quote_strings_only", result);
}

// =============================================================================
// JAVASCRIPT LANGUAGE SNAPSHOTS
// =============================================================================

/// JavaScript: Line comment (//)
#[test]
fn js_line_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::JavaScript);
    let input = "let x = 1; // this is a comment";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("js_line_comment_comments_only", result);
}

/// JavaScript: Block comment
#[test]
fn js_block_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::JavaScript);
    let input = "let x = /* block comment */ 1;";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("js_block_comment_comments_only", result);
}

/// JavaScript: Template literal
#[test]
fn js_template_literal_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::JavaScript);
    let input = "let s = `hello world`;";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("js_template_literal_strings_only", result);
}

/// JavaScript: Template literal multi-line
#[test]
fn js_template_literal_multiline_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::JavaScript);

    let l1 = "let s = `start";
    let s1 = p.sanitize_line(l1);
    assert_eq!(s1.len(), l1.len());

    let l2 = "middle of template";
    let s2 = p.sanitize_line(l2);
    assert_eq!(s2.len(), l2.len());

    let l3 = "end`;";
    let s3 = p.sanitize_line(l3);
    assert_eq!(s3.len(), l3.len());

    assert_snapshot!("js_template_literal_multiline_strings_only_l1", s1);
    assert_snapshot!("js_template_literal_multiline_strings_only_l2", s2);
    assert_snapshot!("js_template_literal_multiline_strings_only_l3", s3);
}

// =============================================================================
// GO LANGUAGE SNAPSHOTS
// =============================================================================

/// Go: Line comment
#[test]
fn go_line_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Go);
    let input = "x := 1 // this is a comment";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("go_line_comment_comments_only", result);
}

/// Go: Raw string (backtick)
#[test]
fn go_raw_string_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Go);
    let input = "x := `hello world`";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("go_raw_string_strings_only", result);
}

// =============================================================================
// SHELL LANGUAGE SNAPSHOTS
// =============================================================================

/// Shell: Hash comment
#[test]
fn shell_line_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Shell);
    let input = "x = 1  # this is a comment";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("shell_line_comment_comments_only", result);
}

/// Shell: Single-quoted literal string (no escapes)
#[test]
fn shell_literal_string_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Shell);
    let input = "echo 'hello world'";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("shell_literal_string_strings_only", result);
}

/// Shell: ANSI-C string with escapes
#[test]
fn shell_ansi_c_string_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Shell);
    let input = "echo $'hello\nworld'";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("shell_ansi_c_string_strings_only", result);
}

// =============================================================================
// C LANGUAGE SNAPSHOTS
// =============================================================================

/// C: Line comment
#[test]
fn c_line_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::C);
    let input = "int x = 1; // this is a comment";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("c_line_comment_comments_only", result);
}

/// C: Block comment
#[test]
fn c_block_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::C);
    let input = "int x = /* block comment */ 1;";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("c_block_comment_comments_only", result);
}

/// C: Char literal
#[test]
fn c_char_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::C);
    let input = "char c = 'x';";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("c_char_strings_only", result);
}

/// C: Double-quoted string
#[test]
fn c_string_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::C);
    let input = "printf(\"hello world\");";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("c_string_strings_only", result);
}

// =============================================================================
// SQL LANGUAGE SNAPSHOTS
// =============================================================================

/// SQL: Line comment (--)
#[test]
fn sql_line_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Sql);
    let input = "SELECT * FROM users -- this is a comment";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("sql_line_comment_comments_only", result);
}

/// SQL: Block comment (/* */)
#[test]
fn sql_block_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Sql);
    let input = "SELECT /* block comment */ * FROM users";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("sql_block_comment_comments_only", result);
}

/// SQL: Single-quoted string
#[test]
fn sql_string_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Sql);
    let input = "SELECT 'hello world' FROM users";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("sql_string_strings_only", result);
}

// =============================================================================
// XML LANGUAGE SNAPSHOTS
// =============================================================================

/// XML: Comment syntax (<!-- -->)
#[test]
fn xml_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Xml);
    let input = "<root><!-- this is a comment -->value</root>";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("xml_comment_comments_only", result);
}

/// XML: Comment multi-line
#[test]
fn xml_comment_multiline_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Xml);

    let l1 = "<root><!-- start";
    let s1 = p.sanitize_line(l1);
    assert_eq!(s1.len(), l1.len());

    let l2 = "middle of comment";
    let s2 = p.sanitize_line(l2);
    assert_eq!(s2.len(), l2.len());

    let l3 = "end -->value</root>";
    let s3 = p.sanitize_line(l3);
    assert_eq!(s3.len(), l3.len());

    assert_snapshot!("xml_comment_multiline_comments_only_l1", s1);
    assert_snapshot!("xml_comment_multiline_comments_only_l2", s2);
    assert_snapshot!("xml_comment_multiline_comments_only_l3", s3);
}

/// XML: Attribute strings (both " and ')
#[test]
fn xml_attribute_strings_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Xml);
    let input = "<item name=\"value\" id='123'></item>";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("xml_attribute_strings_strings_only", result);
}

// =============================================================================
// PHP LANGUAGE SNAPSHOTS
// =============================================================================

/// PHP: Line comments (//)
#[test]
fn php_line_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Php);
    let input = "$x = 1; // C-style comment";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("php_line_comment_cstyle_comments_only", result);
}

/// PHP: Hash comment
#[test]
fn php_hash_comment_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Php);
    let input = "$x = 1; # shell-style comment";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("php_hash_comment_comments_only", result);
}

/// PHP: Double-quoted string with escapes
#[test]
fn php_double_quote_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Php);
    let input = "$s = \"hello\nworld\";";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("php_double_quote_strings_only", result);
}

// =============================================================================
// EDGE CASES
// =============================================================================

/// Empty input
#[test]
fn empty_input_comments_and_strings() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_and_strings(), Language::Rust);
    let input = "";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("empty_input", result);
}

/// No comments or strings to mask
#[test]
fn no_masking_needed_comments_and_strings() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_and_strings(), Language::Rust);
    let input = "fn main() { let x = 1; }";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("no_masking_needed", result);
}

/// Masking disabled (options none)
#[test]
fn masking_disabled() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::none(), Language::Rust);
    let input = "fn main() { let x = 1; // comment }";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("masking_disabled", result);
}

/// Nested block comments (Rust)
#[test]
fn rust_nested_block_comments_comments_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::comments_only(), Language::Rust);

    let l1 = "let x = /* outer /* inner */ still_outer */ 1;";
    let result = p.sanitize_line(l1);
    assert_eq!(result.len(), l1.len());
    assert_snapshot!("rust_nested_block_comments_comments_only", result);
}

/// Escaped characters in strings
#[test]
fn escaped_characters_strings_only() {
    use insta::assert_snapshot;
    let mut p = make_preprocessor(PreprocessOptions::strings_only(), Language::Rust);
    let input = "let s = \"hello\\\"world\\\\test\\n\";";
    let result = p.sanitize_line(input);
    assert_eq!(result.len(), input.len());
    assert_snapshot!("escaped_characters_strings_only", result);
}
