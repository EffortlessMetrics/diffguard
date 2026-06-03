//! Red tests for work-9dbac498: Refactor `sanitize_line` via Mode-Handler Extraction
//!
//! These tests verify that the mode-handler extraction was done correctly.
//! The handlers are private methods on `Preprocessor`, so these tests MUST be placed
//! inside the `#[cfg(test)] mod tests` section of `preprocess.rs`.
//!
//! These tests will FAIL to compile because the handler methods don't exist yet.
//! After the code-builder extracts the handlers, these tests should compile and pass.
//!
//! ## What the Tests Verify
//!
//! 1. Each mode handler method exists with the correct signature
//! 2. Each handler correctly transitions between modes
//! 3. The output is the same length as input (masked chars replaced with spaces)
//! 4. Multi-line state continuity works correctly
//!
//! ## Handler Method Signatures (as per spec)
//!
//! Each handler returns `usize` (updated index `i`) and takes:
//! - `&mut self`
//! - `bytes: &[u8]`
//! - `out: &mut Vec<u8>`
//! - `i: usize`
//! - `len: usize`
//!
//! Handlers that are under 30 lines should have `#[inline]` or `#[inline(always)]`.

use diffguard_domain::{Language, PreprocessOptions, Preprocessor};

/// Test that `handle_normal_mode` exists and handles Normal mode correctly.
///
/// The Normal mode handler should:
/// 1. Detect string starts (Rust raw, Python triple-quoted, JS template, etc.)
/// 2. Detect comment starts (Hash, PHP, SQL, XML, C-style)
/// 3. Return the updated index
///
/// This test will fail to compile until `handle_normal_mode` is implemented.
#[test]
fn test_handle_normal_mode_exists() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Rust);

    // Create test input
    let line = "fn main() { let x = 1; }";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = vec![b' '; len];

    // This will fail to compile until handle_normal_mode is implemented
    let _i = p.handle_normal_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_line_comment_mode` exists and handles LineComment mode correctly.
///
/// The LineComment handler should:
/// 1. Reset mode to Normal on any character (end of line comment)
/// 2. Return i + 1
///
/// This test will fail to compile until `handle_line_comment_mode` is implemented.
#[test]
fn test_handle_line_comment_mode_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    // Set up state: we're in LineComment mode
    let line = "this is all a comment";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = vec![b' '; len];

    // This will fail to compile until handle_line_comment_mode is implemented
    let _i = p.handle_line_comment_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_block_comment_mode` exists and handles nested block comments.
///
/// The BlockComment handler should:
/// 1. Mask characters inside block comment (if masking enabled)
/// 2. Track nesting depth for languages that support it (Rust)
/// 3. Return to Normal mode when closing `*/` is found
/// 4. Return updated index
///
/// This test will fail to compile until `handle_block_comment_mode` is implemented.
#[test]
fn test_handle_block_comment_mode_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    // Set up state: we're in BlockComment mode at depth 1
    let line = "this is still in comment */";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = vec![b' '; len];

    // This will fail to compile until handle_block_comment_mode is implemented
    let _i = p.handle_block_comment_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_normal_string_mode` exists and handles string escaping.
///
/// The NormalString handler should:
/// 1. Mask characters inside string (if masking enabled)
/// 2. Handle escape sequences (backslash sets escaped = true)
/// 3. Return to Normal mode when closing quote is found
/// 4. Return updated index
///
/// This test will fail to compile until `handle_normal_string_mode` is implemented.
#[test]
fn test_handle_normal_string_mode_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

    let line = "hello world";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = line.as_bytes().to_vec();

    // This will fail to compile until handle_normal_string_mode is implemented
    let _i = p.handle_normal_string_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_raw_string_mode` exists and handles Rust raw strings.
///
/// The RawString handler should:
/// 1. Mask characters inside raw string (if masking enabled)
/// 2. Look for closing delimiter: "### (where ### matches opening hashes)
/// 3. Return to Normal mode when closing delimiter is found
/// 4. Return updated index
///
/// This test will fail to compile until `handle_raw_string_mode` is implemented.
#[test]
fn test_handle_raw_string_mode_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

    let line = "hello world";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = line.as_bytes().to_vec();

    // This will fail to compile until handle_raw_string_mode is implemented
    let _i = p.handle_raw_string_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_char_mode` exists and handles C-style char literals.
///
/// The Char handler should:
/// 1. Mask characters inside char literal (if masking enabled)
/// 2. Handle escape sequences
/// 3. Return to Normal mode when closing single quote is found
/// 4. Return updated index
///
/// This test will fail to compile until `handle_char_mode` is implemented.
#[test]
fn test_handle_char_mode_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::C);

    let line = "'x'";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = line.as_bytes().to_vec();

    // This will fail to compile until handle_char_mode is implemented
    let _i = p.handle_char_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_template_literal_mode` exists and handles JS template literals.
///
/// The TemplateLiteral handler should:
/// 1. Mask characters inside template literal (if masking enabled)
/// 2. Handle escape sequences
/// 3. Return to Normal mode when closing backtick is found
/// 4. Return updated index
///
/// This test will fail to compile until `handle_template_literal_mode` is implemented.
#[test]
fn test_handle_template_literal_mode_exists() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::strings_only(), Language::JavaScript);

    let line = "`hello world`";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = line.as_bytes().to_vec();

    // This will fail to compile until handle_template_literal_mode is implemented
    let _i = p.handle_template_literal_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_triple_quoted_string_mode` exists and handles Python triple-quoted strings.
///
/// The TripleQuotedString handler should:
/// 1. Mask characters inside triple-quoted string (if masking enabled)
/// 2. Handle escape sequences
/// 3. Return to Normal mode when closing triple quote is found
/// 4. Return updated index
///
/// This test will fail to compile until `handle_triple_quoted_string_mode` is implemented.
#[test]
fn test_handle_triple_quoted_string_mode_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);

    let line = "\"\"\"hello world\"\"\""; // triple double-quoted string
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = line.as_bytes().to_vec();

    // This will fail to compile until handle_triple_quoted_string_mode is implemented
    let _i = p.handle_triple_quoted_string_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_shell_literal_string_mode` exists and handles Shell single-quoted strings.
///
/// The ShellLiteralString handler should:
/// 1. Mask characters inside single-quoted string (if masking enabled)
/// 2. NO escape handling (shell literal strings have no escapes)
/// 3. Return to Normal mode when closing single quote is found
/// 4. Return updated index
///
/// This test will fail to compile until `handle_shell_literal_string_mode` is implemented.
#[test]
fn test_handle_shell_literal_string_mode_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);

    let line = "'hello world'";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = line.as_bytes().to_vec();

    // This will fail to compile until handle_shell_literal_string_mode is implemented
    let _i = p.handle_shell_literal_string_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_shell_ansi_c_string_mode` exists and handles Shell ANSI-C strings.
///
/// The ShellAnsiCString handler should:
/// 1. Mask characters inside ANSI-C string (if masking enabled)
/// 2. Handle escape sequences (backslash)
/// 3. Return to Normal mode when closing single quote is found
/// 4. Return updated index
///
/// This test will fail to compile until `handle_shell_ansi_c_string_mode` is implemented.
#[test]
fn test_handle_shell_ansi_c_string_mode_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Shell);

    let line = "$'hello world'";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = line.as_bytes().to_vec();

    // This will fail to compile until handle_shell_ansi_c_string_mode is implemented
    let _i = p.handle_shell_ansi_c_string_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_xml_comment_mode` exists and handles XML/HTML comments.
///
/// The XmlComment handler should:
/// 1. Mask characters inside XML comment (if masking enabled)
/// 2. Return to Normal mode when closing `-->` is found
/// 3. Return updated index
///
/// This test will fail to compile until `handle_xml_comment_mode` is implemented.
#[test]
fn test_handle_xml_comment_mode_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Xml);

    let line = "<!-- hello world -->";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = line.as_bytes().to_vec();

    // This will fail to compile until handle_xml_comment_mode is implemented
    let _i = p.handle_xml_comment_mode(bytes, &mut out, 0, len);
}

/// Test that `handle_normal_string_starts` exists and detects string openings in Normal mode.
///
/// The Normal mode has two sub-handlers:
/// 1. `handle_normal_string_starts` - all string-start detection
/// 2. `handle_normal_comment_starts` - all comment-start detection
///
/// This test verifies string-start detection works correctly.
///
/// This test will fail to compile until `handle_normal_string_starts` is implemented.
#[test]
fn test_handle_normal_string_starts_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Rust);

    let line = "let s = r#hello#;";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = line.as_bytes().to_vec();

    // This will fail to compile until handle_normal_string_starts is implemented
    let _i = p.handle_normal_string_starts(bytes, &mut out, 0, len);
}

/// Test that `handle_normal_comment_starts` exists and detects comment openings in Normal mode.
///
/// The Normal mode has two sub-handlers:
/// 1. `handle_normal_string_starts` - all string-start detection
/// 2. `handle_normal_comment_starts` - all comment-start detection
///
/// This test verifies comment-start detection works correctly.
///
/// This test will fail to compile until `handle_normal_comment_starts` is implemented.
#[test]
fn test_handle_normal_comment_starts_exists() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Python);

    let line = "x = 1; this is a comment";
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut out = line.as_bytes().to_vec();

    // This will fail to compile until handle_normal_comment_starts is implemented
    let _i = p.handle_normal_comment_starts(bytes, &mut out, 0, len);
}

// ============================================================================
// Behavioral Tests - These verify the extracted handlers produce correct output
// ============================================================================

/// Test that output length is preserved (masked chars replaced with spaces).
///
/// This is a key invariant: sanitized string must be the same byte length as input.
#[test]
fn test_sanitize_line_preserves_output_length() {
    let mut p =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), Language::Rust);

    let line = "fn main() { let s = \"hello\"; }";
    let result = p.sanitize_line(line);

    assert_eq!(
        result.len(),
        line.len(),
        "sanitize_line output must have same length as the input"
    );
}

/// Test that multiline state continuity works for block comments.
#[test]
fn test_block_comment_multiline_state_continuity() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    // Line 1: starts block comment
    let line1 = "/* start of block";
    let result1 = p.sanitize_line(line1);
    assert!(result1.contains(' '), "block comment should be masked");
    assert!(matches!(
        p.mode,
        diffguard_domain::preprocess::Mode::BlockComment { .. }
    ));

    // Line 2: inside block comment
    let line2 = "middle of block";
    let result2 = p.sanitize_line(line2);
    assert!(
        result2.chars().all(|c| c == ' '),
        "block comment content should be all spaces"
    );
    assert!(matches!(
        p.mode,
        diffguard_domain::preprocess::Mode::BlockComment { .. }
    ));

    // Line 3: ends block comment
    let line3 = "end of block */";
    let result3 = p.sanitize_line(line3);
    assert!(matches!(p.mode, diffguard_domain::preprocess::Mode::Normal));
}

/// Test that multiline state continuity works for triple-quoted strings.
#[test]
fn test_triple_quoted_string_multiline_state_continuity() {
    let mut p = Preprocessor::with_language(PreprocessOptions::strings_only(), Language::Python);

    // Line 1: starts triple-quoted string
    let line1 = "\"\"\"start of string";
    let result1 = p.sanitize_line(line1);
    assert!(result1.contains(' '), "string should be masked");
    assert!(matches!(
        p.mode,
        diffguard_domain::preprocess::Mode::TripleQuotedString { .. }
    ));

    // Line 2: inside string
    let line2 = "middle of string";
    let result2 = p.sanitize_line(line2);
    assert!(
        result2.chars().all(|c| c == ' '),
        "string content should be all spaces"
    );
    assert!(matches!(
        p.mode,
        diffguard_domain::preprocess::Mode::TripleQuotedString { .. }
    ));

    // Line 3: ends string
    let line3 = "\"\"\"end\"\"\"";
    let result3 = p.sanitize_line(line3);
    assert!(matches!(p.mode, diffguard_domain::preprocess::Mode::Normal));
}

/// Test that LineComment mode resets to Normal at end of line.
#[test]
fn test_line_comment_resets_at_eol() {
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Python);

    // Line with hash comment
    let line = "x = 1; this is a comment";
    let _result = p.sanitize_line(line);

    // After processing, mode should be Normal (reset at EOL)
    assert!(matches!(p.mode, diffguard_domain::preprocess::Mode::Normal));

    // Next line should not be in comment mode
    let line2 = "y = 2; not a comment";
    let result2 = p.sanitize_line(line2);
    assert!(result2.contains("y = 2"));
}
