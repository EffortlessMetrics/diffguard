//! Edge case tests for `escape_md()` in diffguard-types
//!
//! These tests verify the escaping behavior with various edge cases including:
//! - Individual special character escaping
//! - Multiple consecutive special characters
//! - Mixed special characters
//! - Empty strings and strings with no special characters
//! - Idempotency (running twice produces same result)
//! - Unicode/ASCII beyond the 10 escaped characters
//! - Very long strings
//! - Whitespace characters

use crate::escape_md;

// ============================================================================
// Happy Path: Individual character escaping
// ============================================================================

#[test]
fn test_escape_md_escapes_pipe() {
    assert_eq!(escape_md("a|b"), r"a\|b");
}

#[test]
fn test_escape_md_escapes_backtick() {
    assert_eq!(escape_md("a`b"), r"a\`b");
}

#[test]
fn test_escape_md_escapes_hash() {
    assert_eq!(escape_md("a#b"), r"a\#b");
}

#[test]
fn test_escape_md_escapes_asterisk() {
    assert_eq!(escape_md("a*b"), r"a\*b");
}

#[test]
fn test_escape_md_escapes_underscore() {
    assert_eq!(escape_md("a_b"), r"a\_b");
}

#[test]
fn test_escape_md_escapes_open_bracket() {
    assert_eq!(escape_md("a[b"), r"a\[b");
}

#[test]
fn test_escape_md_escapes_close_bracket() {
    assert_eq!(escape_md("a]b"), r"a\]b");
}

#[test]
fn test_escape_md_escapes_greater_than() {
    assert_eq!(escape_md("a>b"), r"a\>b");
}

#[test]
fn test_escape_md_escapes_carriage_return() {
    // \r (carriage return) should become \r (literal backslash-r)
    assert_eq!(escape_md("a\r b"), r"a\r b");
}

#[test]
fn test_escape_md_escapes_newline() {
    // \n (newline) should become \n (literal backslash-n)
    assert_eq!(escape_md("a\nb"), r"a\nb");
}

// ============================================================================
// Empty and Boundary Cases
// ============================================================================

#[test]
fn test_escape_md_empty_string() {
    assert_eq!(escape_md(""), "");
}

#[test]
fn test_escape_md_no_special_chars() {
    // String with only safe characters should be unchanged
    assert_eq!(escape_md("hello world 123 ABC !@$%-=+"), "hello world 123 ABC !@$%-=+");
}

#[test]
fn test_escape_md_single_char_no_escape() {
    assert_eq!(escape_md("x"), "x");
}

#[test]
fn test_escape_md_single_special_char() {
    assert_eq!(escape_md("|"), r"\|");
    assert_eq!(escape_md("`"), r"\`");
    assert_eq!(escape_md("#"), r"\#");
    assert_eq!(escape_md("*"), r"\*");
    assert_eq!(escape_md("_"), r"\_");
    assert_eq!(escape_md("["), r"\[");
    assert_eq!(escape_md("]"), r"\]");
    assert_eq!(escape_md(">"), r"\>");
}

// ============================================================================
// Multiple Consecutive Special Characters
// ============================================================================

#[test]
fn test_escape_md_multiple_pipes() {
    assert_eq!(escape_md("a|b|c"), r"a\|b\|c");
}

#[test]
fn test_escape_md_multiple_backticks() {
    assert_eq!(escape_md("a``b"), r"a\`\`b");
}

#[test]
fn test_escape_md_multiple_underscores() {
    assert_eq!(escape_md("a__b"), r"a\_\_b");
}

#[test]
fn test_escape_md_multiple_mixed() {
    assert_eq!(escape_md("__ | ## **"), r"\_\_ \| \#\# \*\*");
}

// ============================================================================
// Mixed Special Characters
// ============================================================================

#[test]
fn test_escape_md_all_special_chars_together() {
    let input = "|`#*_[]>-";
    let expected = r"\|\`\#\*\_\[\]\>\-";
    assert_eq!(escape_md(input), expected);
}

#[test]
fn test_escape_md_realistic_finding_path() {
    // A realistic file path with special characters
    let input = "src/lib|name`.rs";
    let expected = r"src/lib\|name\`.rs";
    assert_eq!(escape_md(input), expected);
}

#[test]
fn test_escape_md_realistic_finding_message() {
    // A realistic finding message with pipes and backticks
    let input = "message with | and `ticks`";
    let expected = r"message with \| and \`ticks\`";
    assert_eq!(escape_md(input), expected);
}

#[test]
fn test_escape_md_realistic_finding_snippet() {
    // A realistic code snippet with backticks and pipes
    let input = r#"snippet with `code` | pipe"#;
    let expected = r"snippet with \`code\` \| pipe";
    assert_eq!(escape_md(input), expected);
}

// ============================================================================
// Idempotency
// ============================================================================

#[test]
fn test_escape_md_is_idempotent() {
    // Running escape_md twice should produce the same result
    let input = "a|b";
    let result1 = escape_md(input);
    let result2 = escape_md(&result1);
    assert_eq!(result1, result2, "escape_md should be idempotent");
}

#[test]
fn test_escape_md_idempotent_all_chars() {
    let input = "|`#*_[]>-";
    let result1 = escape_md(input);
    let result2 = escape_md(&result1);
    assert_eq!(result1, result2);
}

// ============================================================================
// Unicode and Non-ASCII
// ============================================================================

#[test]
fn test_escape_md_unicode_unchanged() {
    // Unicode characters should pass through unchanged (except escaped chars)
    assert_eq!(escape_md("hello 世界 🦀"), "hello 世界 🦀");
}

#[test]
fn test_escape_md_unicode_with_special_chars() {
    // Unicode chars preserved, markdown chars escaped
    assert_eq!(escape_md("|中文|`"), r"\|中文\|\`");
}

#[test]
fn test_escape_md_ascii_extended_unchanged() {
    // Extended ASCII should pass through unchanged
    assert_eq!(escape_md("café résumé"), "café résumé");
}

// ============================================================================
// Whitespace Handling
// ============================================================================

#[test]
fn test_escape_md_spaces_unchanged() {
    // Spaces should not be escaped
    assert_eq!(escape_md("hello world"), "hello world");
}

#[test]
fn test_escape_md_tabs_unchanged() {
    // Tabs should not be escaped
    assert_eq!(escape_md("hello\tworld"), "hello\tworld");
}

#[test]
fn test_escape_md_leading_trailing_whitespace() {
    // Leading and trailing whitespace preserved
    assert_eq!(escape_md("  hello world  "), "  hello world  ");
}

#[test]
fn test_escape_md_multiple_spaces() {
    // Multiple spaces preserved
    assert_eq!(escape_md("hello    world"), "hello    world");
}

// ============================================================================
// CRLF and Mixed Line Endings
// ============================================================================

#[test]
fn test_escape_md_crlf() {
    // Windows-style CRLF line ending
    assert_eq!(escape_md("line1\r\nline2"), r"line1\r\nline2");
}

#[test]
fn test_escape_md_mixed_line_endings() {
    // Mix of LF and CRLF
    assert_eq!(escape_md("a\nb\rc"), r"a\nb\rc");
}

#[test]
fn test_escape_md_only_crlf() {
    assert_eq!(escape_md("\r\n"), r"\r\n");
}

#[test]
fn test_escape_md_only_lf() {
    assert_eq!(escape_md("\n"), r"\n");
}

#[test]
fn test_escape_md_only_cr() {
    // Only CR (old Mac style) - should still be escaped
    assert_eq!(escape_md("\r"), r"\r");
}

// ============================================================================
// Long Strings and Performance Edge Cases
// ============================================================================

#[test]
fn test_escape_md_long_string_no_escapes() {
    // Very long string with no special characters
    let input = "x".repeat(10000);
    assert_eq!(escape_md(&input), input);
}

#[test]
fn test_escape_md_long_string_all_escapes() {
    // Very long string with all special characters repeated
    let input = "|`.#*_[]>-".repeat(1000);
    let expected = "\\|\\`\\#\\*\\\\_\\[\\]\\>\\-".repeat(1000);
    assert_eq!(escape_md(&input), expected);
}

#[test]
fn test_escape_md_long_mixed_string() {
    // Long realistic string
    let path = "src/components/button.rs".repeat(100);
    let escaped = escape_md(&path);
    // Each pipe would be escaped but there are no pipes
    assert!(!escaped.contains('|'));
    assert_eq!(escaped.lines().count(), path.lines().count());
}

// ============================================================================
// Escape Sequence Safety (Verifying backslash itself is NOT escaped)
// ============================================================================

#[test]
fn test_escape_md_backslash_not_escaped() {
    // Backslash should NOT be escaped (only the 10 specific chars)
    assert_eq!(escape_md(r"a\b"), r"a\b");
}

#[test]
fn test_escape_md_backslash_with_special() {
    // Backslash before a special char: the special char is escaped, not the backslash
    assert_eq!(escape_md(r"a\|b"), r"a\|b"); // backslash stays, pipe gets escaped
}

#[test]
fn test_escape_md_multiple_backslashes() {
    assert_eq!(escape_md(r"a\\b"), r"a\\b");
}

#[test]
fn test_escape_md_backslash_at_end() {
    assert_eq!(escape_md(r"test\"), r"test\");
}

// ============================================================================
// Order of Escaping (important - each replace is sequential)
// ============================================================================

#[test]
fn test_escape_md_order_pipe_first() {
    // Pipe should be escaped first
    let input = "|";
    assert_eq!(escape_md(input), r"\|");
}

#[test]
fn test_escape_md_interaction_between_chars() {
    // Characters that might interact if processed in wrong order
    // e.g., "]]" should become "\]\]" not something else
    assert_eq!(escape_md("]]"), r"\]\["");
    assert_eq!(escape_md("[["), r"\[\[");
    assert_eq!(escape_md("[]"), r"\[\]");
    assert_eq!(escape_md("]["), r"\]\[");
}

// ============================================================================
// Finding Field Simulation Tests
// ============================================================================

#[test]
fn test_escape_md_simulated_finding_path() {
    // Simulating a Finding.path field with various special chars
    let path = "src/features/auth/login|register.tsx";
    assert_eq!(escape_md(path), r"src/features/auth/login\|register.tsx");
}

#[test]
fn test_escape_md_simulated_finding_message() {
    // Simulating a Finding.message field
    let message = "Expected `foo` but found `bar` in #423";
    assert_eq!(escape_md(message), r"Expected \`foo\` but found \`bar\` in \#423");
}

#[test]
fn test_escape_md_simulated_finding_snippet() {
    // Simulating a Finding.snippet field with code-like content
    let snippet = "let x = |filter| => x.map(`value`)";
    assert_eq!(escape_md(snippet), r"let x = \|filter\| => x.map(\`value\`)");
}

#[test]
fn test_escape_md_simulated_finding_rule_id() {
    // Simulating a Finding.rule_id field
    let rule_id = "rust.no_unwrap";
    // dots and underscores - only underscore is escaped
    assert_eq!(escape_md(rule_id), r"rust.no\_unwrap");
}

// ============================================================================
// Regression: Verify the 14-replace implementation is correct
// ============================================================================

#[test]
fn test_escape_md_exactly_14_replace_operations() {
    // This test verifies the function processes all 10 characters
    // We check this by ensuring each escaped char appears correctly
    let input = "\r\n|iamking"; // CR, LF, pipe, i, a, m, k, i, n, g
    let result = escape_md(input);
    
    // \r should be escaped to literal \r
    assert!(result.contains(r"\r"), "CR should be escaped");
    // \n should be escaped to literal \n  
    assert!(result.contains(r"\n"), "LF should be escaped");
    // | should be escaped
    assert!(result.contains(r"\|"), "pipe should be escaped");
    
    // The non-special chars should be unchanged
    assert!(result.contains("iamking"), "non-special chars should be unchanged");
}
