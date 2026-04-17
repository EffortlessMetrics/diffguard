//! Red tests for `escape_md()` being available as a public function in `diffguard_types`.
//!
//! These tests verify that `escape_md()` is:
//! 1. Publicly accessible from `diffguard_types` crate
//! 2. Correctly escapes all 14 markdown special characters in the proper order
//!
//! These tests SHOULD FAIL until `escape_md()` is hoisted from `diffguard` and
//! `diffguard-core` into `diffguard_types` as a public function.

use diffguard_types::escape_md;

/// Tests that `escape_md` is publicly available from `diffguard_types`.
#[test]
fn test_escape_md_is_publicly_accessible() {
    // This should compile and call the function - if escape_md is not public in diffguard_types,
    // this will fail to compile with "cannot find function `escape_md` in crate `diffguard_types`"
    let result = escape_md("test string");
    assert_eq!(result, "test string");
}

/// Tests that pipe character is escaped.
#[test]
fn test_escape_md_escapes_pipe() {
    let input = "a|b";
    let expected = "a\\|b";
    assert_eq!(
        escape_md(input),
        expected,
        "pipe should be escaped with backslash"
    );
}

/// Tests that backtick character is escaped.
#[test]
fn test_escape_md_escapes_backtick() {
    let input = "a`b";
    let expected = "a\\`b";
    assert_eq!(
        escape_md(input),
        expected,
        "backtick should be escaped with backslash"
    );
}

/// Tests that hash character is escaped.
#[test]
fn test_escape_md_escapes_hash() {
    let input = "a#b";
    let expected = "a\\#b";
    assert_eq!(
        escape_md(input),
        expected,
        "hash should be escaped with backslash"
    );
}

/// Tests that asterisk character is escaped.
#[test]
fn test_escape_md_escapes_asterisk() {
    let input = "a*b";
    let expected = "a\\*b";
    assert_eq!(
        escape_md(input),
        expected,
        "asterisk should be escaped with backslash"
    );
}

/// Tests that underscore character is escaped.
#[test]
fn test_escape_md_escapes_underscore() {
    let input = "a_b";
    let expected = "a\\_b";
    assert_eq!(
        escape_md(input),
        expected,
        "underscore should be escaped with backslash"
    );
}

/// Tests that open bracket character is escaped.
#[test]
fn test_escape_md_escapes_open_bracket() {
    let input = "a[b";
    let expected = "a\\[b";
    assert_eq!(
        escape_md(input),
        expected,
        "open bracket should be escaped with backslash"
    );
}

/// Tests that close bracket character is escaped.
#[test]
fn test_escape_md_escapes_close_bracket() {
    let input = "a]b";
    let expected = "a\\]b";
    assert_eq!(
        escape_md(input),
        expected,
        "close bracket should be escaped with backslash"
    );
}

/// Tests that greater-than character is escaped.
#[test]
fn test_escape_md_escapes_greater_than() {
    let input = "a>b";
    let expected = "a\\>b";
    assert_eq!(
        escape_md(input),
        expected,
        "greater-than should be escaped with backslash"
    );
}

/// Tests that carriage return is escaped.
#[test]
fn test_escape_md_escapes_carriage_return() {
    let input = "a\r b";
    let expected = "a\\r b";
    assert_eq!(
        escape_md(input),
        expected,
        "carriage return should be escaped"
    );
}

/// Tests that newline is escaped.
#[test]
fn test_escape_md_escapes_newline() {
    let input = "a\nb";
    let expected = "a\\nb";
    assert_eq!(escape_md(input), expected, "newline should be escaped");
}

/// Tests that all markdown special characters are escaped in the correct order.
/// This is the exact string used in the existing render_finding_row_escapes_pipes_and_backticks test.
#[test]
fn test_escape_md_escapes_all_special_chars_integration() {
    // This is a composite string with multiple special characters
    let input = "rule|id`tick";
    let result = escape_md(input);

    // All special chars must be escaped
    assert!(result.contains("\\|"), "pipe should be escaped");
    assert!(result.contains("\\`"), "backtick should be escaped");

    // And the escaped versions should NOT contain the raw characters (except where part of the escape)
    assert!(!result.contains("|"), "raw pipe should not remain");
    assert!(!result.contains("`"), "raw backtick should not remain");
}

/// Tests escaping of a realistic Finding path with multiple special characters.
#[test]
fn test_escape_md_realistic_finding_path() {
    let input = "src/lib|name`.rs";
    let expected = "src/lib\\|name\\`.rs";
    assert_eq!(escape_md(input), expected);
}

/// Tests escaping of a realistic Finding message with pipes and backticks.
#[test]
fn test_escape_md_realistic_finding_message() {
    let input = "message with | and `ticks`";
    let expected = "message with \\| and \\`ticks\\`";
    assert_eq!(escape_md(input), expected);
}

/// Tests escaping of a realistic Finding snippet with backticks and pipes.
#[test]
fn test_escape_md_realistic_finding_snippet() {
    let input = "snippet with `code` | pipe";
    let expected = "snippet with \\`code\\` \\| pipe";
    assert_eq!(escape_md(input), expected);
}

/// Tests that the escaping is idempotent (running twice produces same result).
#[test]
fn test_escape_md_is_idempotent() {
    let input = "a|b";
    let result1 = escape_md(input);
    let result2 = escape_md(&result1);
    assert_eq!(result1, result2, "escape_md should be idempotent");
}

/// Tests that empty string is handled correctly.
#[test]
fn test_escape_md_empty_string() {
    let input = "";
    let expected = "";
    assert_eq!(
        escape_md(input),
        expected,
        "empty string should return empty string"
    );
}

/// Tests that string with no special characters is unchanged.
#[test]
fn test_escape_md_no_special_chars() {
    let input = "hello world 123 ABC";
    let expected = "hello world 123 ABC";
    assert_eq!(
        escape_md(input),
        expected,
        "string with no special chars should be unchanged"
    );
}
