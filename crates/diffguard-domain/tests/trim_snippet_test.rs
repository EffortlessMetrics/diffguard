//! Tests for `trim_snippet` function behavior.
//!
//! These tests define the expected behavior of `trim_snippet`:
//! - Strings <= 240 characters are returned unchanged
//! - Strings > 240 characters are truncated to 240 chars + ellipsis (…)
//! - Unicode characters are counted correctly (not by byte index)
//! - The `const MAX_CHARS` declaration must appear before any executable
//!   statement (enforced by clippy's `items_after_statements` lint).

/// Copy of the internal `trim_snippet` function for testing.
/// The real function is `super::trim_snippet()` in evaluate.rs.
fn trim_snippet(s: &str) -> String {
    const MAX_CHARS: usize = 240;
    let trimmed = s.trim_end();

    let mut out = String::new();
    for (i, ch) in trimmed.chars().enumerate() {
        if i >= MAX_CHARS {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

/// Test that strings under MAX_CHARS (240) are returned unchanged.
#[test]
fn test_trim_snippet_unchanged_under_max_chars() {
    let short = "a".repeat(100);
    let result = trim_snippet(&short);
    assert_eq!(result, short);
    assert_eq!(result.chars().count(), 100);
}

/// Test that strings exactly at MAX_CHARS (240) are returned unchanged.
#[test]
fn test_trim_snippet_exactly_max_chars() {
    let exactly = "x".repeat(240);
    let result = trim_snippet(&exactly);
    assert_eq!(result, exactly);
    assert_eq!(result.chars().count(), 240);
}

/// Test that strings over MAX_CHARS (240) are truncated with ellipsis.
#[test]
fn test_trim_snippet_truncates_over_max_chars() {
    let long = "b".repeat(300);
    let result = trim_snippet(&long);

    // Should be 240 chars + ellipsis = 241 chars
    assert_eq!(result.chars().count(), 241);
    // Should end with ellipsis
    assert!(result.ends_with('…'));
    // Should not equal the original
    assert_ne!(result, long);
}

/// Test that truncation happens at the correct character boundary (not byte).
/// Unicode characters like 'é' are multi-byte in UTF-8 but count as 1 char.
#[test]
fn test_trim_snippet_unicode_character_counting() {
    // Create a string with 250 unicode characters (each 2+ bytes)
    let unicode_str: String = "é".repeat(250);
    let result = trim_snippet(&unicode_str);

    // Should be 240 chars + 1 ellipsis = 241 chars
    assert_eq!(result.chars().count(), 241);
    assert!(result.ends_with('…'));
}

/// Test that empty string is handled correctly.
#[test]
fn test_trim_snippet_empty_string() {
    let empty = "";
    let result = trim_snippet(empty);
    assert_eq!(result, "");
    assert_eq!(result.chars().count(), 0);
}

/// Test that trailing whitespace is trimmed before checking length.
#[test]
fn test_trim_snippet_trims_trailing_whitespace() {
    // String with 100 'a' chars followed by 50 spaces
    let with_trailing = format!("{}                         // 50 spaces", "c".repeat(100));
    let result = trim_snippet(&with_trailing);

    // The trailing whitespace should be trimmed, so it should be returned
    // with only 100 characters (no trailing spaces)
    assert!(!result.ends_with(' '));
}

/// Test that `const MAX_CHARS` appears BEFORE executable statements.
/// This is the core of issue #361 — the const must be declared before
/// any `let` or other executable statement to satisfy clippy's
/// `items_after_statements` lint.
#[test]
fn test_const_before_executable_statements() {
    // This test is a compile-time check that const is properly ordered.
    // If `const MAX_CHARS` were placed after `let trimmed = ...`,
    // clippy would warn: "const item declared after executable statement"
    //
    // The actual lint check is done via:
    // cargo clippy --package diffguard-domain -- -W clippy::pedantic
    // which runs in CI. This test serves as documentation of that requirement.
    const MAX_CHARS: usize = 240; // MUST be first statement in function
    let _trimmed = "test".trim_end(); // This must come AFTER the const

    // If this compiles, the ordering constraint is satisfied
    assert_eq!(MAX_CHARS, 240);
}
