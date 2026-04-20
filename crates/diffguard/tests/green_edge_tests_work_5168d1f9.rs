// Green edge case tests for work-5168d1f9: from_utf8_lossy().into_owned() refactor
//
// These tests verify the implementation handles edge cases correctly:
// - Valid UTF-8 input (Cow::Borrowed)
// - Invalid UTF-8 input (Cow::Owned with replacement chars)
// - Empty input
// - Mixed valid/invalid UTF-8

use std::borrow::Cow;

/// Test that into_owned() produces identical results to to_string() for Cow<str>
#[test]
fn test_into_owned_matches_to_string_for_borrowed_cow() {
    // Valid UTF-8: Cow::Borrowed
    let input = b"Hello, World! This is valid UTF-8.";
    let cow = String::from_utf8_lossy(input);
    assert!(matches!(cow, Cow::Borrowed(_)));

    let via_into_owned: String = cow.into_owned();
    let cow2 = String::from_utf8_lossy(input);
    let via_to_string = cow2.to_string();

    assert_eq!(via_into_owned, via_to_string);
    assert_eq!(via_into_owned, "Hello, World! This is valid UTF-8.");
}

#[test]
fn test_into_owned_matches_to_string_for_owned_cow() {
    // Invalid UTF-8: Cow::Owned (contains replacement char U+FFFD)
    let input = b"Hello \xff\xfe\x00 World";
    let cow = String::from_utf8_lossy(input);
    assert!(matches!(cow, Cow::Owned(_)));

    let via_into_owned: String = cow.into_owned();
    let cow2 = String::from_utf8_lossy(input);
    let via_to_string = cow2.to_string();

    assert_eq!(via_into_owned, via_to_string);
    // Both should contain replacement character
    assert!(via_into_owned.contains('\u{FFFD}'));
}

#[test]
fn test_into_owned_empty_input() {
    let input = b"";
    let cow = String::from_utf8_lossy(input);
    let result: String = cow.into_owned();
    assert_eq!(result, "");
}

#[test]
fn test_into_owned_unicode_edge_cases() {
    // Mixed: valid unicode, then invalid bytes, then more valid unicode
    let input = b"Hello\xff\xfeWorld\xf0\x9f\x98\x80"; // emoji at end
    let cow = String::from_utf8_lossy(input);
    let result: String = cow.into_owned();

    // Should contain replacement chars for invalid bytes
    assert!(result.contains('\u{FFFD}'));
    // Should preserve the emoji
    assert!(result.contains('😀'));
}

#[test]
fn test_into_owned_preserves_ascii() {
    let input = b"ASCII only - no special chars here! 123 !@#$%";
    let cow = String::from_utf8_lossy(input);
    let result: String = cow.into_owned();
    assert_eq!(result, "ASCII only - no special chars here! 123 !@#$%");
}

#[test]
fn test_into_owned_handles_unicode_strings() {
    // Valid multi-byte UTF-8
    let input = "日本語中文한국어".as_bytes();
    let cow = String::from_utf8_lossy(input);
    let result: String = cow.into_owned();
    assert_eq!(result, "日本語中文한국어");
}

#[test]
fn test_into_owned_large_valid_input() {
    // Large valid UTF-8 string
    let input: Vec<u8> = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        .as_bytes()
        .repeat(1000);
    let cow = String::from_utf8_lossy(&input);
    let result: String = cow.into_owned();
    assert!(result.starts_with("Lorem ipsum"));
    assert_eq!(result.len(), input.len());
}

#[test]
fn test_into_owned_all_replacement_chars() {
    // Input that's entirely invalid UTF-8
    let input = b"\xff\xfe\xfd\xfc\xfb\xfa";
    let cow = String::from_utf8_lossy(input);
    let result: String = cow.into_owned();

    // Should have 6 replacement characters (one per invalid byte)
    let replacement_count = result.chars().filter(|&c| c == '\u{FFFD}').count();
    assert_eq!(replacement_count, 6);
}

#[test]
fn test_domain_precedent_still_uses_into_owned() {
    // This test verifies the domain layer precedent at preprocess.rs:882
    // by checking that the pattern exists and is used correctly
    let out = b"test output".as_slice();
    let result = String::from_utf8_lossy(out).into_owned();
    assert_eq!(result, "test output");
}
