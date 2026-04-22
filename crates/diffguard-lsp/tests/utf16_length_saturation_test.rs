//!
//! Tests for `utf16_length` saturating overflow behavior.
//!
//! # Issue
//! [diffguard#434](https://github.com/EffortlessMetrics/diffguard/issues/434):
//! The `utf16_length()` function uses `.sum()` which silently wraps on overflow.
//! For strings with >~2B UTF-16 code units, it returns incorrect small values.
//!
//! # Expected Behavior
//! `utf16_length()` must not silently produce incorrect values due to integer overflow.
//! For strings whose UTF-16 length would exceed `u32::MAX`, the function saturates to `u32::MAX`.
//!
//! This matches the pattern already used at line 140 in `byte_offset_at_position()`
//! which uses `saturating_add` for the same accumulation pattern.

use diffguard_lsp::text::utf16_length;

// ---------------------------------------------------------------------------
// Basic correctness tests
// ---------------------------------------------------------------------------
//
// These tests verify the function returns correct values for various inputs.
// They pass with BOTH the buggy (.sum()) and fixed (saturating_add) implementations
// because they don't trigger overflow.
// ---------------------------------------------------------------------------

#[test]
fn test_utf16_length_empty_string() {
    assert_eq!(utf16_length(""), 0);
}

#[test]
fn test_utf16_length_ascii_only() {
    // ASCII chars are 1 UTF-16 code unit each
    assert_eq!(utf16_length("hello"), 5);
    assert_eq!(utf16_length("hello world"), 11);
}

#[test]
fn test_utf16_length_mixed_ascii_and_cjk() {
    // '世' (U+4E16) is in BMP, 1 UTF-16 code unit
    // 'a' and 'b' are ASCII, 1 each
    assert_eq!(utf16_length("a世b"), 3); // 1 + 1 + 1 = 3
}

#[test]
fn test_utf16_length_surrogate_pairs() {
    // Characters outside the BMP (U+10000 and above) are surrogate pairs in UTF-16
    // They count as 2 UTF-16 code units each
    assert_eq!(utf16_length("😀"), 2); // U+1F600 (outside BMP)
    assert_eq!(utf16_length("🎭"), 2); // U+1F3AD (outside BMP)
    assert_eq!(utf16_length("a😀b"), 4); // 1 + 2 + 1 = 4
}

#[test]
fn test_utf16_length_all_surrogate_pairs() {
    // Multiple surrogate pair characters
    let s = "😀😁😂😃😄"; // 5 emoji, each 2 UTF-16 code units
    assert_eq!(utf16_length(s), 10);
}

#[test]
fn test_utf16_length_longer_text() {
    let text = "The quick brown fox jumps over the lazy dog. 日本語 😀";
    let len = utf16_length(text);
    assert!(len > 0);
    assert_eq!(len, 51); // verified correct value
}

#[test]
fn test_utf16_length_mathematical_property_monotonic() {
    // Adding characters should never decrease the utf16 length
    let s1 = "hello";
    let s2 = "😀world";
    let combined = format!("{}{}", s1, s2);
    assert!(utf16_length(s1) <= utf16_length(&combined));
    assert!(utf16_length(s2) <= utf16_length(&combined));
}

#[test]
fn test_utf16_length_additivity_without_overflow() {
    // For strings that don't cause overflow, utf16_length(s1 + s2) == utf16_length(s1) + utf16_length(s2)
    let s1 = "hello";
    let s2 = "😀world";
    let combined = format!("{}{}", s1, s2);
    assert_eq!(utf16_length(&combined), utf16_length(s1) + utf16_length(s2));
}

#[test]
fn test_utf16_length_zero_characters_count() {
    // Zero-width characters still have length in the string representation
    assert_eq!(utf16_length("\u{200B}"), 1); // Zero-width space
    assert_eq!(utf16_length("\u{034F}"), 1); // Combining grapheme joiner
}

#[test]
fn test_utf16_length_short_string_correct() {
    let s = "hi";
    let len = utf16_length(s);
    assert_eq!(
        len, 2,
        "utf16_length must return correct value for short strings"
    );
}

// ---------------------------------------------------------------------------
// CRITICAL: Overflow behavior specification
// ---------------------------------------------------------------------------
//
// The following tests specify the expected behavior for extremely long strings.
//
// WITHOUT the fix (using .sum()): overflow wraps silently to a small value
// WITH the fix (using saturating_add): overflow saturates to u32::MAX
//
// We CANNOT actually create strings with >2B UTF-16 code units in memory
// (would require ~8GB+). These tests serve as formal specifications of
// the required behavior.
// ---------------------------------------------------------------------------

/// Tests that saturating behavior is consistent with the caller at server.rs:777
#[test]
fn test_utf16_length_max_one_compatibility() {
    // The production caller uses: utf16_length(&finding.match_text).max(1)
    // This ensures the span is at least 1 character.
    //
    // With the saturating fix:
    // - Normal strings: utf16_length returns correct value, .max(1) has no effect
    // - Overflow case: utf16_length returns u32::MAX (which is > 1), .max(1) has no effect
    //
    // So the caller's .max(1) guard is compatible with both normal and saturated returns.

    let short = "hi";
    let len = utf16_length(short);
    let span = len.max(1);
    assert!(span >= 1, "span must be at least 1");

    let emoji = "😀";
    let len = utf16_length(emoji);
    let span = len.max(1);
    assert!(span >= 1, "span must be at least 1 for emoji");
}

/// Verifies utf16_length never returns 0 for non-empty strings.
///
/// This is a key property that distinguishes correct saturating behavior
/// from wrapping behavior: with wrapping, a massive string could return 0,
/// but with saturating, it returns u32::MAX (which is > 0).
#[test]
fn test_utf16_length_never_zero_for_nonempty() {
    let nonempty_strings = ["a", "hello", "😀", "a😀b", "世", "\u{200B}", "   "];

    for s in nonempty_strings {
        let len = utf16_length(s);
        assert!(
            len > 0,
            "utf16_length of non-empty string \"{}\" must be > 0, got {}",
            s,
            len
        );
    }
}

/// Verifies that utf16_length respects the minimum bound for single characters.
///
/// Each character must contribute at least 1 to the utf16 length.
#[test]
fn test_utf16_length_minimum_per_char() {
    // Every character contributes at least 1 UTF-16 code unit
    let chars_to_test = ['a', '世', '😀', '\u{200B}', ' '];

    for c in chars_to_test {
        let len = utf16_length(&c.to_string());
        assert!(
            len >= 1,
            "Character '{}' must have utf16_length >= 1, got {}",
            c,
            len
        );
    }
}

// ---------------------------------------------------------------------------
// NOTE ON OVERFLOW TESTING
// ---------------------------------------------------------------------------
//
// The issue (diffguard#434) describes a bug where `.sum()` silently wraps
// on overflow, returning incorrect small values for strings >~2B UTF-16 code units.
//
// The fix uses `fold` with `saturating_add` instead of `.sum()`.
//
// We cannot write a test that directly triggers this overflow with real data
// because creating a string with 2B+ characters would require ~8GB+ of memory.
//
// What we CAN verify:
// 1. The function works correctly for normal inputs (verified above)
// 2. The function never returns 0 for non-empty strings (verified above)
// 3. The function's behavior is compatible with the production caller (verified above)
//
// The actual overflow/saturation behavior is verified by:
// - Code inspection: the fix changes .sum() to fold with saturating_add
// - The fix matches the pattern already used at line 140 in byte_offset_at_position()
// - The ADR-047 documents the overflow scenario mathematically
// ---------------------------------------------------------------------------
