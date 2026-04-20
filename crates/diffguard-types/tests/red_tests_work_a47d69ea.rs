//! Red tests for work-a47d69ea: Fix clippy::doc_markdown warning in lib.rs:519
//!
//! GitHub issue #391 reports a `clippy::pedantic::doc_markdown` warning in
//! `crates/diffguard-types/src/lib.rs` at the `reason` field doc comment (line 519).
//! The doc comment uses bare identifiers `missing_base` and `tool_error` in quotes,
//! but clippy's `doc_markdown` lint requires backticks for code identifiers.
//!
//! **Before fix**: Line 519 reads:
//!     `/// Stable token reason (e.g., "missing_base", "tool_error").`
//!
//! **After fix**: Line 519 should read:
//!     `/// Stable token reason (e.g., `missing_base`, `tool_error`).`
//!
//! These tests will FAIL before the fix (when quotes are used) and
//! PASS after code-builder wraps the identifiers in backticks.

/// Test that the `reason` field doc comment uses backticks around `missing_base`.
///
/// Clippy's `doc_markdown` lint flags CamelCase or snake_case identifiers in doc
/// comments that aren't wrapped in backticks. The identifiers `missing_base` and
/// `tool_error` are stable token constants, so they should be wrapped in backticks.
///
/// This test will FAIL before the fix (when "missing_base" uses straight quotes)
/// and PASS after the fix (when `missing_base` uses backticks).
#[test]
fn reason_field_doc_comment_uses_backtick_for_missing_base() {
    let source = include_str!("../src/lib.rs");
    let lines: Vec<&str> = source.lines().collect();

    // Line 519 (1-indexed) is at index 518 (0-indexed)
    let line_519 = lines.get(518).expect("Line 519 should exist in lib.rs");

    // The fixed line should have `missing_base` with backticks, not "missing_base" with quotes
    // Check that the backtick version is present
    assert!(
        line_519.contains("`missing_base`"),
        "Line 519 doc comment should use backticks around `missing_base`.
         Expected: `/// Stable token reason (e.g., `missing_base`, `tool_error`).`
         Got:      `{}`

         The fix: Change \"missing_base\" to `missing_base` in the doc comment.",
        line_519.trim()
    );
}

/// Test that the `reason` field doc comment uses backticks around `tool_error`.
///
/// Same reasoning as above — `tool_error` is a stable token constant and should
/// be wrapped in backticks per clippy's `doc_markdown` lint.
///
/// This test will FAIL before the fix (when "tool_error" uses straight quotes)
/// and PASS after the fix (when `tool_error` uses backticks).
#[test]
fn reason_field_doc_comment_uses_backtick_for_tool_error() {
    let source = include_str!("../src/lib.rs");
    let lines: Vec<&str> = source.lines().collect();

    // Line 519 (1-indexed) is at index 518 (0-indexed)
    let line_519 = lines.get(518).expect("Line 519 should exist in lib.rs");

    // The fixed line should have `tool_error` with backticks, not "tool_error" with quotes
    assert!(
        line_519.contains("`tool_error`"),
        "Line 519 doc comment should use backticks around `tool_error`.
         Expected: `/// Stable token reason (e.g., `missing_base`, `tool_error`).`
         Got:      `{}`

         The fix: Change \"tool_error\" to `tool_error` in the doc comment.",
        line_519.trim()
    );
}

/// Test that the `reason` field doc comment does NOT use straight double-quotes.
///
/// Clippy's `doc_markdown` lint specifically flags identifiers in straight quotes
/// because it expects code references to be wrapped in backticks. The identifiers
/// `missing_base` and `tool_error` are stable token constants (REASON_MISSING_BASE,
/// REASON_TOOL_ERROR) defined in the same file.
///
/// This test will FAIL before the fix (when "missing_base", "tool_error" use quotes)
/// and PASS after the fix (when backticks are used instead).
#[test]
fn reason_field_doc_comment_no_straight_quotes() {
    let source = include_str!("../src/lib.rs");
    let lines: Vec<&str> = source.lines().collect();

    // Line 519 (1-indexed) is at index 518 (0-indexed)
    let line_519 = lines.get(518).expect("Line 519 should exist in lib.rs");

    // The unfixed line has "missing_base" and "tool_error" with straight double-quotes (ASCII 0x22)
    // After the fix, these should NOT be present (they should use backticks instead)
    assert!(
        !line_519.contains("\"missing_base\""),
        "Line 519 doc comment should NOT use straight double-quotes around missing_base.
         Found: `{}`
         Clippy's doc_markdown lint flags bare identifiers in quotes as likely code references.
         The fix: Change \"missing_base\" to `missing_base` (backticks).",
        line_519.trim()
    );

    assert!(
        !line_519.contains("\"tool_error\""),
        "Line 519 doc comment should NOT use straight double-quotes around tool_error.
         Found: `{}`
         Clippy's doc_markdown lint flags bare identifiers in quotes as likely code references.
         The fix: Change \"tool_error\" to `tool_error` (backticks).",
        line_519.trim()
    );
}
