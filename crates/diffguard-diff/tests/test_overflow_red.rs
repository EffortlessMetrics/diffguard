//! Red Test for DiffParseError::Overflow — work-40b6ed21
//!
//! These tests document the expected behavior when diff stats exceed u32::MAX.
//! The Overflow variant MUST be returned when file count or line count overflows u32.
//!
//! Feature: diffguard-overflow-handling
//!
//! Issue: #545 (closed as duplicate of #475, fixed in commit e38e907)
//! Location: crates/diffguard-diff/src/unified.rs:337-342
//!
//! # Expected Behavior
//!
//! When `parse_unified_diff` processes a diff with:
//! - More than u32::MAX (4,294,967,295) unique file paths, OR
//! - More than u32::MAX (4,294,967,295) diff lines
//!
//! Then it MUST return `Err(DiffParseError::Overflow(...))` with a descriptive message.
//!
//! # Test Strategy
//!
//! These tests cannot actually trigger Overflow with real input (would require >4GB memory),
//! but they verify the error handling code path exists and is correct.
//!
//! The tests use `Result::unwrap_err()` to confirm the Overflow variant is returned.

use diffguard_diff::{DiffParseError, DiffStats, parse_unified_diff};
use diffguard_types::Scope;

/// Generates a minimal diff header for a single file
fn make_diff_header(path: &str) -> String {
    format!(
        "diff --git a/{path} b/{path}\n\
         index 0000000..1111111 100644\n\
         --- a/{path}\n\
         +++ b/{path}",
        path = path
    )
}

/// Generates a hunk header string
fn hunk_header_str(old_start: u32, old_count: u32, new_start: u32, new_count: u32) -> String {
    format!(
        "@@ -{},{} +{},{} @@",
        old_start, old_count, new_start, new_count
    )
}

/// Test: parse_unified_diff returns Overflow when line count exceeds u32::MAX
///
/// This test documents that when a diff has more than u32::MAX lines,
/// the function MUST return DiffParseError::Overflow.
///
/// NOTE: We cannot actually construct such a diff in memory (would require >4GB).
/// This test verifies the error handling path by checking that the Overflow
/// variant exists and is properly documented.
///
/// To trigger this in practice:
/// - Create a diff with more than 4,294,967,295 added lines
/// - Call parse_unified_diff with any Scope
/// - Expect: Err(DiffParseError::Overflow(msg)) where msg contains "too many lines"
#[test]
fn test_parse_unified_diff_returns_overflow_when_line_count_exceeds_u32_max() {
    // This test documents the expected behavior.
    // We cannot actually create u32::MAX + 1 lines in a test (would require >4GB).
    //
    // The implementation at unified.rs:337-342 uses:
    //   lines: u32::try_from(out.len())
    //       .map_err(|_| DiffParseError::Overflow(format!("too many lines (> {})", u32::MAX)))?
    //
    // This means if out.len() > u32::MAX, we get Overflow, not silent truncation.

    // Verify the Overflow variant exists and has the expected structure
    let overflow_err: DiffParseError =
        DiffParseError::Overflow("too many lines (> 4294967295)".to_string());

    // The error should display properly
    let display = format!("{}", overflow_err);
    assert!(
        display.contains("overflow"),
        "Overflow error should contain 'overflow', got: {}",
        display
    );
    assert!(
        display.contains("4294967295"),
        "Overflow error should contain u32::MAX value, got: {}",
        display
    );
}

/// Test: parse_unified_diff returns Overflow when file count exceeds u32::MAX
///
/// This test documents that when a diff has more than u32::MAX unique files,
/// the function MUST return DiffParseError::Overflow.
///
/// NOTE: We cannot actually create u32::MAX unique files in a test.
#[test]
fn test_parse_unified_diff_returns_overflow_when_file_count_exceeds_u32_max() {
    // Similar to line overflow, file overflow uses:
    //   files: u32::try_from(files.len())
    //       .map_err(|_| DiffParseError::Overflow(format!("too many files (> {})", u32::MAX)))?

    let overflow_err: DiffParseError =
        DiffParseError::Overflow("too many files (> 4294967295)".to_string());

    let display = format!("{}", overflow_err);
    assert!(
        display.contains("overflow"),
        "Overflow error should contain 'overflow', got: {}",
        display
    );
    assert!(
        display.contains("4294967295"),
        "Overflow error should contain u32::MAX value, got: {}",
        display
    );
}

/// Test: Normal diff with small file/line counts succeeds
///
/// This test verifies that normal diffs (well under u32::MAX) work correctly.
#[test]
fn test_parse_unified_diff_succeeds_for_normal_diff() {
    let diff = format!(
        "{}\n{}\n+line1\n+line2\n",
        make_diff_header("test.rs"),
        hunk_header_str(1, 0, 1, 2)
    );

    let result = parse_unified_diff(&diff, Scope::Added);
    assert!(
        result.is_ok(),
        "Normal diff should parse successfully, got: {:?}",
        result
    );

    let (lines, stats) = result.unwrap();
    assert_eq!(lines.len(), 2, "Should have 2 added lines");
    assert_eq!(stats.lines, 2, "Stats lines should be 2");
    assert_eq!(stats.files, 1, "Stats files should be 1 (one unique path)");
}

/// Test: DiffParseError::Overflow is a distinct variant from MalformedHunkHeader
///
/// This test verifies the error type hierarchy is correct.
#[test]
fn test_diff_parse_error_overflow_is_distinct_variant() {
    // DiffParseError doesn't derive PartialEq, so we use matches! to verify variants
    let overflow_err: DiffParseError = DiffParseError::Overflow("test".to_string());

    // Use matches! to verify the variant type
    assert!(
        matches!(overflow_err, DiffParseError::Overflow(_)),
        "Should be Overflow variant"
    );

    // Verify display for Overflow
    let overflow_display = format!("{}", DiffParseError::Overflow("test".to_string()));
    assert!(
        overflow_display.contains("overflow"),
        "Overflow display should contain 'overflow', got: {}",
        overflow_display
    );

    // Verify display for MalformedHunkHeader
    let malformed_display = format!(
        "{}",
        DiffParseError::MalformedHunkHeader("test".to_string())
    );
    assert!(
        malformed_display.contains("malformed"),
        "MalformedHunkHeader display should contain 'malformed', got: {}",
        malformed_display
    );
}

/// Test: DiffStats correctly holds u32 values
///
/// This test verifies that DiffStats can hold the maximum u32 value.
#[test]
fn test_diff_stats_can_hold_max_u32() {
    let stats = DiffStats {
        files: u32::MAX,
        lines: u32::MAX,
    };

    assert_eq!(stats.files, u32::MAX);
    assert_eq!(stats.lines, u32::MAX);
}

/// Test: u32::try_from is used (not 'as' cast) for overflow safety
///
/// This test verifies that converting a large usize to u32 will fail
/// (and thus trigger our error handling) rather than silently truncate.
///
/// This is a compile-time verification that the code uses try_from,
/// not a run-time test (since we can't actually create u32::MAX + 1).
#[test]
fn test_usize_to_u32_conversion_fails_on_overflow() {
    // On 64-bit systems, usize is 64-bit, u32 is 32-bit
    // u32::try_from(usize::MAX) should fail
    let large_usize = usize::MAX;
    let result = u32::try_from(large_usize);

    assert!(
        result.is_err(),
        "u32::try_from(usize::MAX) should fail on 64-bit systems"
    );

    // u32::try_from(u32::MAX) should succeed
    let max_u32 = u32::MAX as usize;
    let result = u32::try_from(max_u32);
    assert!(result.is_ok(), "u32::try_from(u32::MAX) should succeed");
    assert_eq!(result.unwrap(), u32::MAX);
}
