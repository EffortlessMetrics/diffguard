//! Red tests for work-ea7914be: Remove dead code from `safe_slice`
//!
//! These tests verify that `safe_slice` at `evaluate.rs:577` uses direct string
//! indexing `s[start..end]` instead of the unreachable `.get().unwrap_or("")` pattern.
//!
//! **Before fix**: Line 580 contains `s.get(start..end).unwrap_or("").to_string()`
//! **After fix**: Line 580 contains `s[start..end].to_string()`
//!
//! The `.get().unwrap_or("")` is dead code because lines 578-579 guarantee the
//! range is always valid after clamping:
//!   - `end = end.min(s.len())` → end <= s.len()
//!   - `start = start.min(end)` → start <= end
//!
//! Using direct indexing is the idiomatic Rust pattern for "I have already proven
//! this range is valid" — consistent with `byte_to_column` at line 587 which uses
//! `s[..byte_idx]` after its own guard.

/// Test that `safe_slice` uses direct string indexing instead of `.get().unwrap_or("")`.
///
/// This test verifies the source code structure of `safe_slice`. The function should
/// use `s[start..end].to_string()` (direct indexing) rather than
/// `s.get(start..end).unwrap_or("").to_string()` (unreachable fallback).
///
/// This test will FAIL before the fix (when the dead code is present) and
/// PASS after code-builder removes the unreachable `.get().unwrap_or("")` pattern.
#[test]
fn safe_slice_uses_direct_indexing_not_unwrap_or() {
    // Read the source file at compile time via include_str!
    let source = include_str!("../src/evaluate.rs");

    // Split into lines for inspection
    let lines: Vec<&str> = source.lines().collect();

    // Find the safe_slice function
    let fn_line_idx = lines
        .iter()
        .position(|l| l.contains("fn safe_slice(s: &str, start: usize, end: usize) -> String"))
        .expect("fn safe_slice not found in evaluate.rs");

    // The return statement should be on line fn_line_idx + 3 (after the two clamping lines)
    // Lines are:
    //   fn_line_idx + 0: fn safe_slice...
    //   fn_line_idx + 1: let end = end.min(s.len());
    //   fn_line_idx + 2: let start = start.min(end);
    //   fn_line_idx + 3: s.get(start..end).unwrap_or("").to_string()  OR  s[start..end].to_string()
    let return_line_idx = fn_line_idx + 3;
    let return_line = lines.get(return_line_idx)
        .expect("safe_slice return statement not found");

    // The return line should NOT contain `.get(` (the dead code pattern)
    // It SHOULD contain direct indexing: `s[start..end]`
    let has_dead_code_pattern = return_line.contains(".get(");
    let has_direct_indexing = return_line.contains("s[start..end]");

    // Assert: the dead code pattern should NOT be present
    assert!(
        !has_dead_code_pattern,
        "safe_slice still uses unreachable .get().unwrap_or(\"\") pattern at line {}.\n\
         Expected: s[start..end].to_string()\n\
         Found: {}",
        return_line_idx + 1, // 1-indexed for humans
        return_line
    );

    // Assert: direct indexing SHOULD be present
    assert!(
        has_direct_indexing,
        "safe_slice does not use direct indexing s[start..end] at line {}.\n\
         Expected: s[start..end].to_string()\n\
         Found: {}",
        return_line_idx + 1,
        return_line
    );
}

/// Test that `safe_slice` does NOT use `unwrap_or` in its return statement.
///
/// This test enforces the ADR decision that `unwrap_or("")` is dead code and
/// should be removed. The bounds clamping guarantees the range is always valid,
/// making `unwrap_or` unnecessary and misleading.
#[test]
fn safe_slice_no_unwrap_or_in_return() {
    let source = include_str!("../src/evaluate.rs");
    let lines: Vec<&str> = source.lines().collect();

    // Find safe_slice function
    let fn_line_idx = lines
        .iter()
        .position(|l| l.contains("fn safe_slice(s: &str, start: usize, end: usize) -> String"))
        .expect("fn safe_slice not found");

    // The return line is 3 lines after the function signature
    let return_line_idx = fn_line_idx + 3;
    let return_line = lines.get(return_line_idx)
        .expect("safe_slice return statement not found");

    // The return line should NOT contain "unwrap_or"
    assert!(
        !return_line.contains("unwrap_or"),
        "safe_slice still uses unreachable unwrap_or(\"\") at line {}.\n\
         The bounds clamping (lines {} and {}) guarantees the range is always valid.\n\
         Using unwrap_or is dead code that silently masks future regressions.\n\
         Expected: s[start..end].to_string()\n\
         Found: {}",
        return_line_idx + 1,
        fn_line_idx + 2, // line with "let end = ..."
        fn_line_idx + 3, // line with "let start = ..."
        return_line
    );
}

/// Test that `safe_slice` return line uses `.to_string()` appropriately.
///
/// After removing `.get().unwrap_or("")`, the return should be `s[start..end].to_string()`.
#[test]
fn safe_slice_return_is_direct_to_string() {
    let source = include_str!("../src/evaluate.rs");
    let lines: Vec<&str> = source.lines().collect();

    let fn_line_idx = lines
        .iter()
        .position(|l| l.contains("fn safe_slice(s: &str, start: usize, end: usize) -> String"))
        .expect("fn safe_slice not found");

    let return_line_idx = fn_line_idx + 3;
    let return_line = lines.get(return_line_idx)
        .expect("safe_slice return statement not found");

    // After the fix, the return should be: s[start..end].to_string()
    // Check for the pattern: s[start..end] followed by .to_string()
    let has_correct_pattern = return_line.contains("s[start..end].to_string()");

    assert!(
        has_correct_pattern,
        "safe_slice return statement does not match expected pattern.\n\
         Expected: s[start..end].to_string()\n\
         Found: {}",
        return_line
    );
}
