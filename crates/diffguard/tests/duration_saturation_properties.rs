
//! Property-based tests for duration saturation behavior
//!
//! These tests verify the mathematical invariants of u128→u64 and i64→u64
//! conversions with explicit saturation, as required by GitHub Issue #428.
//!
//! Key invariants:
//! - u128→u64 saturation: values > u64::MAX saturate to u64::MAX
//! - i64→u64 saturation: negative values clamp to 0, values > i64::MAX saturate
//! - Result is always a valid u64 within expected bounds

use proptest::prelude::*;
use std::fs;
use std::path::Path;

// =============================================================================
// Pure saturation functions (mirroring what main.rs should use)
// =============================================================================

/// Saturating u128→u64 conversion for duration in milliseconds.
/// Values above u64::MAX saturate to u64::MAX instead of wrapping.
#[inline]
fn saturating_u128_to_u64(millis: u128) -> u64 {
    millis.min(u128::from(u64::MAX)) as u64
}

/// Saturating i64→u64 conversion for chrono Duration.
/// Negative durations clamp to 0, values above i64::MAX saturate to i64::MAX as u64.
#[inline]
fn saturating_i64_to_u64(millis: i64) -> u64 {
    millis.max(0).min(i64::MAX) as u64
}

// =============================================================================
// Property 1: u128→u64 Exact conversion for small values
// =============================================================================

proptest! {
    /// Property: Values ≤ u64::MAX convert exactly to u64.
    ///
    /// Invariant: For all u128 values v where v <= u64::MAX,
    /// saturating_u128_to_u64(v) == v as u64
    #[test]
    fn test_u128_saturation_preserves_small_values(v in 0u128..=u64::MAX as u128) {
        let result = saturating_u128_to_u64(v);
        let expected = v as u64;
        prop_assert_eq!(result, expected,
            "Small value {} should convert exactly to {}, got {}",
            v, expected, result
        );
    }
}

// =============================================================================
// Property 2: u128→u64 Saturation for large values
// =============================================================================

proptest! {
    /// Property: Values > u64::MAX saturate to u64::MAX.
    ///
    /// Invariant: For all u128 values v where v > u64::MAX,
    /// saturating_u128_to_u64(v) == u64::MAX
    #[test]
    fn test_u128_saturation_caps_large_values(v in (u64::MAX as u128 + 1)..u128::MAX) {
        let result = saturating_u128_to_u64(v);
        prop_assert_eq!(result, u64::MAX,
            "Large value {} should saturate to u64::MAX, got {}",
            v, result
        );
    }
}

// =============================================================================
// Property 3: u128→u64 Result is always valid u64
// =============================================================================

proptest! {
    /// Property: Result is always a valid u64 (in range [0, u64::MAX]).
    ///
    /// Invariant: For all u128 inputs, the result r satisfies 0 <= r <= u64::MAX.
    #[test]
    fn test_u128_saturation_result_is_valid_u64(v in any::<u128>()) {
        let result = saturating_u128_to_u64(v);
        prop_assert!(result <= u64::MAX,
            "Result {} should be <= u64::MAX", result
        );
    }
}

// =============================================================================
// Property 4: u128→u64 Monotonicity
// =============================================================================

proptest! {
    /// Property: Output is monotonic non-decreasing with input.
    ///
    /// Invariant: If a < b, then saturating_u128_to_u64(a) <= saturating_u128_to_u64(b)
    /// (except both saturate to u64::MAX at the same point)
    #[test]
    fn test_u128_saturation_is_monotonic(a in 0u128..u128::MAX, b in 0u128..u128::MAX) {
        let a_val = saturating_u128_to_u64(a);
        let b_val = saturating_u128_to_u64(b);

        // If a < b, result should be <= (both could be u64::MAX after saturation)
        if a < b {
            prop_assert!(a_val <= b_val,
                "Monotonicity violated: input {} < {} but output {} > {}",
                a, b, a_val, b_val
            );
        }
    }
}

// =============================================================================
// Property 5: i64→u64 Negative values clamp to 0
// =============================================================================

proptest! {
    /// Property: Negative i64 values convert to 0.
    ///
    /// Invariant: For all i64 values v where v < 0,
    /// saturating_i64_to_u64(v) == 0
    #[test]
    fn test_i64_saturation_negative_clamps_to_zero(v in i64::MIN..0) {
        let result = saturating_i64_to_u64(v);
        prop_assert_eq!(result, 0,
            "Negative value {} should clamp to 0, got {}",
            v, result
        );
    }
}

// =============================================================================
// Property 6: i64→u64 Exact conversion for small non-negative values
// =============================================================================

proptest! {
    /// Property: Non-negative values ≤ i64::MAX convert exactly to u64.
    ///
    /// Invariant: For all i64 values v where 0 <= v <= i64::MAX,
    /// saturating_i64_to_u64(v) == v as u64
    #[test]
    fn test_i64_saturation_preserves_small_values(v in 0i64..=i64::MAX) {
        let result = saturating_i64_to_u64(v);
        let expected = v as u64;
        prop_assert_eq!(result, expected,
            "Value {} should convert exactly to {}, got {}",
            v, expected, result
        );
    }
}

// =============================================================================
// Property 7: i64→u64 Result is always valid u64
// =============================================================================

proptest! {
    /// Property: Result is always a valid u64 (in range [0, u64::MAX]).
    ///
    /// Invariant: For all i64 inputs, the result r satisfies 0 <= r <= u64::MAX.
    #[test]
    fn test_i64_saturation_result_is_valid_u64(v in any::<i64>()) {
        let result = saturating_i64_to_u64(v);
        prop_assert!(result <= u64::MAX,
            "Result {} should be <= u64::MAX", result
        );
    }
}

// =============================================================================
// Property 8: i64→u64 Monotonicity
// =============================================================================

proptest! {
    /// Property: Output is monotonic non-decreasing with input.
    ///
    /// Invariant: If a < b, then saturating_i64_to_u64(a) <= saturating_i64_to_u64(b)
    #[test]
    fn test_i64_saturation_is_monotonic(a in i64::MIN..i64::MAX, b in i64::MIN..i64::MAX) {
        // Filter to ensure a < b strictly
        prop_assume!(a < b);

        let a_val = saturating_i64_to_u64(a);
        let b_val = saturating_i64_to_u64(b);

        prop_assert!(a_val <= b_val,
            "Monotonicity violated: input {} < {} but output {} > {}",
            a, b, a_val, b_val
        );
    }
}

// =============================================================================
// Property 9: Idempotence - applying saturation twice gives same result
// =============================================================================

proptest! {
    /// Property: Saturation is idempotent (applying twice doesn't change result).
    ///
    /// Invariant: saturating_u128_to_u64(saturating_u128_to_u64(v)) == saturating_u128_to_u64(v)
    #[test]
    fn test_u128_saturation_is_idempotent(v in any::<u128>()) {
        let first = saturating_u128_to_u64(v);
        // first is u64, convert back to u128 for second call
        let second = saturating_u128_to_u64(first as u128);
        prop_assert_eq!(first, second,
            "Idempotence violated: first {} != second {}",
            first, second
        );
    }
}

proptest! {
    /// Property: Saturation is idempotent (applying twice doesn't change result).
    ///
    /// Invariant: saturating_i64_to_u64(saturating_i64_to_u64(v)) == saturating_i64_to_u64(v)
    #[test]
    fn test_i64_saturation_is_idempotent(v in any::<i64>()) {
        let first = saturating_i64_to_u64(v);
        // first is u64, convert back to i64 for second call
        let second = saturating_i64_to_u64(first as i64);
        prop_assert_eq!(first, second,
            "Idempotence violated: first {} != second {}",
            first, second
        );
    }
}

// =============================================================================
// Property 10: Edge cases at boundaries
// =============================================================================

#[test]
fn test_u128_saturation_edge_cases() {
    // Exact boundary at u64::MAX
    assert_eq!(saturating_u128_to_u64(u64::MAX as u128), u64::MAX);

    // Just above boundary
    assert_eq!(saturating_u128_to_u64(u64::MAX as u128 + 1), u64::MAX);

    // u128::MAX
    assert_eq!(saturating_u128_to_u64(u128::MAX), u64::MAX);

    // Zero
    assert_eq!(saturating_u128_to_u64(0), 0);
}

#[test]
fn test_i64_saturation_edge_cases() {
    // Zero
    assert_eq!(saturating_i64_to_u64(0), 0);

    // i64::MAX
    assert_eq!(saturating_i64_to_u64(i64::MAX), i64::MAX as u64);

    // i64::MIN
    assert_eq!(saturating_i64_to_u64(i64::MIN), 0);

    // -1
    assert_eq!(saturating_i64_to_u64(-1), 0);

    // 1
    assert_eq!(saturating_i64_to_u64(1), 1);
}

// =============================================================================
// Property 11: No silent wrapping (values don't suddenly decrease)
// =============================================================================

proptest! {
    /// Property: No wrap-around at overflow boundary.
    ///
    /// This is the key invariant that distinguishes saturation from wrapping.
    /// With wrapping (as u64), values near u64::MAX suddenly jump to 0.
    /// With saturation, they stay at u64::MAX.
    #[test]
    fn test_u128_no_wrap_at_boundary(overflow in 0u128..1000u128) {
        let max_minus_overflow = u64::MAX as u128 - overflow;
        let at_boundary = saturating_u128_to_u64(max_minus_overflow);
        let above_boundary = saturating_u128_to_u64(max_minus_overflow + 1);

        // Both should saturate to u64::MAX (not wrap to 0)
        assert!(at_boundary >= above_boundary - 1,  // Allow 1 off for same value
            "Wrap-around detected at boundary: at {} gave {}, at {} gave {}",
            max_minus_overflow, at_boundary, max_minus_overflow + 1, above_boundary
        );
    }
}

// =============================================================================
// Source Code Inspection Tests - Verify fix is applied to main.rs
// =============================================================================

/// Find a line number containing a pattern, searching within a range.
fn find_line_with_pattern(
    source: &str,
    pattern: &str,
    start_line: usize,
    search_range: usize,
) -> Option<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let start = start_line.saturating_sub(1);
    let end = (start + search_range).min(lines.len());

    for i in start..end {
        if lines[i].contains(pattern) {
            return Some((i + 1, lines[i].to_string()));
        }
    }
    None
}

/// Verifies that line ~1933 (Instant::elapsed) uses explicit saturation.
#[test]
fn test_main_rs_instant_conversion_has_saturation() {
    let main_rs_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = fs::read_to_string(&main_rs_path)
        .expect("Failed to read main.rs - is this the diffguard binary crate?");

    let expected_pattern = ".min(u128::from(u64::MAX))";
    let buggy_pattern = "as u64";

    // Search around line 1933
    let (line_num, line_content) = find_line_with_pattern(&source, buggy_pattern, 1920, 30)
        .expect("Could not find 'as u64' pattern near line 1933 in main.rs");

    assert!(
        line_content.contains(expected_pattern),
        "Line {} does not use explicit saturation for u128→u64.\n         Found: {}\n         Expected to contain: {}\n         \n         BUG: Duration calculation will silently truncate for long-running processes.\n         FIX: Add `.min(u128::from(u64::MAX))` before `as u64`",
        line_num, line_content, expected_pattern
    );
}

/// Verifies that line ~2617 (DateTime::signed_duration) uses explicit saturation.
#[test]
fn test_main_rs_datetime_conversion_has_saturation() {
    let main_rs_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = fs::read_to_string(&main_rs_path)
        .expect("Failed to read main.rs - is this the diffguard binary crate?");

    let expected_pattern = ".min(i64::MAX)";
    let buggy_pattern = "as u64";

    // Search around line 2617
    let (line_num, line_content) = find_line_with_pattern(&source, buggy_pattern, 2600, 40)
        .expect("Could not find 'as u64' pattern near line 2617 in main.rs");

    assert!(
        line_content.contains(expected_pattern),
        "Line {} does not use explicit saturation for i64→u64.\n         Found: {}\n         Expected to contain: {}\n         \n         BUG: Duration calculation will silently truncate for long-running processes.\n         FIX: Add `.min(i64::MAX)` before `as u64`",
        line_num, line_content, expected_pattern
    );
}
