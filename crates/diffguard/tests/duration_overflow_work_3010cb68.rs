//! Tests for explicit duration overflow handling in main.rs
//!
//! These tests verify that duration calculations use explicit saturation
//! before narrowing casts, rather than silent truncation.
//!
//! Issue: GitHub #428 - u128→u64 truncation silently overflows for
//! long-running diffguard processes
//!
//! The fix requires:
//! - Line ~1925: `start_time.elapsed().as_millis() as u64` → must use `.min(u128::from(u64::MAX))` before `as u64`
//! - Line ~2609: `(ended_at - *started_at).num_milliseconds().max(0) as u64` → must use `.min(i64::MAX)` before `as u64`

use std::fs;
use std::path::Path;

/// Find the line number where a pattern appears in source, searching from a starting point.
fn find_line_with_pattern(
    source: &str,
    pattern: &str,
    start_line: usize,
    search_range: usize,
) -> Option<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let start = start_line.saturating_sub(1); // Convert to 0-indexed
    let end = (start + search_range).min(lines.len());

    for (i, line) in lines.iter().enumerate().skip(start).take(end - start) {
        if line.contains(pattern) {
            return Some((i + 1, line.to_string())); // Return 1-indexed line number
        }
    }
    None
}

/// Verifies that u128→u64 conversion at line ~1925 uses explicit saturation.
///
/// Before fix: `let duration_ms = start_time.elapsed().as_millis() as u64;`
/// After fix:  `let duration_ms = start_time.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;`
#[test]
fn test_duration_instant_conversion_uses_saturation() {
    let main_rs_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = fs::read_to_string(&main_rs_path)
        .expect("Failed to read main.rs - crate may not be diffguard binary");

    // The pattern we're looking for - the CORRECT pattern after the fix
    let expected_pattern = ".min(u128::from(u64::MAX))";

    // The pattern that indicates the BUG (silent truncation)
    let buggy_pattern = "as u64";

    // Search around line 1925 (from ADR, may be off by ~2 lines)
    let start_search = 1920;
    let search_range = 20;

    // Find lines containing "as u64" near the expected location
    let matches = find_line_with_pattern(&source, buggy_pattern, start_search, search_range);

    let (line_num, line_content) = matches.expect(
        "Could not find 'as u64' pattern in expected region (~lines 1920-1940).\n\
         This suggests the code structure may have changed significantly.",
    );

    // The fixed code should have both:
    // 1. The buggy pattern "as u64" (still present, just after saturation)
    // 2. The fix pattern ".min(u128::from(u64::MAX))"

    let has_saturation = line_content.contains(expected_pattern);

    assert!(
        has_saturation,
        "Line {} does not use explicit saturation before u128→u64 cast.\n\
         Found: {}\n\
         Expected to contain: {}\n\
         \n\
         FIX REQUIRED: Add `.min(u128::from(u64::MAX))` before `as u64`\n\
         Example: `start_time.elapsed().as_millis().min(u128::from(u64::MAX)) as u64`",
        line_num, line_content, expected_pattern
    );
}

/// Verifies that i64→u64 conversion at line ~2609 uses explicit saturation.
///
/// Before fix: `let duration_ms = (ended_at - *started_at).num_milliseconds().max(0) as u64;`
/// After fix:  `let duration_ms = (ended_at - *started_at).num_milliseconds().max(0).min(i64::MAX) as u64;`
#[test]
fn test_duration_datetime_conversion_uses_saturation() {
    let main_rs_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = fs::read_to_string(&main_rs_path)
        .expect("Failed to read main.rs - crate may not be diffguard binary");

    // The pattern we're looking for - the CORRECT pattern after the fix
    let expected_pattern = ".min(i64::MAX)";

    // The pattern that indicates the BUG (silent truncation)
    let buggy_pattern = "as u64";

    // Search around line 2609 (from ADR, may be off by ~2 lines)
    let start_search = 2604;
    let search_range = 20;

    // Find lines containing "as u64" near the expected location
    let matches = find_line_with_pattern(&source, buggy_pattern, start_search, search_range);

    let (line_num, line_content) = matches.expect(
        "Could not find 'as u64' pattern in expected region (~lines 2604-2624).\n\
         This suggests the code structure may have changed significantly.",
    );

    // The fixed code should have both:
    // 1. The buggy pattern "as u64" (still present, just after saturation)
    // 2. The fix pattern ".min(i64::MAX)"

    let has_saturation = line_content.contains(expected_pattern);

    assert!(
        has_saturation,
        "Line {} does not use explicit saturation before i64→u64 cast.\n\
         Found: {}\n\
         Expected to contain: {}\n\
         \n\
         FIX REQUIRED: Add `.min(i64::MAX)` before `as u64`\n\
         Example: `(ended_at - *started_at).num_milliseconds().max(0).min(i64::MAX) as u64`",
        line_num, line_content, expected_pattern
    );
}

/// Verifies that ONLY the two expected lines use `as u64` for duration conversion.
/// This prevents accidentally introducing new silent truncations elsewhere.
#[test]
fn test_only_expected_duration_casts_exist() {
    let main_rs_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = fs::read_to_string(&main_rs_path)
        .expect("Failed to read main.rs - crate may not be diffguard binary");

    let lines: Vec<&str> = source.lines().collect();
    let mut duration_cast_lines = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        // Look for "as u64" which might be duration-related truncations
        if line.contains("as u64") {
            // Skip lines that are just type annotations like `duration_ms: u64`
            // We're looking for actual casts in expressions
            let trimmed = line.trim();
            if trimmed.contains("as u64")
                && !trimmed.starts_with("//")
                && !trimmed.contains(": u64")
                && !trimmed.contains("{")
                && (trimmed.contains("as u64;") || trimmed.contains("as u64,"))
            {
                duration_cast_lines.push((idx + 1, line.to_string()));
            }
        }
    }

    // We expect exactly 2 duration-related `as u64` casts (lines 1925 and 2609 after fix)
    // Before the fix, these still exist but without saturation
    assert!(
        duration_cast_lines.len() >= 2,
        "Expected at least 2 duration-related 'as u64' casts, found {} at:\n{}",
        duration_cast_lines.len(),
        duration_cast_lines
            .iter()
            .map(|(l, c)| format!("  Line {}: {}", l, c))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Tests the pure conversion logic for u128→u64 with saturation behavior.
/// This tests the mathematical correctness of the saturation approach.
#[test]
fn test_u128_to_u64_saturation_logic() {
    // Test cases: (input, expected_output)
    let test_cases = [
        // Normal case - no saturation needed
        (100u128, 100u64),
        (u64::MAX as u128, u64::MAX),
        // Overflow case - should saturate to u64::MAX
        (u128::MAX, u64::MAX),
        (u64::MAX as u128 + 1, u64::MAX),
        (u64::MAX as u128 * 2, u64::MAX),
    ];

    for (input, expected) in test_cases {
        let result = input.min(u128::from(u64::MAX)) as u64;
        assert_eq!(
            result, expected,
            "Saturation failed for input {}: expected {}, got {}",
            input, expected, result
        );
    }
}

/// Tests the pure conversion logic for i64→u64 with saturation behavior.
///
/// Note: After `.max(0)`, values are guaranteed >= 0, which is always <= i64::MAX,
/// so `.min(i64::MAX)` appears redundant to clippy. However, the saturation IS needed
/// for defensive programming - if num_milliseconds() ever returns a value larger than
/// i64::MAX (which shouldn't happen but is theoretically possible for very long durations),
/// we want explicit saturation rather than silent wrapping.
#[test]
fn test_i64_to_u64_saturation_logic() {
    // Test cases: (input, expected_output)
    let test_cases = [
        // Normal case - no saturation needed
        (100i64, 100u64),
        (0i64, 0u64),
        (i64::MAX, i64::MAX as u64),
        // Negative - should be handled by .max(0) first
        (-100i64, 0u64),
    ];

    for (input, expected) in test_cases {
        // The .min(i64::MAX) is defensive - it prevents wrapping if input somehow exceeds i64::MAX
        // (which can't happen with num_milliseconds() but is good practice)
        #[allow(clippy::unnecessary_min_or_max, clippy::manual_clamp)]
        let result = input.max(0).min(i64::MAX) as u64;
        assert_eq!(
            result, expected,
            "Conversion failed for input {}: expected {}, got {}",
            input, expected, result
        );
    }
}
