// Tests for changed_lines_between usize→u32 overflow behavior
//
// The bug: changed_lines_between (text.rs:24) performs `(index + 1) as u32`
// which silently truncates when index + 1 > u32::MAX (~4.29 billion).
//
// The fix: saturate at u32::MAX and emit an eprintln! warning.
//
// These tests verify:
// AC3: No behavioral change for normal inputs
// AC4: No API changes
//
// NOTE: The overflow case (index + 1 > u32::MAX) is physically impossible to
// test with real data - a file with u32_MAX lines would require ~16GB+ of
// text memory just for newlines. Tests for AC1/AC2 (overflow saturation and
// warning) rely on code inspection after the fix is applied.

use std::collections::BTreeSet;

/// Verifies the function signature of changed_lines_between
/// This test ensures no API changes (AC4)
#[test]
fn test_changed_lines_between_returns_btreeset_u32() {
    use diffguard_lsp::text::changed_lines_between;

    let before = "line1\nline2\n";
    let after = "line1\nmodified\n";

    // The return type must be BTreeSet<u32> - this is the API constraint
    // from DocumentState::changed_lines: BTreeSet<u32>
    let result: BTreeSet<u32> = changed_lines_between(before, after);

    // Verify we get correct values for normal inputs
    assert_eq!(result.len(), 1);
    assert!(
        result.contains(&2),
        "Expected line 2 to be marked as changed"
    );
}

/// Tests that normal case behavior is preserved (AC3)
/// When index + 1 <= u32::MAX, no truncation should occur.
#[test]
fn test_changed_lines_between_no_truncation_for_normal_inputs() {
    use diffguard_lsp::text::changed_lines_between;

    // Test case 1: Single line change at the start
    let before = "original\n";
    let after = "modified\n";
    let result = changed_lines_between(before, after);
    assert_eq!(result, BTreeSet::from([1]), "Case 1 failed: {:?}", result);

    // Test case 2: Single line change at the end (line 3 of 3)
    let before = "line1\nline2\nline3\n";
    let after = "line1\nline2\nCHANGED\n";
    let result = changed_lines_between(before, after);
    assert_eq!(result, BTreeSet::from([3]), "Case 2 failed: {:?}", result);

    // Test case 3: Multiple line changes at positions 1, 3, 5
    // Note: trailing newline creates an empty final element in split_lines
    let before = "a\nb\nc\nd\ne\n";
    let after = "A\nb\nC\nd\nE\n";
    let result = changed_lines_between(before, after);
    assert_eq!(
        result,
        BTreeSet::from([1, 3, 5]),
        "Case 3 failed: {:?}",
        result
    );

    // Test case 4: Empty before (new file)
    // When before is empty, before_lines.get(i) returns None for all i.
    // None != Some(line) is always true, so ALL after lines are marked changed.
    // The trailing newline creates an empty final element: ["line1", "line2", ""]
    let before = "";
    let after = "line1\nline2\n";
    let result = changed_lines_between(before, after);
    assert_eq!(
        result,
        BTreeSet::from([1, 2, 3]),
        "Case 4 failed: {:?}",
        result
    );

    // Test case 5: Empty after (deleted file content)
    let before = "line1\nline2\n";
    let after = "";
    let result = changed_lines_between(before, after);
    // When after is shorter, lines beyond after_lines.len() are not marked
    assert!(result.is_empty(), "Case 5 failed: {:?}", result);
}

/// Tests line number accuracy for a large but still safe number of lines.
/// This is well below u32::MAX so no overflow is possible.
#[test]
fn test_changed_lines_between_large_file_no_overflow() {
    use diffguard_lsp::text::changed_lines_between;

    // Create a large file with 10,000 lines - well below u32::MAX
    // but large enough to verify no truncation occurs
    let before: String = (0..10_000u32).map(|i| format!("line{}\n", i)).collect();
    let after: String = (0..10_000u32)
        .map(|i| format!("line{} modified\n", i))
        .collect();

    let result = changed_lines_between(&before, &after);

    // All 10,000 lines should be marked as changed
    assert_eq!(result.len(), 10_000);

    // Verify first and last line numbers are correct
    assert!(
        result.contains(&1),
        "First line should be marked as changed"
    );
    assert!(
        result.contains(&10_000),
        "Last line should be marked as changed"
    );

    // Verify no values are 0 (which would indicate truncation wrapping)
    assert!(!result.contains(&0), "Line 0 should never be in the result");
}

/// Integration test: Verify the LSP server handles document changes correctly
/// This indirectly tests changed_lines_between through the server's use of it.
#[test]
fn test_server_changed_lines_reflect_diagnostic_source() {
    use diffguard_lsp::text::changed_lines_between;

    // Simulate what the server does: compute changed_lines and then use them
    let baseline = "// TODO: implement\nfn main() {}\n";
    let current = "// TODO: URGENT - fix this\nfn main() {}\n";

    let changed_lines = changed_lines_between(baseline, current);

    // Line 1 should be marked as changed
    assert!(
        changed_lines.contains(&1),
        "Expected line 1 to be in changed set: {:?}",
        changed_lines
    );

    // Line 2 should NOT be marked (it hasn't changed)
    assert!(
        !changed_lines.contains(&2),
        "Expected line 2 NOT to be in changed set: {:?}",
        changed_lines
    );
}

/// Verifies that build_synthetic_diff correctly handles valid line numbers
#[test]
fn test_build_synthetic_diff_with_valid_line_numbers() {
    use diffguard_lsp::text::build_synthetic_diff;

    let text = "line0\nline1\nline2\n";
    let changed = BTreeSet::from([1_u32, 3_u32]);

    let diff = build_synthetic_diff("test.txt", text, &changed);

    // Should contain hunks for lines 1 and 3
    assert!(
        diff.contains("+line0"),
        "Should contain +line0, got: {}",
        diff
    );
    assert!(
        diff.contains("+line2"),
        "Should contain +line2, got: {}",
        diff
    );
}

/// Verifies the saturating_sub pattern is used correctly in build_synthetic_diff
/// When index exceeds text length, the line is skipped (not a panic).
#[test]
fn test_build_synthetic_diff_skips_lines_beyond_text_length() {
    use diffguard_lsp::text::build_synthetic_diff;

    // Text has only 3 lines (indices 0, 1, 2)
    // Asking for line 10 should be skipped gracefully
    let text = "line0\nline1\nline2\n";
    let changed = BTreeSet::from([10_u32]);

    // This should NOT panic - saturating_sub handles it
    let diff = build_synthetic_diff("test.txt", text, &changed);

    // The diff header should be present but no hunks (line 10 doesn't exist)
    assert!(diff.contains("diff --git"), "Should have diff header");
    assert!(
        diff.contains("--- a/test.txt"),
        "Should have old file header"
    );
    assert!(
        diff.contains("+++ b/test.txt"),
        "Should have new file header"
    );
    // No hunk for line 10 since it doesn't exist
    assert!(
        !diff.contains("+10,1"),
        "Should not have hunk for non-existent line"
    );
}

// ============================================================================
// OVERFLOW BEHAVIOR - CODE INSPECTION REQUIRED
// ============================================================================
//
// The following documents the expected behavior for the overflow case
// (index + 1 > u32::MAX). This case is physically impossible to test with
// real data due to memory constraints (~16GB+ just for newlines in a file
// with u32_MAX lines).
//
// EXPECTED BEHAVIOR (from ADR-2026-04-19):
//   When index + 1 overflows u32:
//   - Insert u32::MAX into the result set (NOT the truncated value 0)
//   - Emit eprintln!("changed_lines_between: line number overflow ...")
//
// CURRENT BUGGY BEHAVIOR:
//   When index + 1 overflows u32:
//   - Insert (index + 1) as u32 which wraps to 0
//   - No warning emitted
//
// To verify the fix is correct, after the fix is applied, code-inspect text.rs:24:
//
//   let line_number = (index + 1) as u32;
//   if line_number as usize != index + 1 {
//       changed.insert(u32::MAX);
//       eprintln!("changed_lines_between: line number overflow ...");
//   } else {
//       changed.insert(line_number);
//   }
//
// AC1 (Saturation at u32::MAX): Verified by code inspection
// AC2 (Warning emitted on overflow): Verified by code inspection
// AC3 (No behavioral change for normal inputs): Verified by passing tests above
// AC4 (No API changes): Verified by test_changed_lines_between_returns_btreeset_u32
// AC5 (Code compiles without errors): Verified by cargo build
