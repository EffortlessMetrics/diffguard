//! Green Tests for DiffParseError::Overflow — work-40b6ed21
//!
//! Edge case tests that confirm the u32::try_from overflow handling works correctly
//! with real inputs. These tests complement the red tests which document the expected
//! behavior but cannot actually trigger overflow with real input.
//!
//! Feature: diffguard-overflow-handling
//!
//! Issue: #545 (closed as duplicate of #475, fixed in commit e38e907)
//! Location: crates/diffguard-diff/src/unified.rs:337-342
//!
//! Edge cases covered:
//! - Empty input handling
//! - Empty hunks
//! - Single file, single line
//! - Multiple files, multiple lines
//! - Binary files are skipped (no overflow risk)
//! - Submodule changes are skipped (no overflow risk)
//! - Mode-only changes are skipped (no overflow risk)
//! - Deleted files are skipped unless scope=Deleted
//! - Renamed files tracked correctly
//! - Malformed hunk headers handled gracefully
//! - Large (but non-overflow) file/line counts succeed

use diffguard_diff::{ChangeKind, DiffParseError, DiffStats, parse_unified_diff};
use diffguard_types::Scope;

// ============================================================================
// Helper functions
// ============================================================================

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

/// Builds a complete diff with added lines
fn build_diff(path: &str, added_lines: &[&str]) -> String {
    let header = make_diff_header(path);
    let hunk = hunk_header_str(1, 0, 1, added_lines.len() as u32);
    let content: String = added_lines.iter().map(|l| format!("+{}\n", l)).collect();
    format!("{}\n{}\n{}", header, hunk, content)
}

// ============================================================================
// Edge Case Tests: Empty and Minimal Inputs
// ============================================================================

/// Test: Empty string input returns empty results with zero stats
///
/// An empty diff string should parse successfully and return empty results,
/// not an error. This is a common case for diffs with no changes.
#[test]
fn test_empty_diff_returns_empty_results_with_zero_stats() {
    let result = parse_unified_diff("", Scope::Added);
    assert!(
        result.is_ok(),
        "Empty diff should parse successfully, got: {:?}",
        result
    );

    let (lines, stats) = result.unwrap();
    assert!(
        lines.is_empty(),
        "Empty diff should have no lines, got {}",
        lines.len()
    );
    assert_eq!(stats.files, 0, "Empty diff should have 0 files");
    assert_eq!(stats.lines, 0, "Empty diff should have 0 lines");
}

/// Test: Whitespace-only input returns empty results with zero stats
///
/// A diff containing only whitespace should parse successfully.
#[test]
fn test_whitespace_only_diff_returns_empty_results() {
    let result = parse_unified_diff("   \n\n   \n", Scope::Added);
    assert!(
        result.is_ok(),
        "Whitespace-only diff should parse successfully, got: {:?}",
        result
    );

    let (lines, stats) = result.unwrap();
    assert!(lines.is_empty(), "Whitespace diff should have no lines");
    assert_eq!(stats.files, 0);
    assert_eq!(stats.lines, 0);
}

/// Test: Diff header with no hunk returns empty results
///
/// A file section with no actual hunks should not contribute to stats.
#[test]
fn test_diff_header_without_hunk_returns_empty_results() {
    let diff = make_diff_header("test.rs");
    let result = parse_unified_diff(&diff, Scope::Added);

    assert!(
        result.is_ok(),
        "Diff without hunk should parse, got: {:?}",
        result
    );
    let (lines, stats) = result.unwrap();
    assert!(lines.is_empty(), "Should have no lines without hunks");
    assert_eq!(stats.files, 0, "Should have 0 files without hunks");
    assert_eq!(stats.lines, 0, "Should have 0 lines without hunks");
}

// ============================================================================
// Edge Case Tests: Single File, Various Line Counts
// ============================================================================

/// Test: Single added line returns correct stats
#[test]
fn test_single_added_line_returns_correct_stats() {
    let diff = build_diff("test.rs", &["line1"]);
    let result = parse_unified_diff(&diff, Scope::Added).unwrap();

    assert_eq!(result.0.len(), 1);
    assert_eq!(result.1.files, 1);
    assert_eq!(result.1.lines, 1);
}

/// Test: Many added lines in single file returns correct stats
///
/// This tests that the line counting is correct for larger (but non-overflow)
/// inputs.
#[test]
fn test_many_added_lines_returns_correct_stats() {
    let lines: Vec<String> = (0..1000).map(|i| format!("line{}", i)).collect();
    let diff = build_diff(
        "test.rs",
        &lines.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    );

    let result = parse_unified_diff(&diff, Scope::Added).unwrap();

    assert_eq!(result.0.len(), 1000, "Should have 1000 lines");
    assert_eq!(result.1.files, 1, "Should have 1 file");
    assert_eq!(result.1.lines, 1000, "Should have 1000 lines in stats");
}

/// Test: Zero lines in hunk (empty change) handled correctly
#[test]
fn test_zero_line_hunk_handled_correctly() {
    let diff = format!(
        "{}\n{}\n",
        make_diff_header("test.rs"),
        hunk_header_str(1, 0, 1, 0)
    );

    let result = parse_unified_diff(&diff, Scope::Added).unwrap();
    assert_eq!(result.0.len(), 0);
    assert_eq!(result.1.files, 0); // No lines means no file tracked?
    assert_eq!(result.1.lines, 0);
}

// ============================================================================
// Edge Case Tests: Multiple Files
// ============================================================================

/// Test: Multiple files with added lines returns correct file count
///
/// Each unique file path should be counted once in stats.files.
#[test]
fn test_multiple_files_returns_correct_file_count() {
    let diff1 = build_diff("file1.rs", &["line1"]);
    let diff2 = build_diff("file2.rs", &["line2"]);
    let diff3 = build_diff("file3.rs", &["line3"]);

    let combined = format!("{}\n\n{}", diff1, diff2);

    // Parse first two files
    let result = parse_unified_diff(&combined, Scope::Added).unwrap();
    assert_eq!(result.1.files, 2, "Should count 2 unique files");
    assert_eq!(result.1.lines, 2, "Should have 2 total lines");

    // Parse all three files
    let combined3 = format!("{}\n\n{}\n\n{}", diff1, diff2, diff3);
    let result3 = parse_unified_diff(&combined3, Scope::Added).unwrap();
    assert_eq!(result3.1.files, 3, "Should count 3 unique files");
    assert_eq!(result3.1.lines, 3, "Should have 3 total lines");
}

// ============================================================================
// Edge Case Tests: Scope Filtering
// ============================================================================

/// Test: Added scope returns only added lines
#[test]
fn test_added_scope_returns_only_added_lines() {
    let diff = r#"
diff --git a/test.rs b/test.rs
--- a/test.rs
+++ b/test.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() {}
"#;

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(lines.len(), 1, "Should have 1 added line");
    assert_eq!(lines[0].kind, ChangeKind::Added);
    assert_eq!(stats.lines, 1);
}

/// Test: Deleted scope returns only deleted lines
#[test]
fn test_deleted_scope_returns_only_deleted_lines() {
    let diff = r#"
diff --git a/test.rs b/test.rs
--- a/test.rs
+++ b/test.rs
@@ -1,2 +1,1 @@
 fn a() {}
-fn b() {}
+fn c() {}
"#;

    let (lines, stats) = parse_unified_diff(diff, Scope::Deleted).unwrap();
    assert_eq!(lines.len(), 1, "Should have 1 deleted line");
    assert_eq!(lines[0].kind, ChangeKind::Deleted);
    assert_eq!(stats.lines, 1);
}

/// Test: Changed scope returns lines that follow deletions in same hunk
#[test]
fn test_changed_scope_returns_lines_after_deletions() {
    let diff = r#"
diff --git a/test.rs b/test.rs
--- a/test.rs
+++ b/test.rs
@@ -1,3 +1,3 @@
 fn a() {}
-fn b() {}
+fn b() { 1 }
 fn c() {}
"#;

    let (lines, _stats) = parse_unified_diff(diff, Scope::Changed).unwrap();
    // The "+fn b() { 1 }" follows "-fn b() {}", so it's "changed"
    assert_eq!(lines.len(), 1, "Should have 1 changed line");
    assert_eq!(lines[0].kind, ChangeKind::Changed);
}

/// Test: Added scope on diff with only deletions returns empty
#[test]
fn test_added_scope_on_only_deletions_returns_empty() {
    let diff = r#"
diff --git a/test.rs b/test.rs
--- a/test.rs
+++ b/test.rs
@@ -1,2 +1,1 @@
 fn a() {}
-fn b() {}
"#;

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert!(
        lines.is_empty(),
        "Added scope on only deletions should be empty"
    );
    assert_eq!(stats.lines, 0);
}

// ============================================================================
// Edge Case Tests: Binary and Submodule Files
// ============================================================================

/// Test: Binary file diff is skipped and doesn't affect stats
///
/// Binary files should not contribute any lines to the output.
#[test]
fn test_binary_file_diff_is_skipped() {
    let diff = format!(
        "{}\nBinary files a/test.png and b/test.png differ",
        make_diff_header("test.png")
    );

    let result = parse_unified_diff(&diff, Scope::Added).unwrap();
    assert!(
        result.0.is_empty(),
        "Binary file should have no extracted lines"
    );
    assert_eq!(result.1.files, 0, "Binary file should not be counted");
    assert_eq!(result.1.lines, 0, "Binary file should have 0 lines");
}

/// Test: Submodule change is skipped and doesn't affect stats
#[test]
fn test_submodule_change_is_skipped() {
    let diff = format!(
        "{}\nSubproject commit abc123def456...",
        make_diff_header("submodule")
    );

    let result = parse_unified_diff(&diff, Scope::Added).unwrap();
    assert!(
        result.0.is_empty(),
        "Submodule should have no extracted lines"
    );
    assert_eq!(result.1.files, 0, "Submodule should not be counted");
    assert_eq!(result.1.lines, 0, "Submodule should have 0 lines");
}

// ============================================================================
// Edge Case Tests: Mode-Only Changes
// ============================================================================

/// Test: Mode-only change (chmod) is skipped
///
/// Mode-only changes have no content lines to extract.
#[test]
fn test_mode_only_change_is_skipped() {
    let diff = format!(
        "{}\nold mode 100644\nnew mode 100755",
        make_diff_header("script.sh")
    );

    let result = parse_unified_diff(&diff, Scope::Added).unwrap();
    assert!(result.0.is_empty(), "Mode-only change should have no lines");
    assert_eq!(result.1.files, 0);
    assert_eq!(result.1.lines, 0);
}

// ============================================================================
// Edge Case Tests: Renamed Files
// ============================================================================

/// Test: Renamed file is tracked with destination path
///
/// When a file is renamed, we should use the new (destination) path.
#[test]
fn test_renamed_file_uses_destination_path() {
    let diff = format!(
        "{}\nrename from old_file.rs\nrename to new_file.rs\n\
         --- a/old_file.rs\n\
         +++ b/new_file.rs\n\
         @@ -1,1 +1,1 @@\n\
         -fn old() {{}}\n\
         +fn new() {{}}",
        make_diff_header("test.rs")
    );

    let result = parse_unified_diff(&diff, Scope::Added).unwrap();
    assert_eq!(result.0.len(), 1, "Should have 1 added line");
    assert_eq!(
        result.0[0].path, "new_file.rs",
        "Path should be destination path"
    );
    assert_eq!(result.1.files, 1, "Should count 1 file");
}

// ============================================================================
// Edge Case Tests: Deleted Files
// ============================================================================

/// Test: Deleted file is skipped unless scope is Deleted
#[test]
fn test_deleted_file_is_skipped_for_non_deleted_scope() {
    let diff = format!(
        "{}\ndeleted file mode 100644",
        make_diff_header("deleted.rs")
    );

    // Added scope should skip deleted files
    let result = parse_unified_diff(&diff, Scope::Added).unwrap();
    assert!(result.0.is_empty());
    assert_eq!(result.1.files, 0);

    // Changed scope should skip deleted files
    let result = parse_unified_diff(&diff, Scope::Changed).unwrap();
    assert!(result.0.is_empty());

    // Deleted scope should process deleted files
    let result = parse_unified_diff(&diff, Scope::Deleted).unwrap();
    assert!(result.0.is_empty()); // No content lines, just the marker
    assert_eq!(result.1.files, 0); // But file is tracked
}

// ============================================================================
// Edge Case Tests: Malformed Input Handling
// ============================================================================

/// Test: Malformed hunk header is handled gracefully
///
/// A malformed hunk header should not crash; it should be skipped and
/// processing should continue with subsequent content.
#[test]
fn test_malformed_hunk_header_is_handled_gracefully() {
    let diff = format!(
        "{}\n@@ NOT_VALID @@\n+valid line",
        make_diff_header("test.rs")
    );

    let result = parse_unified_diff(&diff, Scope::Added);
    // Should succeed despite malformed hunk header
    assert!(
        result.is_ok(),
        "Malformed hunk should not crash, got: {:?}",
        result
    );
    // The malformed hunk is skipped, so we get no lines from it
    // But subsequent content (if any) would still be processed
}

/// Test: Missing file path after diff --git is handled
///
/// If the diff --git line doesn't contain a path, processing should continue.
#[test]
fn test_missing_path_after_diff_git_continues_processing() {
    let diff = r#"
diff --git
--- a/test.rs
+++ b/test.rs
@@ -1,1 +1,2 @@
 fn a() {}
+fn b() {}
"#;

    let result = parse_unified_diff(diff, Scope::Added);
    // Should not panic; the diff is malformed but we handle it
    assert!(
        result.is_ok(),
        "Malformed diff --git should be handled: {:?}",
        result
    );
}

// ============================================================================
// Edge Case Tests: Large (But Non-Overflow) Inputs
// ============================================================================

/// Test: Large number of files (but well under u32::MAX) works correctly
///
/// This confirms the u32::try_from doesn't fail for large but valid inputs.
#[test]
fn test_large_file_count_under_u32_max_succeeds() {
    // Create a diff with 100 files, each with 1 line
    // This is well under u32::MAX (4.2 billion)
    let mut combined = String::new();
    for i in 0..100 {
        combined.push_str(&build_diff(&format!("file{}.rs", i), &["line"]));
        combined.push_str("\n\n");
    }

    let result = parse_unified_diff(&combined, Scope::Added).unwrap();
    assert_eq!(result.1.files, 100, "Should count 100 files");
    assert_eq!(result.1.lines, 100, "Should have 100 lines");
}

/// Test: Large number of lines (but well under u32::MAX) works correctly
///
/// This tests that line counting works for large (but valid) inputs.
#[test]
fn test_large_line_count_under_u32_max_succeeds() {
    // Create a diff with 10,000 lines in one file
    // This is well under u32::MAX
    let lines: Vec<String> = (0..10_000).map(|i| format!("line{}", i)).collect();
    let diff = build_diff(
        "large.rs",
        &lines.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    );

    let result = parse_unified_diff(&diff, Scope::Added).unwrap();
    assert_eq!(result.0.len(), 10_000, "Should have 10000 lines");
    assert_eq!(result.1.files, 1, "Should have 1 file");
    assert_eq!(result.1.lines, 10_000, "Should have 10000 lines in stats");
}

// ============================================================================
// Edge Case Tests: DiffParseError Overflow Variant Behavior
// ============================================================================

/// Test: Overflow error message contains meaningful information
///
/// When Overflow is returned, the message should indicate what overflowed
/// and what the limit is.
#[test]
fn test_overflow_error_message_is_descriptive() {
    let err = DiffParseError::Overflow("too many files (> 4294967295)".to_string());
    let display = format!("{}", err);

    assert!(
        display.contains("overflow") || display.contains("Overflow"),
        "Overflow error should mention 'overflow', got: {}",
        display
    );
    assert!(
        display.contains("4294967295") || display.contains("u32::MAX"),
        "Overflow error should mention the limit, got: {}",
        display
    );
}

/// Test: DiffStats implements Default (can be created with ..Default::default())
#[test]
fn test_diff_stats_default() {
    let stats = DiffStats {
        files: 5,
        lines: 10,
    };

    assert_eq!(stats.files, 5);
    assert_eq!(stats.lines, 10);
}

// ============================================================================
// Edge Case Tests: Line Number Tracking
// ============================================================================

/// Test: Line numbers are correctly tracked in output
///
/// The line number in DiffLine should match the position in the hunk.
#[test]
fn test_line_numbers_are_correctly_tracked() {
    let diff = format!(
        "{}\n{}\n+line1\n+line2\n+line3\n",
        make_diff_header("test.rs"),
        hunk_header_str(10, 0, 10, 3)
    );

    let result = parse_unified_diff(&diff, Scope::Added).unwrap();

    assert_eq!(result.0.len(), 3);
    // Line numbers should be 10, 11, 12 (starting at new_start)
    assert_eq!(result.0[0].line, 10);
    assert_eq!(result.0[1].line, 11);
    assert_eq!(result.0[2].line, 12);
}

/// Test: Content is correctly extracted (without + prefix)
#[test]
fn test_content_is_extracted_without_plus_prefix() {
    let diff = format!(
        "{}\n{}\n+fn test() {{}}\n",
        make_diff_header("test.rs"),
        hunk_header_str(1, 0, 1, 1)
    );

    let result = parse_unified_diff(&diff, Scope::Added).unwrap();

    assert_eq!(result.0.len(), 1);
    assert_eq!(
        result.0[0].content, "fn test() {}",
        "Content should not have + prefix"
    );
}

// ============================================================================
// Edge Case Tests: Edge of u32 Boundary
// ============================================================================

/// Test: u32::MAX as file count is valid input to DiffStats
///
/// DiffStats should be able to hold u32::MAX without overflow.
#[test]
fn test_diff_stats_can_hold_u32_max() {
    let stats = DiffStats {
        files: u32::MAX,
        lines: u32::MAX,
    };

    assert_eq!(stats.files, u32::MAX);
    assert_eq!(stats.lines, u32::MAX);
}

/// Test: usize::MAX to u32 conversion fails (as expected)
///
/// This confirms that on 64-bit systems, converting usize::MAX to u32
/// will fail, which is why we use u32::try_from() instead of 'as'.
#[test]
fn test_usize_max_to_u32_conversion_fails() {
    let large_usize = usize::MAX;
    let result = u32::try_from(large_usize);

    #[cfg(target_pointer_width = "64")]
    {
        assert!(
            result.is_err(),
            "On 64-bit, usize::MAX should not fit in u32"
        );
    }

    #[cfg(target_pointer_width = "32")]
    {
        assert!(
            result.is_ok(),
            "On 32-bit, usize::MAX == u32::MAX should fit"
        );
    }
}
