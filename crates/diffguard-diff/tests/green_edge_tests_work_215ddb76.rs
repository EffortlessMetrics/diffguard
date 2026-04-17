//! Green edge case tests for work-215ddb76: lines_scanned u32 → u64 migration
//!
//! Feature: comprehensive-test-coverage
//!
//! These tests verify that the u64 migration for `DiffStats.lines`
//! handles edge cases correctly.
//!
//! Edge cases covered:
//! - Zero lines (empty diff)
//! - Single line diff  
//! - u32::MAX boundary
//! - Values larger than u32::MAX
//! - u64::MAX (extreme boundary)

use diffguard_diff::{DiffStats, parse_unified_diff};
use diffguard_types::Scope;

mod diff_stats_lines_u64_edge_cases {
    use super::*;

    /// Test that DiffStats.lines can hold u64::MAX without overflow.
    /// This is a boundary test - we construct a diff with u64::MAX lines
    /// by checking that the type accepts the maximum value.
    #[test]
    fn diff_stats_lines_type_is_u64() {
        // The type system guarantees this, but we verify by checking
        // that the struct field has the correct type via reflection.
        // This test passes by compilation - if lines were u32, the
        // attempted construction below would fail.
        let stats = DiffStats {
            files: 1,
            lines: u64::MAX,
        };
        assert_eq!(stats.lines, u64::MAX);
    }

    /// Test that DiffStats.lines can hold a value larger than u32::MAX.
    /// This verifies the core purpose of the migration - handling large diffs.
    #[test]
    fn diff_stats_lines_handles_value_larger_than_u32_max() {
        let large_value = (u32::MAX as u64) + 1;
        let stats = DiffStats {
            files: 1,
            lines: large_value,
        };
        assert_eq!(stats.lines, large_value);
        assert!(stats.lines > u32::MAX as u64);
    }

    /// Test that DiffStats.lines handles zero correctly.
    #[test]
    fn diff_stats_lines_handles_zero() {
        let stats = DiffStats { files: 0, lines: 0 };
        assert_eq!(stats.lines, 0);
    }

    /// Test that DiffStats.lines handles one correctly.
    #[test]
    fn diff_stats_lines_handles_one() {
        let stats = DiffStats { files: 1, lines: 1 };
        assert_eq!(stats.lines, 1);
    }

    /// Test that DiffStats.lines handles u32::MAX correctly.
    #[test]
    fn diff_stats_lines_handles_u32_max() {
        let stats = DiffStats {
            files: 1,
            lines: u32::MAX as u64,
        };
        assert_eq!(stats.lines, u32::MAX as u64);
        assert_eq!(stats.lines, u32::MAX as u64);
    }

    /// Test that DiffStats.files is u32 and lines is u64.
    /// Note: files is kept as u32 for API compatibility.
    #[test]
    fn diff_stats_files_is_u32_lines_is_u64() {
        let stats = DiffStats {
            files: u32::MAX, // files is still u32
            lines: u64::MAX, // lines is u64 (the migration)
        };
        assert_eq!(stats.files, u32::MAX);
        assert_eq!(stats.lines, u64::MAX);
    }
}

mod parse_unified_diff_lines_count_edge_cases {
    use super::*;

    /// Test that parse_unified_diff handles empty diff correctly.
    #[test]
    fn parse_unified_diff_empty_diff() {
        let diff = "";
        let result = parse_unified_diff(diff, Scope::Added);
        assert!(result.is_ok());
        let (lines, stats) = result.unwrap();
        assert_eq!(lines.len(), 0);
        assert_eq!(stats.lines, 0);
    }

    /// Test that parse_unified_diff handles single line diff.
    #[test]
    fn parse_unified_diff_single_line() {
        let diff = "diff --git a/f b/f\nindex 0000000..1234567 100644\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n+new\n";
        let result = parse_unified_diff(diff, Scope::Added);
        assert!(result.is_ok());
        let (lines, stats) = result.unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(stats.lines, 1);
    }

    /// Test that parse_unified_diff handles diff with multiple files.
    #[test]
    fn parse_unified_diff_multiple_files() {
        let diff = "diff --git a/f1 b/f1\nindex 0000000..1234567 100644\n--- a/f1\n+++ b/f1\n@@ -1 +1 @@\n-old\n+new1\ndiff --git a/f2 b/f2\nindex 0000000..1234568 100644\n--- a/f2\n+++ b/f2\n@@ -1 +1 @@\n-old\n+new2\n";
        let result = parse_unified_diff(diff, Scope::Added);
        assert!(result.is_ok());
        let (lines, stats) = result.unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(stats.files, 2);
        assert_eq!(stats.lines, 2);
    }

    /// Test that parse_unified_diff handles context lines correctly.
    #[test]
    fn parse_unified_diff_with_context_lines() {
        let diff = "diff --git a/f b/f\nindex 0000000..1234567 100644\n--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n old1\n-old2\n+new2\n old3\n";
        let result = parse_unified_diff(diff, Scope::Added);
        assert!(result.is_ok());
        let (lines, stats) = result.unwrap();
        // Should only count the added line (new2), not context lines
        assert_eq!(stats.lines, 1);
    }

    /// Test that parse_unified_diff handles Scope::Deleted correctly.
    #[test]
    fn parse_unified_diff_deleted_scope() {
        let diff = "diff --git a/f b/f\nindex 0000000..1234567 100644\n--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n old1\n-old2\n+new2\n old3\n";
        let result = parse_unified_diff(diff, Scope::Deleted);
        assert!(result.is_ok());
        let (lines, stats) = result.unwrap();
        // Should only count the deleted line (old2), not added or context
        assert_eq!(stats.lines, 1);
    }
}
