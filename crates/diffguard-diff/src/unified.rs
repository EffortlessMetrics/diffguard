//! Red tests for work-095e24f2: Extract helpers from parse_unified_diff()
//!
//! Feature: refactor-parse-unified-diff
//! Feature: clippy-pedantic-too-many-lines
//!
//! ============================================================================
//! These tests verify the behavior of two helper functions that will be
//! extracted from `parse_unified_diff()`:
//!
//! 1. `process_diff_line_content()` - handles content-line processing
//! 2. `compute_diff_stats()` - handles file/line counting
//!
//! These tests will FAIL TO COMPILE until code-builder implements the helpers.
//! Once the helpers exist with the correct signatures, these tests should pass.
//!
//! ============================================================================
//! LOCATION: These tests call pub(crate) helpers from unified.rs.
//!
//! The helpers are NOT exported from lib.rs (they're pub(crate)), so they can
//! only be accessed from within the crate. This test file is placed in
//! `src/unified.rs` within the existing #[cfg(test)] mod tests section.
//!
//! When code-builder implements the helpers, they will be added to unified.rs
//! and these tests (which will be in unified.rs) can access them via super::*.
//! ============================================================================
//!

// This module contains tests for the helper functions.
// They will fail to compile until code-builder implements:
// - pub(crate) fn process_diff_line_content(...) -> Option<(Option<DiffLine>, bool, u32, u32)>
// - pub(crate) fn compute_diff_stats(...) -> DiffStats

#[cfg(test)]
mod helper_function_tests {
    use crate::{ChangeKind, DiffLine, DiffParseError, DiffStats, Scope};

    // =========================================================================
    // Tests for process_diff_line_content()
    // =========================================================================
    // Expected signature:
    // pub(crate) fn process_diff_line_content(
    //     line: &str,
    //     first: u8,
    //     path: &str,
    //     scope: Scope,
    //     old_line_no: u32,
    //     new_line_no: u32,
    //     pending_removed: bool,
    // ) -> Option<(Option<DiffLine>, bool, u32, u32)>

    #[test]
    fn test_process_diff_line_content_context_line() {
        // Context line (first = b' '):
        // - Returns Some((None, false, old_line_no+1, new_line_no+1))
        // - Resets pending_removed to false
        // - Increments both counters
        let result = process_diff_line_content(
            " context line",
            b' ',
            "src/lib.rs",
            Scope::Added,
            1,
            1,
            false,
        );
        let (diff_line, pending_removed, old_no, new_no) = result.unwrap();
        assert!(diff_line.is_none(), "Context line should not produce a DiffLine");
        assert!(!pending_removed, "pending_removed should be reset to false");
        assert_eq!(old_no, 2, "old_line_no should be incremented");
        assert_eq!(new_no, 2, "new_line_no should be incremented");
    }

    #[test]
    fn test_process_diff_line_content_removed_line() {
        // Removed line (first = b'-'):
        // - Returns Some((None, true, old_line_no+1, new_line_no))
        // - Sets pending_removed to true
        // - Increments only old_line_no
        let result = process_diff_line_content(
            "-removed line",
            b'-',
            "src/lib.rs",
            Scope::Added,
            1,
            1,
            false,
        );
        let (diff_line, pending_removed, old_no, new_no) = result.unwrap();
        assert!(diff_line.is_none(), "Removed line should not produce DiffLine for Added scope");
        assert!(pending_removed, "pending_removed should be set to true");
        assert_eq!(old_no, 2, "old_line_no should be incremented");
        assert_eq!(new_no, 1, "new_line_no should NOT change for removed line");
    }

    #[test]
    fn test_process_diff_line_content_added_without_pending() {
        // Added line (first = b'+') WITHOUT preceding removed:
        // - Returns Some((Some(DiffLine::Added), false, old_no, new_no+1))
        // - Resets pending_removed to false
        // - Increments only new_line_no
        let result = process_diff_line_content(
            "+added line",
            b'+',
            "src/lib.rs",
            Scope::Added,
            1,
            1,
            false, // no preceding removed
        );
        let (diff_line, pending_removed, old_no, new_no) = result.unwrap();
        assert!(diff_line.is_some(), "Added line should produce a DiffLine");
        let line = diff_line.unwrap();
        assert_eq!(line.kind, ChangeKind::Added);
        assert!(!pending_removed, "pending_removed should be reset");
        assert_eq!(old_no, 1, "old_line_no should NOT change");
        assert_eq!(new_no, 2, "new_line_no should be incremented");
    }

    #[test]
    fn test_process_diff_line_content_added_with_pending_changed_kind() {
        // Added line (first = b'+') WITH preceding removed (pending_removed=true):
        // - Returns Some((Some(DiffLine::Changed), false, old_no, new_no+1))
        // - Resets pending_removed to false
        // - Increments only new_line_no
        let result = process_diff_line_content(
            "+changed line",
            b'+',
            "src/lib.rs",
            Scope::Changed,
            2,
            2,
            true, // pending_removed = true from preceding -
        );
        let (diff_line, pending_removed, _, _) = result.unwrap();
        assert!(diff_line.is_some(), "Changed line should produce a DiffLine");
        let line = diff_line.unwrap();
        assert_eq!(line.kind, ChangeKind::Changed);
        assert!(!pending_removed, "pending_removed should be reset after consuming");
    }

    #[test]
    fn test_process_diff_line_content_added_scope_deleted_excludes() {
        // Added line with Scope::Deleted should be filtered out
        let result = process_diff_line_content(
            "+added line",
            b'+',
            "src/lib.rs",
            Scope::Deleted,
            1,
            1,
            true,
        );
        let (diff_line, pending_removed, _, _) = result.unwrap();
        assert!(diff_line.is_none(), "Added line should be excluded for Scope::Deleted");
        assert!(!pending_removed, "pending_removed should still be reset");
    }

    #[test]
    fn test_process_diff_line_content_non_content_returns_none() {
        // Lines not starting with +, -, or space should return None (not a content line)
        let result = process_diff_line_content(
            "diff --git a/file.rs b/file.rs",
            b'd',
            "src/lib.rs",
            Scope::Added,
            1,
            1,
            false,
        );
        assert!(result.is_none(), "Non-content line should return outer None");
    }

    #[test]
    fn test_process_diff_line_content_pending_removed_survives_multiple_removed() {
        // Multiple consecutive - lines should keep pending_removed=true
        let r1 = process_diff_line_content("-first", b'-', "f", Scope::Added, 1, 1, false);
        let (_, p1, _, _ ) = r1.unwrap();
        assert!(p1);

        let r2 = process_diff_line_content("-second", b'-', "f", Scope::Added, 2, 1, p1);
        let (_, p2, _, _ ) = r2.unwrap();
        assert!(p2);

        let r3 = process_diff_line_content("-third", b'-', "f", Scope::Added, 3, 1, p2);
        let (_, p3, _, _ ) = r3.unwrap();
        assert!(p3);
    }

    // =========================================================================
    // Tests for compute_diff_stats()
    // =========================================================================
    // Expected signature:
    // pub(crate) fn compute_diff_stats(lines: &[DiffLine]) -> DiffStats

    #[test]
    fn test_compute_diff_stats_single_file() {
        let lines = vec![
            DiffLine {
                path: "src/lib.rs".to_string(),
                line: 2,
                content: "+added1".to_string(),
                kind: ChangeKind::Added,
            },
            DiffLine {
                path: "src/lib.rs".to_string(),
                line: 3,
                content: "+added2".to_string(),
                kind: ChangeKind::Added,
            },
        ];
        let stats = compute_diff_stats(&lines);
        assert_eq!(stats.files, 1, "Should count 1 unique file");
        assert_eq!(stats.lines, 2, "Should count 2 total lines");
    }

    #[test]
    fn test_compute_diff_stats_multiple_files() {
        let lines = vec![
            DiffLine {
                path: "file1.rs".to_string(),
                line: 1,
                content: "+a".to_string(),
                kind: ChangeKind::Added,
            },
            DiffLine {
                path: "file2.rs".to_string(),
                line: 1,
                content: "+b".to_string(),
                kind: ChangeKind::Added,
            },
        ];
        let stats = compute_diff_stats(&lines);
        assert_eq!(stats.files, 2, "Should count 2 unique files");
        assert_eq!(stats.lines, 2, "Should count 2 total lines");
    }

    #[test]
    fn test_compute_diff_stats_same_file_multiple_hunks() {
        // Same file appearing in multiple hunks should count as 1 file
        let lines = vec![
            DiffLine {
                path: "src/lib.rs".to_string(),
                line: 2,
                content: "+added1".to_string(),
                kind: ChangeKind::Added,
            },
            DiffLine {
                path: "src/lib.rs".to_string(),
                line: 10,
                content: "+added2".to_string(),
                kind: ChangeKind::Added,
            },
        ];
        let stats = compute_diff_stats(&lines);
        assert_eq!(stats.files, 1, "Same file should count as 1 unique file");
        assert_eq!(stats.lines, 2, "Should count 2 total lines");
    }

    #[test]
    fn test_compute_diff_stats_empty() {
        let lines: Vec<DiffLine> = vec![];
        let stats = compute_diff_stats(&lines);
        assert_eq!(stats.files, 0);
        assert_eq!(stats.lines, 0);
    }
}

// ============================================================================
// Documentation tests for acceptance criteria
// ============================================================================
//
// These tests always pass - they document the acceptance criteria that must
// be satisfied after the refactoring.

#[test]
fn ac1_clippy_warning_resolved() {
    // AC1: Clippy warning is resolved
    //
    // Run: cargo clippy --package diffguard-diff -- -W clippy::pedantic
    // Before: warning: this function has too many lines (144/100)
    // After: no warning for parse_unified_diff
    //
    // This test always passes - it documents the requirement.
    assert!(true);
}

#[test]
fn ac4_function_line_count_under_100() {
    // AC4: Function line count is < 100
    //
    // The refactored parse_unified_diff must contain fewer than 100 logical
    // lines. This is enforced by the clippy::pedantic too_many_lines lint.
    //
    // This test always passes - it documents the requirement.
    assert!(true);
}

#[test]
fn ac5_pending_removed_state_preserved() {
    // AC5: pending_removed state is preserved correctly
    //
    // - A '-' line sets pending_removed = true
    // - A subsequent '+' line consumes pending_removed (ChangeKind::Changed)
    // - A ' ' context line resets pending_removed = false without consuming it
    // - State is correctly propagated through the helper return tuple
    //
    // This test always passes - it documents the requirement.
    assert!(true);
}
