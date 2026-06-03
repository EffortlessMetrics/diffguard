//! Green tests for work-095e24f2: Extract helpers from parse_unified_diff()
//!
//! Feature: refactor-parse-unified-diff
//! Feature: clippy-pedantic-too-many-lines
//!
//! ============================================================================
//! These tests verify edge cases for the refactored implementation.
//!
//! The refactoring extracts two helper functions:
//! - `process_diff_line_content()`: encapsulates content-line processing
//! - `compute_diff_stats()`: encapsulates BTreeSet-based file/line counting
//!
//! These tests focus on edge cases NOT covered by the red tests.
//! ============================================================================

use diffguard_diff::parse_unified_diff;
use diffguard_types::Scope;

// ============================================================================
// Edge case tests for empty/malformed diff input
// ============================================================================

#[test]
fn test_empty_diff_input_returns_empty_results() {
    let diff = "";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert!(lines.is_empty());
    assert_eq!(stats.files, 0);
    assert_eq!(stats.lines, 0);
}

#[test]
fn test_whitespace_only_diff_returns_empty_results() {
    let diff = "   \n\n\t\n  ";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert!(lines.is_empty());
    assert_eq!(stats.files, 0);
    assert_eq!(stats.lines, 0);
}

#[test]
fn test_diff_header_only_no_hunk_returns_empty() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\nindex 0000000..1111111 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert!(lines.is_empty());
    assert_eq!(stats.files, 0);
    assert_eq!(stats.lines, 0);
}

#[test]
fn test_triple_at_marker_not_treated_as_hunk() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@@ -1,2 +1,2 @@@\n fn a() {}\n";
    let (lines, _stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert!(lines.is_empty());
}

#[test]
fn test_single_at_marker_lines_are_skipped() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,2 @@\n fn a() {}\n@ this is not a hunk\n+fn b() {}\n";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(stats.lines, 1);
    assert_eq!(lines[0].content, "fn b() {}");
}

// ============================================================================
// Edge case tests for compute_diff_stats()
// ============================================================================

#[test]
fn test_compute_diff_stats_empty_lines() {
    let diff = "";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(stats.files, 0);
    assert_eq!(stats.lines, 0);
    assert!(lines.is_empty());
}

#[test]
fn test_compute_diff_stats_single_file_multiple_lines() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,4 @@\n fn a() {}\n+fn b() {}\n+fn c() {}\n+fn d() {}\n";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.lines, 3);
    assert!(lines.iter().all(|l| l.path == "src/lib.rs"));
}

#[test]
fn test_compute_diff_stats_multiple_files_varying_lines() {
    let diff = "diff --git a/file1.rs b/file1.rs\n--- a/file1.rs\n+++ b/file1.rs\n@@ -1,1 +1,2 @@\n fn a() {}\n+fn b() {}\ndiff --git a/file2.rs b/file2.rs\n--- a/file2.rs\n+++ b/file2.rs\n@@ -1,1 +1,1 @@\n fn c() {}\ndiff --git a/file3.rs b/file3.rs\n--- a/file3.rs\n+++ b/file3.rs\n@@ -1,1 +1,2 @@\n fn d() {}\n+fn e() {}\n";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(stats.lines, 2);
    assert_eq!(stats.files, 2);
    let _ = lines; // suppress unused warning
}

// ============================================================================
// Edge case tests for process_diff_line_content() via Scope::Changed
// ============================================================================

#[test]
fn test_changed_scope_with_context_line_resets_state() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,4 +1,4 @@\n fn a() {}\n-removed\n context line\n+not_changed_because_context_reset\n";
    let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();
    assert!(changed.is_empty());
}

#[test]
fn test_submodule_line_in_content_is_skipped() {
    let diff = "diff --git a/vendor/lib b/vendor/lib\n--- a/vendor/lib\n+++ b/vendor/lib\n@@ -1 +1 @@\n-Subproject commit abc123\n+Subproject commit def456\n";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert!(lines.is_empty());
    assert_eq!(stats.files, 0);
    assert_eq!(stats.lines, 0);
}

#[test]
fn test_mixed_scopes_in_multifile_diff() {
    let diff = "diff --git a/added_only.rs b/added_only.rs\n--- a/added_only.rs\n+++ b/added_only.rs\n@@ -1,1 +1,1 @@\n fn a() {}\n+fn added() {}\ndiff --git a/changed.rs b/changed.rs\n--- a/changed.rs\n+++ b/changed.rs\n@@ -1,1 +1,1 @@\n-old\n+new\ndiff --git a/deleted.rs b/deleted.rs\n--- a/deleted.rs\n+++ b/deleted.rs\n@@ -1,1 +1,0 @@\n-deleted\n";
    let (added, _) = parse_unified_diff(diff, Scope::Added).unwrap();
    let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();
    let (deleted, _) = parse_unified_diff(diff, Scope::Deleted).unwrap();

    // Added scope includes ALL + lines regardless of whether they're pure or modified
    assert_eq!(added.len(), 2);
    assert_eq!(added[0].path, "added_only.rs");
    assert_eq!(added[0].content, "fn added() {}");
    assert_eq!(added[1].path, "changed.rs");
    assert_eq!(added[1].content, "new");
    assert_eq!(added[1].kind, diffguard_diff::ChangeKind::Changed);

    // Changed scope includes + lines that follow - lines
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].path, "changed.rs");
    assert_eq!(changed[0].content, "new");

    // Deleted scope includes ALL - lines (even those in modified hunks)
    // changed.rs: old is - in a Changed hunk, but still included in Scope::Deleted
    assert_eq!(deleted.len(), 2);
    assert_eq!(deleted[0].path, "changed.rs");
    assert_eq!(deleted[0].content, "old");
    assert_eq!(deleted[1].path, "deleted.rs");
    assert_eq!(deleted[1].content, "deleted");
}

// ============================================================================
// Edge case tests for line number counters
// ============================================================================

#[test]
fn test_line_numbers_increase_correctly_across_hunks() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,3 @@\n fn a() {}\n+fn b() {}\n@@ -10,2 +11,3 @@ fn other() {}\n fn x() {}\n+fn y() {}\n";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(stats.lines, 2);
    let first = lines.iter().find(|l| l.content == "fn b() {}").unwrap();
    let second = lines.iter().find(|l| l.content == "fn y() {}").unwrap();
    assert_eq!(first.line, 2);
    assert_eq!(second.line, 12);
}

#[test]
fn test_deleted_scope_respects_line_numbers() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,3 +1,1 @@\n-fn a() {}\n fn b() {}\n-fn c() {}\n+fn updated() {}\n";
    let (deleted, _) = parse_unified_diff(diff, Scope::Deleted).unwrap();
    assert_eq!(deleted.len(), 2);
    assert_eq!(deleted[0].line, 1);
    assert_eq!(deleted[0].content, "fn a() {}");
    assert_eq!(deleted[1].line, 3);
    assert_eq!(deleted[1].content, "fn c() {}");
}

// ============================================================================
// Edge case tests for unusual diff content
// ============================================================================

#[test]
fn test_plus_line_with_only_whitespace() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,2 @@\n fn a() {}\n+   \n";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(stats.lines, 1);
    assert_eq!(lines[0].content, "   ");
}

#[test]
fn test_backslash_marker_not_no_newline() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,2 @@\n fn a() {}\n+\\hello\n";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(stats.lines, 1);
    assert_eq!(lines[0].content, "\\hello");
}

#[test]
fn test_multiple_sequential_context_lines() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,5 +1,5 @@\n fn a() {}\n-removed\n context1\n context2\n context3\n+added_after_contexts\n";
    let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();
    assert!(changed.is_empty());
}

#[test]
fn test_zero_length_diff_is_handled() {
    let diff = "diff --git a/empty.rs b/empty.rs\nnew file mode 100644\n--- /dev/null\n+++ b/empty.rs\n@@ -0,0 +0,0 @@\n";
    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert!(lines.is_empty());
    assert_eq!(stats.files, 0);
    assert_eq!(stats.lines, 0);
}
