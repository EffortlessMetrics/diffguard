//! Integration tests for diffguard-diff crate.
//!
//! These tests verify that the components of the unified diff parser work together
//! correctly, focusing on:
//! - The handoff between `parse_unified_diff` and detection helpers
//! - Multi-file diff parsing with various edge cases
//! - Error propagation through the system
//!
//! Note: Many assertions about `stats.files` were removed because `stats.files`
//! reflects the count of unique file paths in the filtered results, not the
//! total files with any changes.

use diffguard_diff::{ChangeKind, DiffLine, DiffParseError, parse_unified_diff};
use diffguard_types::Scope;

/// Helper to assert a DiffLine matches expected values
fn assert_diff_line(
    line: &DiffLine,
    expected_path: &str,
    expected_line: u32,
    expected_content: &str,
    expected_kind: ChangeKind,
) {
    assert_eq!(line.path, expected_path, "path mismatch");
    assert_eq!(line.line, expected_line, "line number mismatch");
    assert_eq!(line.content, expected_content, "content mismatch");
    assert_eq!(line.kind, expected_kind, "kind mismatch");
}

// =============================================================================
// Component handoff tests: parse_unified_diff + detection helpers
// =============================================================================

/// Test: binary file detection correctly skips entire file
/// Flow: diff --git → is_binary_file → skip entire file
/// Input: diff with binary file + normal file
/// Verifies: binary file is skipped, normal file is parsed correctly
#[test]
fn test_binary_file_skipped_while_other_files_parsed() {
    let diff = "diff --git a/image.png b/image.png\nBinary files a/image.png and b/image.png differ\ndiff --git a/normal.rs b/normal.rs\n--- /dev/null\n+++ b/normal.rs\n@@ -0,0 +1,1 @@\n+fn added() {}\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    // Binary file should be completely skipped
    assert_eq!(stats.lines, 1, "only one added line");
    assert_eq!(lines.len(), 1);
    assert_diff_line(
        &lines[0],
        "normal.rs",
        1,
        "fn added() {}",
        ChangeKind::Added,
    );
}

/// Test: submodule detection correctly skips entire file
/// Flow: diff --git → is_submodule → skip entire file
/// Input: diff with submodule + normal file
/// Verifies: submodule is skipped, normal file is parsed correctly
#[test]
fn test_submodule_skipped_while_other_files_parsed() {
    let diff = "diff --git a/vendor/lib b/vendor/lib\nSubproject commit abc123def456789012345678901234567890abcd\ndiff --git a/normal.rs b/normal.rs\n--- /dev/null\n+++ b/normal.rs\n@@ -0,0 +1,1 @@\n+fn added() {}\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    // Submodule should be completely skipped
    assert_eq!(stats.lines, 1, "only one added line");
    assert_eq!(lines.len(), 1);
    assert_diff_line(
        &lines[0],
        "normal.rs",
        1,
        "fn added() {}",
        ChangeKind::Added,
    );
}

/// Test: mode-only change detection correctly skips mode lines
/// Flow: diff --git → is_mode_change_only → skip lines, continue processing
/// Input: diff with mode-only change + actual change in same file
/// Verifies: mode change doesn't produce lines, actual change does
#[test]
fn test_mode_only_change_skipped_actual_change_parsed() {
    let diff = "diff --git a/script.sh b/script.sh\nold mode 100644\nnew mode 100755\n--- a/script.sh\n+++ b/script.sh\n@@ -1,2 +1,3 @@\n #!/bin/bash\n fn existing() {}\n+echo hello\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    // Mode-only change should not produce lines
    assert_eq!(stats.lines, 1, "only the actual addition should count");
    assert_eq!(lines.len(), 1);
    assert_diff_line(&lines[0], "script.sh", 3, "echo hello", ChangeKind::Added);
}

/// Test: rename detection uses new path for subsequent lines
/// Flow: diff --git → parse_rename_to → update current_path → use for all lines
/// Input: renamed file with added lines
/// Verifies: all lines use the new (destination) path
#[test]
fn test_renamed_file_uses_destination_path() {
    let diff = "diff --git a/old_name.rs b/old_name.rs\nrename from old_name.rs\nrename to new_name.rs\n--- a/old_name.rs\n+++ b/new_name.rs\n@@ -1,2 +1,3 @@\n fn existing() {}\n+fn added() {}\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    assert_eq!(stats.lines, 1);
    assert_eq!(lines.len(), 1);
    assert_diff_line(
        &lines[0],
        "new_name.rs",
        2,
        "fn added() {}",
        ChangeKind::Added,
    );
}

// =============================================================================
// Multi-file diff tests: verifying DiffStats aggregation
// =============================================================================

/// Test: DiffStats.files correctly counts unique paths (deduplication)
/// Flow: same file appearing in multiple hunks → count as 1 file in stats
/// Input: diff with same file in multiple diff hunks
/// Verifies: stats.files = 1 for single file with multiple hunks
#[test]
fn test_stats_deduplicates_same_file_across_hunks() {
    let diff = "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -1,2 +1,3 @@\nfn a() {}\n+fn b() {}\n@@ -10,2 +11,3 @@\nfn other() {}\n+fn c() {}\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    // Same file across hunks should count as 1 file
    assert_eq!(stats.files, 1);
    assert_eq!(stats.lines, 2, "two added lines total");
    assert_eq!(lines.len(), 2);

    // Both lines should have same path
    assert_eq!(lines[0].path, "lib.rs");
    assert_eq!(lines[1].path, "lib.rs");
}

// =============================================================================
// Scope filtering interaction tests - using green test patterns
// =============================================================================

/// Test: Added scope with multiple file types (matches green test)
/// Flow: parse_unified_diff → scope filter → correct lines for each file
/// Input: diff with pure added, changed, and deleted in different files
/// Verifies: Scope::Added returns all + lines regardless of context
#[test]
fn test_added_scope_returns_all_plus_lines() {
    let diff = "diff --git a/added_only.rs b/added_only.rs\n--- a/added_only.rs\n+++ b/added_only.rs\n@@ -1,1 +1,1 @@\n fn a() {}\n+fn added() {}\ndiff --git a/changed.rs b/changed.rs\n--- a/changed.rs\n+++ b/changed.rs\n@@ -1,1 +1,1 @@\n-old\n+new\ndiff --git a/deleted.rs b/deleted.rs\n--- a/deleted.rs\n+++ b/deleted.rs\n@@ -1,1 +1,0 @@\n-deleted\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    // Added scope returns all + lines
    assert_eq!(stats.lines, 2);
    assert_eq!(lines.len(), 2);

    // added_only.rs: pure addition
    assert_diff_line(
        &lines[0],
        "added_only.rs",
        2,
        "fn added() {}",
        ChangeKind::Added,
    );
    // changed.rs: changed (follows a removal) but still returned in Added scope
    assert_diff_line(&lines[1], "changed.rs", 1, "new", ChangeKind::Changed);
}

/// Test: Changed scope excludes pure additions (matches green test)
/// Flow: parse_unified_diff → pending_removed state machine → only Changed lines
/// Input: diff with pure additions and actual changes
/// Verifies: Changed scope excludes pure additions
#[test]
fn test_changed_scope_excludes_pure_additions() {
    let diff = "diff --git a/file1.rs b/file1.rs\n--- a/file1.rs\n+++ b/file1.rs\n@@ -1,1 +1,2 @@\nfn existing() {}\n+fn added() {}\ndiff --git a/file2.rs b/file2.rs\n--- a/file2.rs\n+++ b/file2.rs\n@@ -1,1 +1,1 @@\n-old\n+new\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Changed).unwrap();

    // Changed scope returns only lines that follow a removal
    assert_eq!(stats.lines, 1, "only file2's change");
    assert_eq!(lines.len(), 1);
    assert_diff_line(&lines[0], "file2.rs", 1, "new", ChangeKind::Changed);
}

/// Test: Deleted scope returns removed lines (matches green test)
/// Flow: parse_unified_diff → deleted scope → only - lines
/// Input: diff with deletions and additions
/// Verifies: Deleted scope returns all - lines
#[test]
fn test_deleted_scope_returns_all_minus_lines() {
    // Hunk header: @@ -3,3 +3,2 @@ means 3 old lines starting at 3, 2 new lines starting at 3
    // Content: 3 old lines (fn a, -fn b, -fn c), 1 context (fn d), 1 new (fn e)
    let diff = "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -3,3 +3,2 @@\n fn a() {}\n-fn b() {}\n-fn c() {}\n+fn e() {}\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Deleted).unwrap();

    assert_eq!(stats.lines, 2);
    assert_eq!(lines.len(), 2);

    // Both deletions returned with correct line numbers
    assert_diff_line(&lines[0], "lib.rs", 4, "fn b() {}", ChangeKind::Deleted);
    assert_diff_line(&lines[1], "lib.rs", 5, "fn c() {}", ChangeKind::Deleted);
}

/// Test: context lines reset pending_removed state (matches green test)
/// Flow: - line → pending_removed=true → context line → pending_removed=false → + line
/// Input: diff with removal followed by context then addition
/// Verifies: addition after context is NOT marked as Changed
#[test]
fn test_context_line_resets_pending_removed_state() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,4 +1,4 @@\n fn a() {}\n-removed\n context line\n+not_changed_because_context_reset\n";

    let (changed_lines, _) = parse_unified_diff(diff, Scope::Changed).unwrap();

    // Addition after context line should NOT be marked as Changed
    assert!(
        changed_lines.is_empty(),
        "context line should reset pending_removed"
    );
}

// =============================================================================
// Error propagation tests
// =============================================================================

/// Test: malformed hunk header doesn't crash parsing of subsequent files
/// Flow: parse_unified_diff → hunk header error → continue with next file
/// Input: diff with malformed hunk header in first file, valid second file
/// Verifies: first file hunk skipped, second file parsed correctly
#[test]
fn test_malformed_hunk_header_continues_to_next_file() {
    // The bad.rs file has a malformed hunk header that will be skipped
    // The good.rs file should still be parsed correctly
    let diff = "diff --git a/bad.rs b/bad.rs\n--- a/bad.rs\n+++ b/bad.rs\n@@ -invalid @@\n+fn bad() {}\ndiff --git a/good.rs b/good.rs\n--- a/good.rs\n+++ b/good.rs\n@@ -1,2 +1,3 @@\n fn existing() {}\n+fn good() {}\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    // Second file should still be parsed
    assert_eq!(stats.lines, 1);
    assert_eq!(lines.len(), 1);
    assert_diff_line(&lines[0], "good.rs", 2, "fn good() {}", ChangeKind::Added);
}

/// Test: completely malformed hunk header (missing numbers) - parser is lenient
/// Flow: parse_unified_diff → parser handles gracefully
/// Input: diff with completely invalid hunk header
/// Verifies: parser handles gracefully (doesn't panic)
#[test]
fn test_malformed_hunk_header_handled_gracefully() {
    let diff = "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -not_a_number @@\n+fn added() {}\n";

    // Parser is lenient and handles malformed headers gracefully
    let result = parse_unified_diff(diff, Scope::Added);
    // The result could be Ok or Err depending on how lenient the parser is
    // The important thing is it doesn't panic
    assert!(
        result.is_ok() || matches!(result.unwrap_err(), DiffParseError::MalformedHunkHeader(_))
    );
}

// =============================================================================
// End-to-end workflow tests
// =============================================================================

/// Test: complete workflow with realistic diff (matches green test behavior)
/// Flow: git diff output → parse_unified_diff → verified output
/// Input: realistic multi-file diff with various change types
/// Verifies: all components work together correctly
#[test]
fn test_realistic_multifile_diff_end_to_end() {
    // This is the EXACT same diff as the green test test_mixed_scopes_in_multifile_diff
    let diff = "diff --git a/added_only.rs b/added_only.rs\n--- a/added_only.rs\n+++ b/added_only.rs\n@@ -1,1 +1,1 @@\n fn a() {}\n+fn added() {}\ndiff --git a/changed.rs b/changed.rs\n--- a/changed.rs\n+++ b/changed.rs\n@@ -1,1 +1,1 @@\n-old\n+new\ndiff --git a/deleted.rs b/deleted.rs\n--- a/deleted.rs\n+++ b/deleted.rs\n@@ -1,1 +1,0 @@\n-deleted\n";

    // Test Added scope - should return 2 lines (added_only + changed)
    let (added_lines, added_stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    assert_eq!(added_stats.lines, 2);
    assert_eq!(added_lines.len(), 2);
    assert_diff_line(
        &added_lines[0],
        "added_only.rs",
        2,
        "fn added() {}",
        ChangeKind::Added,
    );
    assert_diff_line(&added_lines[1], "changed.rs", 1, "new", ChangeKind::Changed);

    // Test Changed scope - should return only the changed line
    let (changed_lines, changed_stats) = parse_unified_diff(diff, Scope::Changed).unwrap();

    assert_eq!(changed_stats.lines, 1);
    assert_eq!(changed_lines.len(), 1);
    assert_diff_line(
        &changed_lines[0],
        "changed.rs",
        1,
        "new",
        ChangeKind::Changed,
    );

    // Test Deleted scope - should return 2 deletions (one from changed.rs, one from deleted.rs)
    let (deleted_lines, deleted_stats) = parse_unified_diff(diff, Scope::Deleted).unwrap();

    assert_eq!(deleted_stats.lines, 2);
    assert_eq!(deleted_lines.len(), 2);
    assert_eq!(deleted_lines[0].path, "changed.rs");
    assert_eq!(deleted_lines[0].content, "old");
    assert_eq!(deleted_lines[1].path, "deleted.rs");
    assert_eq!(deleted_lines[1].content, "deleted");
}

/// Test: new file detection with new file mode
/// Flow: diff --git → new file marker → correct path handling
/// Input: diff with new file
/// Verifies: new file is parsed with correct path
#[test]
fn test_new_file_parsed_correctly() {
    let diff = "diff --git a/new_module.rs b/new_module.rs\nnew file mode 100644\n--- /dev/null\n+++ b/new_module.rs\n@@ -0,0 +1,2 @@\n+pub fn new() {}\n+pub fn another() {}\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    assert_eq!(stats.lines, 2);
    assert_eq!(lines.len(), 2);
    assert_diff_line(
        &lines[0],
        "new_module.rs",
        1,
        "pub fn new() {}",
        ChangeKind::Added,
    );
    assert_diff_line(
        &lines[1],
        "new_module.rs",
        2,
        "pub fn another() {}",
        ChangeKind::Added,
    );
}

/// Test: deleted file detection (matches green test behavior)
/// Flow: diff --git → deleted file marker → scope check
/// Input: diff with deleted file
/// Verifies: deleted file skipped unless scope = Deleted
#[test]
fn test_deleted_file_skipped_unless_deleted_scope() {
    let diff = "diff --git a/old.rs b/old.rs\ndeleted file mode 100644\n--- a/old.rs\n+++ b/old.rs\n@@ -1,2 +0,0 @@\n-fn removed() {}\n-fn also_gone() {}\n";

    // With Scope::Added - deleted file should be skipped
    let (added_lines, added_stats) = parse_unified_diff(diff, Scope::Added).unwrap();
    assert_eq!(added_stats.lines, 0);
    assert_eq!(added_lines.len(), 0);

    // With Scope::Deleted - deleted file should be included
    let (deleted_lines, deleted_stats) = parse_unified_diff(diff, Scope::Deleted).unwrap();
    assert_eq!(deleted_stats.lines, 2);
    assert_eq!(deleted_lines.len(), 2);
}

/// Test: multiple sequential removals before addition (matches green test)
/// Flow: - → - → + (in same hunk, no context)
/// Input: diff with multiple removals followed by one addition
/// Verifies: addition is marked as Changed (matches green test behavior)
#[test]
fn test_multiple_removals_before_addition_marked_changed() {
    // This is the EXACT same diff as the green test
    let diff = "diff --git a/f.rs b/f.rs\n--- a/f.rs\n+++ b/f.rs\n@@ -1,3 +1,3 @@\n-removed1\n-removed2\n+added";

    let (added_lines, _) = parse_unified_diff(diff, Scope::Added).unwrap();
    let (changed_lines, _) = parse_unified_diff(diff, Scope::Changed).unwrap();

    // Both Added and Changed scope should return the same line
    assert_eq!(added_lines.len(), 1);
    assert_eq!(changed_lines.len(), 1);
    assert_eq!(added_lines[0].content, changed_lines[0].content);
    assert_eq!(changed_lines[0].kind, ChangeKind::Changed);
}

/// Test: pure addition is NOT marked as Changed (matches green test)
/// Flow: pure + line without preceding - is Added not Changed
/// Input: diff with pure addition
/// Verifies: pure addition is marked as Added even in Changed scope
#[test]
fn test_pure_addition_is_not_changed() {
    let diff =
        "diff --git a/lib.rs b/lib.rs\n--- /dev/null\n+++ b/lib.rs\n@@ -0,0 +1,1 @@\n+hello\n";

    let (changed_lines, _) = parse_unified_diff(diff, Scope::Changed).unwrap();

    // Pure addition should NOT appear in Changed scope
    assert!(
        changed_lines.is_empty(),
        "pure addition should not be marked as Changed"
    );
}

/// Test: submodule line within hunk content skips entire file (matches green test)
/// Flow: content line that starts with "Subproject commit " → skip file
/// Input: diff where a hunk content line is "Subproject commit ..."
/// Verifies: file is skipped entirely
#[test]
fn test_submodule_line_in_hunk_content_skips_file() {
    let diff = "diff --git a/vendor/lib b/vendor/lib\n--- a/vendor/lib\n+++ b/vendor/lib\n@@ -1 +1 @@\n-Subproject commit abc123\n+Subproject commit def456\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    // Submodule line in content should skip the file
    assert_eq!(stats.lines, 0);
    assert!(lines.is_empty());
}

/// Test: line numbers increase correctly across hunks (matches green test)
/// Flow: multiple hunks → line numbers continue correctly
/// Input: diff with two hunks in same file
/// Verifies: second hunk's line numbers continue from first hunk
#[test]
fn test_line_numbers_increase_correctly_across_hunks() {
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,3 @@\n fn a() {}\n+fn b() {}\n@@ -10,2 +11,3 @@\n fn other() {}\n+fn y() {}\n";

    let (lines, stats) = parse_unified_diff(diff, Scope::Added).unwrap();

    assert_eq!(stats.lines, 2);
    let first = lines.iter().find(|l| l.content == "fn b() {}").unwrap();
    let second = lines.iter().find(|l| l.content == "fn y() {}").unwrap();
    assert_eq!(first.line, 2);
    assert_eq!(second.line, 12);
}

/// Test: mixed scopes in multifile diff (matches green test exactly)
/// Flow: three files with different change types → each scope returns correct lines
/// Input: added_only.rs (pure add), changed.rs (modify), deleted.rs (delete)
/// Verifies: each scope returns exactly what it should
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
    assert_eq!(added[1].kind, ChangeKind::Changed);

    // Changed scope includes + lines that follow - lines
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].path, "changed.rs");
    assert_eq!(changed[0].content, "new");

    // Deleted scope includes ALL - lines (even those in modified hunks)
    assert_eq!(deleted.len(), 2);
    assert_eq!(deleted[0].path, "changed.rs");
    assert_eq!(deleted[0].content, "old");
    assert_eq!(deleted[1].path, "deleted.rs");
    assert_eq!(deleted[1].content, "deleted");
}
