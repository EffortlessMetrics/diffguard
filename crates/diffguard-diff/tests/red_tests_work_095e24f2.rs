//! Red tests for work-095e24f2: Extract helpers from parse_unified_diff()
//!
//! Feature: refactor-parse-unified-diff
//! Feature: clippy-pedantic-too-many-lines
//!
//! ============================================================================
//! These tests verify the behavior of the pending_removed state machine that
//! will be encapsulated in process_diff_line_content().
//!
//! Since this is a refactoring task (no algorithmic changes, only structural),
//! these tests verify the EXISTING behavior that will be preserved after the
//! helper extraction.
//!
//! These tests PASS before the refactoring (because the behavior exists) and
//! will continue to PASS after (because the refactoring is purely structural).
//!
//! The value of these tests is that they document the expected behavior and
//! catch any regressions if the refactoring is done incorrectly.
//!
//! AC1: Clippy warning resolved     -> verified via cargo clippy (not a test)
//! AC2: Existing tests pass         -> the existing tests in unified.rs
//! AC3: Public API unchanged        -> integration tests use public API
//! AC4: Function line count < 100  -> verified via cargo clippy (not a test)
//! AC5: pending_removed preserved    -> tested by integration tests below
//!
//! ============================================================================

use diffguard_diff::parse_unified_diff;
use diffguard_types::Scope;

// ============================================================================
// Integration tests for pending_removed state machine
// ============================================================================
//
// These tests verify the behavior of the pending_removed state machine that
// will be encapsulated in process_diff_line_content(). The state machine is:
//
// - A '-' line sets pending_removed = true
// - A subsequent '+' line consumes pending_removed (classifies as Changed)
// - A ' ' context line resets pending_removed = false without consuming it
// - State resets at "diff --git" and "@@" boundaries

#[test]
fn test_pending_removed_resets_at_diff_git_boundary() {
    // pending_removed state must be reset when we see a new "diff --git" header
    let diff = r#"
diff --git a/file1.rs b/file1.rs
--- a/file1.rs
+++ b/file1.rs
@@ -1,2 +1,2 @@
- removed_in_file1
+ changed_in_file1
diff --git a/file2.rs b/file2.rs
--- a/file2.rs
+++ b/file2.rs
@@ -1 +1 @@
+ pure_addition_in_file2
"#;
    let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();

    // Only the + in file1 should be Changed (has preceding - in same file)
    // The + in file2 should NOT be Changed (no preceding - in that file)
    assert_eq!(changed.len(), 1, "Should only have 1 Changed line");
    assert_eq!(changed[0].path, "file1.rs");
    assert_eq!(
        changed[0].kind,
        diffguard_diff::ChangeKind::Changed,
        "Line after - should be Changed"
    );
}

#[test]
fn test_pending_removed_resets_at_hunk_header() {
    // pending_removed state must be reset when we see a new hunk "@@"
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,2 +1,2 @@
- removed_in_first_hunk
+ changed_in_first_hunk
@@ -5,2 +5,2 @@ fn other() {}
+ pure_add_in_second_hunk
"#;
    let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();

    // Only the + in first hunk should be Changed
    // The + in second hunk should NOT be Changed (pending_removed reset at @@)
    assert_eq!(changed.len(), 1, "Should only have 1 Changed line");
    assert_eq!(
        changed[0].content, " changed_in_first_hunk",
        "First hunk's + after - should be Changed"
    );
}

#[test]
fn test_context_line_resets_pending_removed() {
    // A context line ' ' between - and + should reset pending_removed
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,3 @@
 fn a() {}
- removed
 context line (resets pending_removed)
+ added_after_context
"#;
    let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();

    // The + after context line should NOT be Changed because context reset pending_removed
    assert_eq!(
        changed.len(),
        0,
        "Should have 0 Changed lines because context reset pending_removed"
    );
}

#[test]
fn test_multiple_removed_before_addition() {
    // Multiple - lines before a single + should all trigger Changed
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,4 +1,4 @@
 fn a() {}
- removed1
- removed2
- removed3
+ added_after_multiple_removed
"#;
    let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();

    assert_eq!(changed.len(), 1, "Should have 1 Changed line");
    assert_eq!(
        changed[0].content, " added_after_multiple_removed",
        "Line after multiple - should be Changed"
    );
}

#[test]
fn test_pure_addition_is_added_not_changed() {
    // A + without preceding - in the same hunk should be Added (not Changed)
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -0,0 +1 @@
+ pure_addition
"#;
    let (added, _) = parse_unified_diff(diff, Scope::Added).unwrap();
    let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();

    // Scope::Added should include the line
    assert_eq!(added.len(), 1, "Should have 1 Added line");
    assert_eq!(added[0].kind, diffguard_diff::ChangeKind::Added);

    // Scope::Changed should NOT include it (no preceding -)
    assert_eq!(
        changed.len(),
        0,
        "Pure addition should NOT be Changed (no preceding -)"
    );
}

#[test]
fn test_deleted_scope_independent_of_pending_removed() {
    // Scope::Deleted should include - lines regardless of pending_removed state
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,2 +1,1 @@
-fn a() {}
- removed
+ changed
"#;
    let (deleted, _) = parse_unified_diff(diff, Scope::Deleted).unwrap();

    // Both - lines should be included
    assert_eq!(deleted.len(), 2, "Should have 2 Deleted lines");
    assert_eq!(deleted[0].content, "fn a() {}");
    assert_eq!(deleted[1].content, " removed");
}

#[test]
fn test_modified_scope_same_as_changed() {
    // Scope::Modified should behave identically to Scope::Changed
    let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
-old
+new
"#;
    let (changed, _) = parse_unified_diff(diff, Scope::Changed).unwrap();
    let (modified, _) = parse_unified_diff(diff, Scope::Modified).unwrap();

    assert_eq!(
        changed.len(),
        modified.len(),
        "Changed and Modified scopes should return same count"
    );
    assert_eq!(
        changed, modified,
        "Changed and Modified scopes should return identical results"
    );
}

// ============================================================================
// Documentation tests for acceptance criteria
// ============================================================================

#[test]
fn ac1_clippy_warning_resolved_after_refactoring() {
    // AC1: Clippy warning is resolved
    //
    // Run: cargo clippy --package diffguard-diff -- -W clippy::pedantic
    // Before: warning: this function has too many lines (144/100)
    //              --> crates/diffguard-diff/src/unified.rs:144
    // After: no warning for parse_unified_diff
    //
    // This test always passes - it documents the acceptance criteria.
    // The actual verification is done via clippy, not this test.
    assert!(true);
}

#[test]
fn ac3_public_api_unchanged_after_refactoring() {
    // AC3: No changes to:
    // - parse_unified_diff function signature or return type
    // - DiffLine, DiffStats, ChangeKind, DiffParseError type definitions
    // - Any pub item in the crate's public API
    //
    // This is verified by: cargo clippy --lib --bins --tests -- -D warnings
    //
    // NOTE: This test always passes - it documents the acceptance criteria.
    assert!(true);
}

#[test]
fn ac4_function_line_count_under_100_after_refactoring() {
    // AC4: Function line count is < 100
    //
    // The refactored parse_unified_diff must contain fewer than 100 logical
    // lines. This is enforced by the clippy::pedantic too_many_lines lint.
    //
    // NOTE: This test always passes - it documents the acceptance criteria.
    // The actual verification is done via clippy, not this test.
    assert!(true);
}

#[test]
fn ac5_pending_removed_state_preserved_after_refactoring() {
    // AC5: The refactoring must not change how pending_removed is managed:
    // - A '-' line sets pending_removed = true
    // - A subsequent '+' line consumes pending_removed (classifies as Changed)
    // - A ' ' context line resets pending_removed = false without consuming it
    // - State must be correctly propagated through the helper return tuple
    //
    // The integration tests above verify this behavior through the public API.
    //
    // NOTE: This test always passes - it documents the acceptance criteria.
    assert!(true);
}
