//! BDD tests for base-only unchanged code behavior.
//!
//! Verifies that diffguard ignores violations in unchanged base code.

use super::test_repo::TestRepo;

/// Scenario: unwrap() exists only in base (not modified) - should pass.
///
/// Given: A repository where the base commit has unwrap() in the code
/// When: A new commit makes unrelated changes (not touching the unwrap line)
/// Then: Exit code is 0 (pass) because the unwrap was not added/changed
#[test]
fn given_unwrap_only_in_base_when_check_then_pass() {
    // Given: A repository where the base commit has unwrap() in the code
    let repo = TestRepo::with_initial_content(&[(
        "src/lib.rs",
        "pub fn legacy() -> u32 { Some(1).unwrap() }\n",
    )]);

    // When: A new commit makes unrelated changes
    repo.write_file(
        "src/lib.rs",
        r#"pub fn legacy() -> u32 { Some(1).unwrap() }
pub fn new_safe_function() -> Option<u32> { Some(42) }
"#,
    );
    let head_sha = repo.commit("add new safe function");

    // Then: Exit code is 0 because the unwrap was not added/changed
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
    assert_eq!(receipt.verdict_status(), Some("pass"));
}

/// Scenario: unwrap() in base, other file modified - should pass.
///
/// Given: A file with unwrap() exists in base
/// When: A different file is added/modified
/// Then: No findings because the unwrap file was not touched
#[test]
fn given_unwrap_in_base_when_other_file_changed_then_pass() {
    // Given: A file with unwrap() exists in base
    let repo = TestRepo::with_initial_content(&[
        (
            "src/lib.rs",
            "pub fn legacy() -> u32 { Some(1).unwrap() }\n",
        ),
        ("src/other.rs", "pub fn other() {}\n"),
    ]);

    // When: A different file is added/modified
    repo.write_file(
        "src/other.rs",
        "pub fn other() { println!(\"modified\"); }\n",
    );
    let head_sha = repo.commit("modify other file");

    // Then: No findings on the unwrap (but may have warning for println)
    let result = repo.run_check(&head_sha);

    let receipt = result.parse_receipt();
    // Should not have unwrap finding (that file wasn't changed)
    assert!(!receipt.has_finding_with_rule("rust.no_unwrap"));
    // May have dbg/println warning, but that's separate
}

/// Scenario: No changes at all - empty diff should pass.
///
/// Given: A repository with some code
/// When: Checking with base == head (no changes)
/// Then: Exit code is 0 with no findings
#[test]
fn given_no_changes_when_check_then_pass() {
    // Given: A repository with some code
    let repo = TestRepo::new();

    // When: Checking with base == head (no changes)
    // Just check at the base SHA itself
    let result = repo.run_check(&repo.base_sha);

    // Then: Exit code is 0 with no findings
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

/// Scenario: Context lines from base are not flagged.
///
/// Given: A file with unwrap() in the middle
/// When: Lines are added near (but not touching) the unwrap line
/// Then: The unwrap is not flagged because it wasn't changed
#[test]
fn given_unwrap_in_context_when_nearby_change_then_not_flagged() {
    // Given: A file with unwrap() in the middle
    let repo = TestRepo::with_initial_content(&[(
        "src/lib.rs",
        r#"pub fn before() {}

pub fn risky() -> u32 {
    Some(1).unwrap()
}

pub fn after() {}
"#,
    )]);

    // When: Lines are added near but not touching the unwrap line
    repo.write_file(
        "src/lib.rs",
        r#"pub fn before() {}
pub fn new_before() {}

pub fn risky() -> u32 {
    Some(1).unwrap()
}

pub fn new_after() {}
pub fn after() {}
"#,
    );
    let head_sha = repo.commit("add functions around risky");

    // Then: The unwrap is not flagged because it wasn't changed
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert!(!receipt.has_finding_with_rule("rust.no_unwrap"));
}

/// Scenario: Deleting lines doesn't trigger base content checks.
///
/// Given: A file with multiple functions including some with unwrap
/// When: Safe lines are deleted (not the unwrap lines)
/// Then: No findings are reported
#[test]
fn given_deletion_only_when_check_then_pass() {
    // Given: A file with multiple functions
    let repo = TestRepo::with_initial_content(&[(
        "src/lib.rs",
        r#"pub fn keep_me() {}
pub fn delete_me() {}
pub fn also_keep() {}
"#,
    )]);

    // When: A line is deleted
    repo.write_file(
        "src/lib.rs",
        r#"pub fn keep_me() {}
pub fn also_keep() {}
"#,
    );
    let head_sha = repo.commit("delete a function");

    // Then: No findings (deletions don't add violations)
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}
