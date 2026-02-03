//! BDD tests for diff-only scoping behavior.
//!
//! Verifies that diffguard only lints added/changed lines, not existing code.

use super::test_repo::TestRepo;

/// Scenario: unwrap() added in new code triggers a finding.
///
/// Given: A repository with clean baseline code
/// When: A commit introduces unwrap() in new code
/// Then: diffguard check returns exit code 2 (policy fail)
///   And: The receipt contains a finding pointing to the new line
#[test]
fn given_unwrap_added_when_check_then_finding_reported() {
    // Given: A repository with clean baseline code
    let repo = TestRepo::new();

    // When: A commit introduces unwrap() in new code
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("add unwrap");

    // Then: diffguard check returns exit code 2 (policy fail)
    let result = repo.run_check(&head_sha);
    result
        .assert_exit_code(2)
        .assert_receipt_exists()
        .assert_receipt_contains("rust.no_unwrap");

    // And: The receipt contains a finding pointing to the new line
    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("rust.no_unwrap"));
    assert!(receipt.has_finding_at("src/lib.rs", 1));
    assert_eq!(receipt.error_count(), 1);
}

/// Scenario: Multiple unwrap() calls in new code all get flagged.
///
/// Given: A repository with clean baseline code
/// When: A commit introduces multiple unwrap() calls
/// Then: Each unwrap() generates a separate finding
#[test]
fn given_multiple_unwraps_added_when_check_then_all_findings_reported() {
    // Given: A repository with clean baseline code
    let repo = TestRepo::new();

    // When: A commit introduces multiple unwrap() calls
    repo.write_file(
        "src/lib.rs",
        r#"pub fn f() -> u32 {
    let a = Some(1).unwrap();
    let b = Some(2).unwrap();
    let c = Some(3).expect("oops");
    a + b + c
}
"#,
    );
    let head_sha = repo.commit("add multiple unwraps");

    // Then: Each unwrap()/expect() generates a finding
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    // All three should be flagged (2 unwrap + 1 expect)
    assert_eq!(receipt.error_count(), 3);
}

/// Scenario: unwrap() added in a new file is detected.
///
/// Given: A repository with existing files
/// When: A new file with unwrap() is added
/// Then: The finding points to the new file
#[test]
fn given_new_file_with_unwrap_when_check_then_finding_reported() {
    // Given: A repository with existing files
    let repo = TestRepo::new();

    // When: A new file with unwrap() is added
    repo.write_file(
        "src/new_module.rs",
        "pub fn risky() { let _ = None::<i32>.unwrap(); }\n",
    );
    let head_sha = repo.commit("add new module");

    // Then: The finding points to the new file
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_at("src/new_module.rs", 1));
}

/// Scenario: Changed line with unwrap() is detected in "changed" scope.
///
/// Given: A file with existing safe code
/// When: A line is modified to include unwrap() and checked with scope=changed
/// Then: The changed line triggers a finding
#[test]
fn given_line_changed_to_unwrap_when_scope_changed_then_finding_reported() {
    // Given: A file with existing safe code
    let repo = TestRepo::with_initial_content(&[(
        "src/lib.rs",
        "pub fn f() -> Option<u32> { Some(1) }\n",
    )]);

    // When: A line is modified to include unwrap()
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("change to use unwrap");

    // Then: The changed line triggers a finding with scope=changed
    let result = repo.run_check_with_args(&head_sha, &["--scope", "changed"]);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("rust.no_unwrap"));
}

/// Scenario: Clean diff produces exit code 0.
///
/// Given: A repository with baseline code
/// When: A commit adds clean code without violations
/// Then: Exit code is 0 and no findings are reported
#[test]
fn given_clean_code_added_when_check_then_pass() {
    // Given: A repository with baseline code
    let repo = TestRepo::new();

    // When: A commit adds clean code without violations
    repo.write_file(
        "src/lib.rs",
        r#"pub fn f() -> Option<u32> { Some(1) }
pub fn g() -> Option<u32> { Some(2) }
"#,
    );
    let head_sha = repo.commit("add clean code");

    // Then: Exit code is 0 and no findings are reported
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
    assert_eq!(receipt.verdict_status(), Some("pass"));
}
