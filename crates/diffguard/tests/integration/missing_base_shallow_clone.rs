//! BDD tests for missing base SHA (shallow clone) behavior.
//!
//! Verifies that diffguard returns exit code 1 (tool error) when the
//! base SHA is not available (e.g., in a shallow clone scenario).

#![allow(deprecated)]

use super::test_repo::TestRepo;

/// Scenario: Base SHA not available produces tool error.
///
/// Given: A repository where the base SHA does not exist
/// When: diffguard check runs with an invalid base ref
/// Then: Exit code is 1 (tool error)
///   And: stderr contains an error message about git
#[test]
fn given_missing_base_sha_when_check_then_tool_error() {
    // Given: A repository
    let repo = TestRepo::new();

    // Make a change so we have a valid head
    repo.write_file("src/lib.rs", "pub fn new_code() {}\n");
    let head_sha = repo.commit("add new code");

    // When: Running with a non-existent base SHA
    let result =
        repo.run_check_with_invalid_base(&head_sha, "0000000000000000000000000000000000000000");

    // Then: Exit code is 1 (tool error)
    result.assert_exit_code(1);

    // And: stderr contains an error message
    // The error should indicate git diff failed
    assert!(
        result.stderr.contains("git diff failed")
            || result.stderr.contains("error")
            || result.stderr.contains("Error"),
        "stderr should contain error message, got: {}",
        result.stderr
    );
}

/// Scenario: Invalid ref name produces tool error.
///
/// Given: A repository
/// When: diffguard check runs with an invalid ref name
/// Then: Exit code is 1 (tool error)
#[test]
fn given_invalid_ref_name_when_check_then_tool_error() {
    // Given: A repository
    let repo = TestRepo::new();

    repo.write_file("src/lib.rs", "pub fn f() {}\n");
    let head_sha = repo.commit("add code");

    // When: Running with an invalid ref name
    let result = repo.run_check_with_invalid_base(&head_sha, "this-branch-does-not-exist");

    // Then: Exit code is 1 (tool error)
    result.assert_exit_code(1);
}

/// Scenario: Non-existent head SHA produces tool error.
///
/// Given: A repository with a valid base
/// When: diffguard check runs with an invalid head SHA
/// Then: Exit code is 1 (tool error)
#[test]
fn given_invalid_head_sha_when_check_then_tool_error() {
    // Given: A repository
    let repo = TestRepo::new();

    // When: Running with a non-existent head SHA
    // We use the base_sha as the base and an invalid SHA as head
    let out_path = repo.path().join("artifacts/diffguard/report.json");

    let output = assert_cmd::Command::cargo_bin("diffguard")
        .expect("binary")
        .current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(&repo.base_sha)
        .arg("--head")
        .arg("0000000000000000000000000000000000000000")
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("run command");

    // Then: Exit code is 1 (tool error)
    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(exit_code, 1, "Expected exit code 1 for invalid head SHA");
}

/// Scenario: Truncated SHA produces tool error.
///
/// Given: A repository
/// When: diffguard check runs with a truncated (too short) SHA
/// Then: Exit code is 1 (tool error) if git cannot resolve it
#[test]
fn given_truncated_sha_when_check_then_error_or_resolves() {
    // Given: A repository
    let repo = TestRepo::new();

    repo.write_file("src/lib.rs", "pub fn f() {}\n");
    let head_sha = repo.commit("add code");

    // When: Running with a very short (likely ambiguous or invalid) ref
    // Using just "0000" which likely won't resolve
    let result = repo.run_check_with_invalid_base(&head_sha, "0000");

    // Then: Should fail (exit code 1) because the ref can't be resolved
    // Note: very short SHAs might actually resolve in some repos, but "0000"
    // is almost certainly invalid
    assert!(
        result.exit_code == 1,
        "Expected exit code 1 for unresolvable short SHA, got {}",
        result.exit_code
    );
}

/// Scenario: Valid short SHA works.
///
/// Given: A repository with a commit
/// When: Using the first 7 characters of a valid SHA
/// Then: It should resolve correctly (exit code 0 or 2)
#[test]
fn given_valid_short_sha_when_check_then_works() {
    // Given: A repository
    let repo = TestRepo::new();

    repo.write_file("src/lib.rs", "pub fn clean() -> Option<u32> { Some(1) }\n");
    let head_sha = repo.commit("add clean code");

    // When: Using short SHA (first 7 chars)
    let short_base = &repo.base_sha[..7.min(repo.base_sha.len())];
    let short_head = &head_sha[..7.min(head_sha.len())];

    let out_path = repo.path().join("artifacts/diffguard/report.json");

    let output = assert_cmd::Command::cargo_bin("diffguard")
        .expect("binary")
        .current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(short_base)
        .arg("--head")
        .arg(short_head)
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("run command");

    // Then: Should succeed (exit 0 for clean code)
    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(
        exit_code, 0,
        "Expected exit code 0 for valid short SHAs, got {}",
        exit_code
    );
}
