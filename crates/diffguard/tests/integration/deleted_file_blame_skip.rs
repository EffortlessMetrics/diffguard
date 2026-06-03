//! BDD tests for CLI deleted file blame skip behavior.
//!
//! Verifies that diffguard handles deleted files correctly when blame filters are used.
//! These tests verify the end-to-end behavior via the CLI.

use super::test_repo::TestRepo;

/// Scenario: git blame should not be called on deleted files
///
/// Given: A file exists in the base commit
/// When: The file is deleted in the head commit
/// Then: diffguard check should complete without git blame errors
///
/// This test verifies the fix for the issue where collect_blame_allowed_lines
/// was calling git blame on paths to deleted files, causing errors.
#[test]
fn given_deleted_file_when_check_then_no_git_blame_error() {
    let repo = TestRepo::new();

    // Create initial files
    repo.write_file("src/lib.rs", "pub fn base() {}\n");
    repo.write_file(
        "src/deleted_file.rs",
        "pub fn will_be_deleted() -> u32 { 42 }\n",
    );
    let base_sha = repo.commit("add files");

    // Modify one file and delete another
    repo.write_file("src/modified.rs", "pub fn modified() {}\n");
    std::fs::remove_file(repo.path().join("src/deleted_file.rs")).expect("delete file");
    let head_sha = repo.commit("modify and delete");

    // Get the diff to verify deleted file is in it
    let diff_output = std::process::Command::new("git")
        .current_dir(repo.path())
        .args(["diff", &base_sha, &head_sha])
        .output()
        .expect("git diff");

    let diff_text = String::from_utf8_lossy(&diff_output.stdout);
    println!("Diff text:\n{}", diff_text);

    // Verify the diff contains deleted file marker
    assert!(
        diff_text.contains("deleted file mode"),
        "diff should contain deleted file marker"
    );

    // Run the check - it should complete without git blame errors
    let result = repo.run_check_with_args(&head_sha, &["--base", &base_sha]);

    // The key assertion: check should NOT fail due to git blame on deleted file
    // Without the fix, git blame is called on deleted file path and fails with:
    // "fatal: cannot stat path 'src/deleted_file.rs': No such file or directory"
    //
    // With the fix, the deleted file path is detected and skipped, so no error occurs.
    assert!(
        !result.stderr.contains("git blame") || !result.stderr.contains("No such file"),
        "check should not fail due to git blame error on deleted file.\nstderr: {}\nstdout: {}",
        result.stderr,
        result.stdout
    );
}

/// Scenario: blame filters should work correctly with mixed deleted and modified files
///
/// Given: A diff with both deleted files and modified files
/// When: Running check with blame filters
/// Then: check completes without errors
#[test]
fn given_mixed_deleted_and_modified_files_when_check_then_completes_successfully() {
    let repo = TestRepo::with_initial_content(&[
        ("src/lib.rs", "pub fn base() {}\n"),
        ("src/deleted.rs", "pub fn will_delete() {}\n"),
    ]);
    let base_sha = repo.base_sha.clone();

    // Modify one file and delete another
    repo.write_file("src/modified.rs", "pub fn modified() {}\n");
    std::fs::remove_file(repo.path().join("src/deleted.rs")).expect("delete file");
    let head_sha = repo.commit("modify and delete");

    // Get the diff
    let diff_output = std::process::Command::new("git")
        .current_dir(repo.path())
        .args(["diff", &base_sha, &head_sha])
        .output()
        .expect("git diff");

    let diff_text = String::from_utf8_lossy(&diff_output.stdout);
    println!("Diff text:\n{}", diff_text);

    // Verify the diff contains both deleted file marker and modified file
    assert!(
        diff_text.contains("deleted file mode"),
        "diff should contain deleted file marker"
    );

    // Run the check - it should complete without git blame errors
    let result = repo.run_check_with_args(&head_sha, &["--base", &base_sha]);

    // Should not fail with git blame error
    assert!(
        !result.stderr.contains("git blame") || !result.stderr.contains("No such file"),
        "should not have git blame error on deleted file.\nstderr: {}\nstdout: {}",
        result.stderr,
        result.stdout
    );
}

/// Scenario: check with deleted files should work in standard mode
///
/// Given: A repository with a deleted file
/// When: Running check in standard mode
/// Then: The check should complete with exit code 0 (no violations) or 2 (violations found),
///       but NOT exit code 1 (tool error from git blame failure)
#[test]
fn given_deleted_file_when_standard_check_then_no_tool_error() {
    let repo = TestRepo::with_initial_content(&[
        ("src/lib.rs", "pub fn f() {}\n"),
        ("src/will_delete.rs", "pub fn g() {}\n"),
    ]);
    let base_sha = repo.base_sha.clone();

    // Delete will_delete.rs
    std::fs::remove_file(repo.path().join("src/will_delete.rs")).expect("remove file");
    let head_sha = repo.commit("delete file");

    // Verify the diff shows deleted file
    let diff_output = std::process::Command::new("git")
        .current_dir(repo.path())
        .args(["diff", &base_sha, &head_sha])
        .output()
        .expect("git diff base head");

    let diff_text = String::from_utf8_lossy(&diff_output.stdout);
    println!("Diff between {} and {}:\n{}", base_sha, head_sha, diff_text);

    assert!(
        diff_text.contains("deleted file mode"),
        "diff should contain deleted file marker"
    );

    // The check should NOT produce a git blame error
    // Before the fix: git blame fails on deleted file path, causing tool error (exit 1)
    // After the fix: deleted file is skipped, no git blame error (exit 0 or 2)
    let result = repo.run_check_with_args(&head_sha, &["--base", &base_sha]);

    // Exit code 1 means tool error - which is what happens when git blame fails
    // Exit code 0 means pass, exit code 2 means policy violations found
    assert_ne!(
        result.exit_code, 1,
        "should not have tool error (exit code 1) from git blame failure on deleted file.\nstderr: {}\nstdout: {}",
        result.stderr, result.stdout
    );
}
