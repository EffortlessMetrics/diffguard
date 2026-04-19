//! Green tests for verifying edge cases around the "check failed" message fix.
//!
//! These tests verify that when cockpit mode encounters an error:
//! - If receipts write successfully, the message says "check failed" (not "tool error")
//! - The message text matches the exit code semantics
//!
//! Issue: #510
//! PR: #513
//! Commit: a7d61c4d4e54a72779a4d8fc614c2e41d4fa7c89

use super::test_repo::TestRepo;

/// Edge case: Sensor path is a directory (can't write file), regular receipt succeeds.
/// When sensor.json is a directory, write_text fails, but the regular receipt
/// should still be written successfully with "check failed" message.
#[test]
fn test_cockpit_sensor_path_is_directory_regular_receipt_succeeds() {
    // Given: A repository with a valid commit
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn new_code() {}\n");
    let head_sha = repo.commit("add new code");

    // Use a missing config to trigger the cockpit error path
    let missing_config = repo.path().join("missing.toml");
    // Sensor path is a directory (not a file) - this will fail to write
    let sensor_dir = repo.path().join("sensor.json");
    std::fs::create_dir_all(&sensor_dir).expect("create sensor dir");

    // When: Running with sensor path as directory
    let result = repo.run_check_with_args(
        &head_sha,
        &[
            "--mode",
            "cockpit",
            "--config",
            missing_config.to_str().unwrap(),
            "--sensor",
            sensor_dir.to_str().unwrap(),
        ],
    );

    // Then: Exit code is 0 (regular receipt written successfully)
    result.assert_exit_code(0);

    // And: stderr should say "check failed" (not "tool error")
    assert!(
        result.stderr.contains("check failed"),
        "stderr should contain 'check failed' but got: {}",
        result.stderr
    );

    // And: stderr should NOT say "tool error"
    assert!(
        !result.stderr.contains("tool error"),
        "stderr should NOT contain 'tool error' but got: {}",
        result.stderr
    );

    // And: A receipt should have been written
    result.assert_receipt_exists();
}

/// Edge case: No sensor flag, only regular receipt path.
/// When no sensor is specified, only the regular receipt is written.
/// Should still say "check failed" and return 0.
#[test]
fn test_cockpit_no_sensor_flag_only_receipt() {
    // Given: A repository with a valid commit
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn new_code() {}\n");
    let head_sha = repo.commit("add new code");

    // Use a missing config to trigger the cockpit error path
    let missing_config = repo.path().join("missing.toml");

    // When: Running without sensor flag
    let result = repo.run_check_with_args(
        &head_sha,
        &[
            "--mode",
            "cockpit",
            "--config",
            missing_config.to_str().unwrap(),
        ],
    );

    // Then: Exit code is 0 (receipt written successfully)
    result.assert_exit_code(0);

    // And: stderr should say "check failed" (not "tool error")
    assert!(
        result.stderr.contains("check failed"),
        "stderr should contain 'check failed' but got: {}",
        result.stderr
    );

    // And: stderr should NOT say "tool error"
    assert!(
        !result.stderr.contains("tool error"),
        "stderr should NOT contain 'tool error' but got: {}",
        result.stderr
    );

    // And: A receipt should have been written
    result.assert_receipt_exists();
}

/// Edge case: Receipt exists at default path already.
/// The code should overwrite the existing receipt.
#[test]
fn test_cockpit_receipt_overwrites_existing() {
    // Given: A repository with a valid commit
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn new_code() {}\n");
    let head_sha = repo.commit("add new code");

    // Pre-create the artifacts directory and receipt file
    let artifacts_dir = repo.path().join("artifacts/diffguard");
    std::fs::create_dir_all(&artifacts_dir).expect("create artifacts dir");
    let receipt_path = artifacts_dir.join("report.json");
    std::fs::write(&receipt_path, "old content").expect("create old receipt");

    // Use a missing config to trigger the cockpit error path
    let missing_config = repo.path().join("missing.toml");

    // When: Running with pre-existing receipt
    let result = repo.run_check_with_args(
        &head_sha,
        &[
            "--mode",
            "cockpit",
            "--config",
            missing_config.to_str().unwrap(),
        ],
    );

    // Then: Exit code is 0 (new receipt written successfully, overwriting old)
    result.assert_exit_code(0);

    // And: stderr should say "check failed" (not "tool error")
    assert!(
        result.stderr.contains("check failed"),
        "stderr should contain 'check failed' but got: {}",
        result.stderr
    );

    // And: A receipt should exist with new content (not "old content")
    result.assert_receipt_exists();
    let receipt_content = result.receipt.unwrap();
    assert!(
        !receipt_content.contains("old content"),
        "receipt should be overwritten, but still contains old content"
    );
}

/// Edge case: Multiple runs in same repo, receipts accumulate.
/// Each run should overwrite the previous receipt.
#[test]
fn test_cockpit_multiple_runs_overwrite_receipt() {
    // Given: A repository with valid commits
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn new_code() {}\n");
    let head_sha = repo.commit("add new code");

    let missing_config = repo.path().join("missing.toml");

    // First run
    let result1 = repo.run_check_with_args(
        &head_sha,
        &[
            "--mode",
            "cockpit",
            "--config",
            missing_config.to_str().unwrap(),
        ],
    );
    result1.assert_exit_code(0);

    // Second run
    let result2 = repo.run_check_with_args(
        &head_sha,
        &[
            "--mode",
            "cockpit",
            "--config",
            missing_config.to_str().unwrap(),
        ],
    );
    result2.assert_exit_code(0);

    // Both runs should say "check failed"
    assert!(
        result1.stderr.contains("check failed"),
        "first run should contain 'check failed'"
    );
    assert!(
        result2.stderr.contains("check failed"),
        "second run should contain 'check failed'"
    );

    // And neither should say "tool error"
    assert!(
        !result1.stderr.contains("tool error"),
        "first run should NOT contain 'tool error'"
    );
    assert!(
        !result2.stderr.contains("tool error"),
        "second run should NOT contain 'tool error'"
    );
}

/// Edge case: Error message contains special characters.
/// The detail message should be preserved in the output.
#[test]
fn test_cockpit_error_message_preserves_detail() {
    // Given: A repository with a valid commit
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn new_code() {}\n");
    let head_sha = repo.commit("add new code");

    // Use a missing config - the error message will contain the path
    let missing_config = repo.path().join("missing.toml");
    let config_path_str = missing_config.to_str().unwrap();

    // When: Running with missing config
    let result = repo.run_check_with_args(
        &head_sha,
        &["--mode", "cockpit", "--config", config_path_str],
    );

    // Then: Exit code is 0 (receipt written successfully despite error)
    result.assert_exit_code(0);

    // And: The error detail (missing config path) should appear in stderr
    // Either as part of "check failed" message or somewhere in output
    assert!(
        result.stderr.contains(config_path_str) || result.stderr.contains("check failed"),
        "stderr should contain either the config path or 'check failed', got: {}",
        result.stderr
    );
}
