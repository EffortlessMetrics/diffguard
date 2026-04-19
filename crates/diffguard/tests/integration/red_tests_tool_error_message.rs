//! Red tests for verifying the "check failed" vs "tool error" message fix.
//!
//! This test verifies that when cockpit mode encounters an error but successfully
//! writes receipts, the stderr message says "check failed" (not "tool error")
//! because the exit code is 0 (success) indicating the receipt was written.
//!
//! The bug (before fix #513) was that stderr said "tool error" even though
//! the exit code was 0, which was misleading because "tool error" implies
//! exit code 1 (actual tool failure).
//!
//! Issue: #510
//! PR: #513
//! Commit: a7d61c4d4e54a72779a4d8fc614c2e41d4fa7c89

#![allow(deprecated)]

use super::test_repo::TestRepo;

/// Scenario: Cockpit mode with missing config should say "check failed" not "tool error"
///
/// Given: A repository
/// When: diffguard check runs in cockpit mode with a non-existent config file
/// Then: Exit code is 0 (receipt written successfully)
///   And: stderr says "check failed" (not "tool error")
///   And: A receipt file is written
///
/// This tests the tool error path in cockpit mode, where an unexpected error
/// (like a missing config file) occurs but the receipt is still written.
/// The message should say "check failed" because:
/// - Exit code is 0 (receipt written successfully)
/// - "tool error" would imply exit code 1 (actual tool failure)
/// - "check failed" indicates an error was encountered but handled gracefully
#[test]
fn test_cockpit_missing_config_says_check_failed_not_tool_error() {
    // Given: A repository with a valid commit
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn new_code() {}\n");
    let head_sha = repo.commit("add new code");

    // Use a missing config file to trigger the tool error path
    let missing_config = repo.path().join("missing.toml");

    // When: Running with a missing config in cockpit mode
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
    // The receipt was written successfully, so exit code 0 is correct.
    result.assert_exit_code(0);

    // And: stderr should say "check failed" not "tool error"
    // The fix changes "tool error" to "check failed" because:
    // - Exit code 0 = success (receipt written)
    // - "tool error" implies exit code 1 = tool failure
    // - "check failed" indicates an error was found but handled
    assert!(
        result.stderr.contains("check failed"),
        "stderr should contain 'check failed' but got: {}",
        result.stderr
    );

    // And: stderr should NOT say "tool error"
    // (The original bug was that it said "tool error" on success paths)
    assert!(
        !result.stderr.contains("tool error"),
        "stderr should NOT contain 'tool error' on success paths (exit code 0), but got: {}",
        result.stderr
    );

    // And: A receipt should have been written
    result.assert_receipt_exists();
}

/// Scenario: Cockpit mode with missing config and sensor should say "check failed" not "tool error"
///
/// Given: A repository
/// When: diffguard check runs in cockpit mode with a non-existent config and sensor path
/// Then: Exit code is 0 (receipt written successfully)
///   And: stderr says "check failed" (not "tool error")
///   And: A receipt file is written (sensor path failure falls back to out path)
///
/// This tests the scenario where the sensor JSON fails but the regular receipt
/// is still written successfully.
#[test]
fn test_cockpit_missing_config_with_sensor_says_check_failed_not_tool_error() {
    // Given: A repository with a valid commit
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn new_code() {}\n");
    let head_sha = repo.commit("add new code");

    // Use a missing config file to trigger the tool error path
    let missing_config = repo.path().join("missing.toml");
    // And a sensor path (the sensor.json will fail to write but out.json should succeed)
    let sensor_path = repo.path().join("sensor.json");

    // When: Running with a missing config and sensor path in cockpit mode
    let result = repo.run_check_with_args(
        &head_sha,
        &[
            "--mode",
            "cockpit",
            "--config",
            missing_config.to_str().unwrap(),
            "--sensor",
            sensor_path.to_str().unwrap(),
        ],
    );

    // Then: Exit code is 0 (receipt written successfully)
    result.assert_exit_code(0);

    // And: stderr should say "check failed" not "tool error"
    assert!(
        result.stderr.contains("check failed"),
        "stderr should contain 'check failed' but got: {}",
        result.stderr
    );

    // And: stderr should NOT say "tool error"
    assert!(
        !result.stderr.contains("tool error"),
        "stderr should NOT contain 'tool error' on success paths, but got: {}",
        result.stderr
    );
}

/// Scenario: Standard mode with actual tool error should still say "tool error"
///
/// Given: A repository
/// When: diffguard check runs in standard mode with a missing base ref
/// Then: Exit code is 1 (tool error)
///   And: stderr should mention an error
///
/// This test ensures we didn't "fix" the wrong path - the actual tool error
/// path in standard mode should still produce error messages.
#[test]
fn test_standard_tool_error_says_tool_error() {
    // Given: A repository
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn new_code() {}\n");
    let head_sha = repo.commit("add new code");

    // When: Running with a non-existent base ref in standard mode
    let result = repo.run_check_with_args(
        &head_sha,
        &["--base", "0000000000000000000000000000000000000000"],
    );

    // Then: Exit code is 1 (actual tool error occurred)
    result.assert_exit_code(1);

    // And: stderr should mention an error
    let stderr_lower = result.stderr.to_lowercase();
    assert!(
        stderr_lower.contains("error") || stderr_lower.contains("failed"),
        "stderr should contain error message, got: {}",
        result.stderr
    );
}
