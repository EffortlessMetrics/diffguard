//! GREEN edge case tests for `cmd_doctor` return type fix.
//!
//! These tests verify edge cases specific to the return type change from
//! `Result<i32>` to `i32`. The change affects how `cmd_doctor` integrates
//! with the main function's match expression.
//!
//! These tests complement the existing `doctor.rs` tests which cover
//! functional behavior (git checks, config validation, etc.).
//!
//! Edge cases covered:
//! - Return value propagation through `Ok()` wrapper at call site
//! - Exit code 0 when all checks pass
//! - Exit code 1 when any check fails
//! - Clippy lint does not fire after the fix

use assert_cmd::Command;
use assert_cmd::cargo;
use tempfile::TempDir;

/// Verify that `diffguard doctor` exits with code 0 when all checks pass.
///
/// This tests the complete integration: cmd_doctor returns i32 -> Ok() wrapper
/// at call site -> main function returns Result<i32> -> process exit code.
#[test]
fn green_test_doctor_exit_code_zero_when_all_pass() {
    let td = TempDir::new().expect("temp dir");

    // Set up a valid git repo with valid config
    std::process::Command::new("git")
        .current_dir(td.path())
        .args(["init"])
        .output()
        .expect("git init should work");

    std::process::Command::new("git")
        .current_dir(td.path())
        .args(["config", "user.email", "test@test.com"])
        .output()
        .expect("git config should work");

    std::process::Command::new("git")
        .current_dir(td.path())
        .args(["config", "user.name", "Test"])
        .output()
        .expect("git config should work");

    let config_path = td.path().join("diffguard.toml");
    std::fs::write(
        &config_path,
        r#"
[[rules]]
id = "test"
description = "test"
severity = "warn"
match = "test"
"#,
    )
    .expect("write config");

    let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
    cmd.current_dir(td.path())
        .arg("doctor")
        .arg("--config")
        .arg(config_path.to_str().unwrap());

    let output = cmd.output().expect("doctor command should run");
    let exit_code = output.status.code().expect("should have exit code");

    assert_eq!(
        exit_code,
        0,
        "doctor should exit 0 when all checks pass.\n\
         stdout: {}\n\
         stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Verify that `diffguard doctor` exits with code 1 when git repo check fails.
///
/// This tests the failure path: cmd_doctor returns i32 -> Ok() wrapper
/// at call site -> main function returns Result<i32> -> process exit code 1.
#[test]
fn green_test_doctor_exit_code_one_when_not_in_git_repo() {
    let td = TempDir::new().expect("temp dir");

    // Do NOT initialize git repo - so git-repo check fails
    // But git itself is available, so only git-repo check fails

    let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
    cmd.current_dir(td.path()).arg("doctor");

    let output = cmd.output().expect("doctor command should run");
    let exit_code = output.status.code().expect("should have exit code");

    assert_eq!(
        exit_code,
        1,
        "doctor should exit 1 when not in a git repo.\n\
         stdout: {}\n\
         stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Verify that `diffguard doctor` exits with code 1 when config check fails.
///
/// Uses invalid TOML structure (`[[rule]]` instead of `[[rules]]`) which causes
/// TOML parsing to fail at the config loading stage.
#[test]
fn green_test_doctor_exit_code_one_when_config_invalid() {
    let td = TempDir::new().expect("temp dir");

    // Set up a valid git repo but with invalid config
    std::process::Command::new("git")
        .current_dir(td.path())
        .args(["init"])
        .output()
        .expect("git init should work");

    std::process::Command::new("git")
        .current_dir(td.path())
        .args(["config", "user.email", "test@test.com"])
        .output()
        .expect("git config should work");

    std::process::Command::new("git")
        .current_dir(td.path())
        .args(["config", "user.name", "Test"])
        .output()
        .expect("git config should work");

    // Invalid TOML: [[rule]] instead of [[rules]]
    // This creates a nested table structure that conflicts with the array of tables
    let config_path = td.path().join("diffguard.toml");
    std::fs::write(
        &config_path,
        r#"
[[rule]]
id = "test.bad_regex"
description = "Bad regex"
severity = "error"
match = "[invalid(regex"
"#,
    )
    .expect("write config");

    let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
    cmd.current_dir(td.path())
        .arg("doctor")
        .arg("--config")
        .arg(config_path.to_str().unwrap());

    let output = cmd.output().expect("doctor command should run");
    let exit_code = output.status.code().expect("should have exit code");

    assert_eq!(
        exit_code,
        1,
        "doctor should exit 1 when config is invalid TOML.\n\
         stdout: {}\n\
         stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Verify that `clippy` does not report `unnecessary_wraps` on cmd_doctor
/// after the return type change from `Result<i32>` to `i32`.
#[test]
fn green_test_no_unnecessary_wraps_lint_after_fix() {
    let mut cmd = Command::new("cargo");
    cmd.arg("clippy")
        .arg("-p")
        .arg("diffguard")
        .arg("--")
        .arg("-W")
        .arg("clippy::unnecessary_wraps")
        .current_dir("/home/hermes/repos/diffguard");

    let output = cmd.output().expect("clippy should run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}\n{}", stdout, stderr);

    assert!(
        !combined.contains("unnecessary_wraps"),
        "clippy should NOT report unnecessary_wraps lint after fix.\n\
         The cmd_doctor function should return i32, not Result<i32>.\n\
         clippy output:\n{}",
        combined
    );
}

/// Verify that `cmd_doctor` output mentions all three checks:
/// git availability, git repository, and config validation.
#[test]
fn green_test_doctor_reports_all_three_checks() {
    let td = TempDir::new().expect("temp dir");

    std::process::Command::new("git")
        .current_dir(td.path())
        .args(["init"])
        .output()
        .expect("git init should work");

    std::process::Command::new("git")
        .current_dir(td.path())
        .args(["config", "user.email", "test@test.com"])
        .output()
        .expect("git config should work");

    std::process::Command::new("git")
        .current_dir(td.path())
        .args(["config", "user.name", "Test"])
        .output()
        .expect("git config should work");

    let config_path = td.path().join("diffguard.toml");
    std::fs::write(&config_path, "[]").expect("write config");

    let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
    cmd.current_dir(td.path())
        .arg("doctor")
        .arg("--config")
        .arg(config_path.to_str().unwrap());

    let output = cmd.output().expect("doctor command should run");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // All three checks should be reported
    assert!(
        stdout.contains("git") && stdout.contains("git-repo") && stdout.contains("config"),
        "doctor output should mention all three checks.\n\
         Got:\n{}",
        stdout
    );
}
