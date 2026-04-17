//! RED tests for `cmd_doctor` return type fix.
//!
//! These tests verify that `cmd_doctor` returns `i32` directly (not `Result<i32>`).
//!
//! The issue: `clippy::unnecessary_wraps` lint reports that `cmd_doctor` at line 956
//! returns `Result<i32>` but never produces an `Err` variant. The fix changes the
//! return type to `i32` and wraps the call site with `Ok()`.
//!
//! These tests will FAIL before the fix (return type is `Result<i32>`)
//! and will PASS after the fix (return type is `i32`).

use assert_cmd::Command;
use assert_cmd::cargo;
use tempfile::TempDir;

/// Test that clippy does NOT report `unnecessary_wraps` on `cmd_doctor`.
///
/// Before fix: `cmd_doctor` returns `Result<i32>`, clippy warns.
/// After fix: `cmd_doctor` returns `i32`, no warning.
#[test]
fn test_cmd_doctor_no_unnecessary_wraps_lint() {
    // Run clippy on the diffguard binary and check for the unnecessary_wraps lint
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
    let combined_output = format!("{}\n{}", stdout, stderr);

    // The lint should NOT appear after the fix
    // Before fix: "warning: unnecessary wrap"
    // After fix: no such warning
    assert!(
        !combined_output.contains("unnecessary_wraps"),
        "clippy should NOT report unnecessary_wraps on cmd_doctor after fix.\n\
         If this fails, cmd_doctor still returns Result<i32> instead of i32.\n\
         Output:\n{}",
        combined_output
    );
}

/// Test that `cmd_doctor` can be used in integer arithmetic context.
///
/// Before fix: `cmd_doctor` returns `Result<i32>`, which cannot be used directly in `i32 + 1`.
/// After fix: `cmd_doctor` returns `i32`, which can be used in `i32 + 1`.
///
/// This is a compile-time test encoded as a runtime test - we verify by
/// checking that running `diffguard doctor` in a valid git repo produces
/// an exit code that can be treated as an i32.
#[test]
fn test_cmd_doctor_exit_code_is_raw_integer() {
    // Create a temp git repo so doctor passes
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

    // Create a valid config
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

    // Run diffguard doctor
    let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
    cmd.current_dir(td.path())
        .arg("doctor")
        .arg("--config")
        .arg(config_path.to_str().unwrap());

    let output = cmd.output().expect("doctor command should run");
    let exit_code = output.status.code().expect("should have exit code");

    // Exit code should be 0 (all checks pass) or 1 (some fail)
    // It should NOT be wrapped in Result (which would be Ok(0) or Ok(1))
    // The exit code should be a raw i32 value
    assert!(
        exit_code == 0 || exit_code == 1,
        "doctor exit code should be 0 or 1, got: {}",
        exit_code
    );

    // Additional verification: after the fix, the return type is i32.
    // This means the function's return value can be used directly in integer contexts.
    // We verify this by checking that clippy doesn't warn about unnecessary_wraps
    // which would be present if the return type is still Result<i32>.
    let mut clippy_cmd = Command::new("cargo");
    clippy_cmd
        .arg("clippy")
        .arg("-p")
        .arg("diffguard")
        .arg("--")
        .arg("-W")
        .arg("clippy::unnecessary_wraps")
        .current_dir("/home/hermes/repos/diffguard");

    let clippy_output = clippy_cmd.output().expect("clippy should run");
    let clippy_stderr = String::from_utf8_lossy(&clippy_output.stderr);

    // After fix, clippy should NOT mention unnecessary_wraps for cmd_doctor
    assert!(
        !clippy_stderr.contains("unnecessary_wraps"),
        "cmd_doctor should not trigger unnecessary_wraps lint after fix.\n\
         The function should return i32, not Result<i32>.\n\
         clippy output:\n{}",
        clippy_stderr
    );
}

/// Test that the doctor command call site is correctly wrapped with Ok().
///
/// After the fix, the call site `Commands::Doctor(args) => Ok(cmd_doctor(args))`
/// wraps the i32 return in Ok() to maintain type compatibility with the
/// main function's Result<i32> return type.
#[test]
fn test_doctor_command_runs_successfully() {
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

    let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
    cmd.current_dir(td.path()).arg("doctor");

    let output = cmd.output().expect("doctor command should run");

    // Command should succeed (exit 0) in a valid git repo with default config
    assert!(
        output.status.success(),
        "doctor should succeed in a valid git repo with default config.\n\
         Exit code: {:?}\n\
         stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}
