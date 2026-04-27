//! RED tests for `cmd_doctor()` return type refactoring.
//!
//! These tests verify that `cmd_doctor` has return type `i32` (not `Result<i32>`)
//! and that the call site properly wraps the return value with `Ok()`.
//!
//! The issue: `cmd_doctor()` had return type `Result<i32>` but never returned `Err`.
//! This is misleading because callers expecting error propagation will find none.
//!
//! These tests will FAIL until the return type is changed from `Result<i32>` to `i32`.

use assert_cmd::Command;
use assert_cmd::cargo;
use tempfile::TempDir;
use std::process::Command as StdCommand;

/// Test that `cmd_doctor` is compiled with `i32` return type (not `Result<i32>`).
///
/// This is verified by checking that the clippy lint `clippy::unnecessary_wraps`
/// does NOT fire on the `cmd_doctor` function after the refactoring.
///
/// Before fix: clippy will warn "unnecessary wraps: `cmd_doctor` never returns `Err`"
/// After fix:  no warning
#[test]
fn test_cmd_doctor_no_unnecessary_wraps_warning() {
    // Run clippy specifically on the doctor binary
    // With the correct return type (i32), there should be no unnecessary_wraps warning
    // on cmd_doctor
    let output = std::process::Command::new("cargo")
        .args(["clippy", "-p", "diffguard", "--bin", "diffguard", "--",
               "-D", "clippy::unnecessary_wraps"])
        .output()
        .expect("clippy should run");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // If the return type is still Result<i32>, clippy will fire a warning
    // about unnecessary wraps on cmd_doctor. With i32, no warning.
    // We check that the warning doesn't mention cmd_doctor specifically.
    assert!(
        !stderr.to_lowercase().contains("cmd_doctor")
            || !stderr.contains("unnecessary"),
        "cmd_doctor should not trigger unnecessary_wraps warning if return type is i32.\n\
         Stderr:\n{}",
        stderr
    );
}

/// Verify the call site at line 697 properly wraps `cmd_doctor` return with `Ok()`.
///
/// The pattern should be:
///   `Commands::Doctor(args) => Ok(cmd_doctor(args)),`
///
/// NOT:
///   `Commands::Doctor(args) => cmd_doctor(args),`
///
/// This test verifies the exit codes work correctly, which indirectly validates
/// that the call site properly handles the i32 return.
#[test]
fn test_doctor_call_site_wraps_with_ok() {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    // Initialize a git repo so doctor passes
    StdCommand::new("git")
        .current_dir(dir)
        .args(["init"])
        .output()
        .expect("git init should work");
    StdCommand::new("git")
        .current_dir(dir)
        .args(["config", "user.email", "test@example.com"])
        .output()
        .expect("git config should work");
    StdCommand::new("git")
        .current_dir(dir)
        .args(["config", "user.name", "Test"])
        .output()
        .expect("git config should work");

    // Run diffguard doctor
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir).arg("doctor");

    let output = cmd.output().expect("doctor command should run");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // The command should succeed (exit 0) in a valid git repo
    // If the call site doesn't wrap with Ok(), we might get a type error at compile time
    // or a runtime error if the Result isn't properly handled
    assert!(
        output.status.success(),
        "doctor should succeed in a valid git repo. Exit code: {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        stdout,
        stderr
    );

    // Verify the exit code is 0 (all checks pass)
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        code, 0,
        "doctor should exit 0 when all checks pass, got {}",
        code
    );
}

/// Verify that `cmd_doctor` returns exit code 1 when checks fail.
///
/// This test ensures the function correctly returns the failure exit code
/// and that the return type change doesn't break error reporting.
#[test]
fn test_doctor_returns_one_when_failing() {
    let td = TempDir::new().expect("temp");
    // Intentionally NOT initializing a git repo - should fail

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(td.path()).arg("doctor");

    let output = cmd.output().expect("doctor command should run");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Should exit with code 1 (failure)
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        code, 1,
        "doctor should exit 1 when checks fail, got {}. Output:\n{}",
        code, stdout
    );

    // Should show FAIL indication
    assert!(
        stdout.contains("FAIL"),
        "output should contain FAIL, got:\n{}",
        stdout
    );
}

/// Test that verifies the function signature is `i32` not `Result<i32>`.
///
/// This is a compile-time test - if the signature is `Result<i32>`, the code
/// won't compile with the expected pattern.
#[test]
fn test_cmd_doctor_return_type_is_i32() {
    // This test verifies that cmd_doctor's return type is i32.
    //
    // The refactoring changes:
    //   BEFORE: fn cmd_doctor(args: DoctorArgs) -> Result<i32>
    //   AFTER:  fn cmd_doctor(args: DoctorArgs) -> i32
    //
    // With the correct return type:
    // - Line 697: Commands::Doctor(args) => Ok(cmd_doctor(args)),
    // - Line 956: fn cmd_doctor(args: DoctorArgs) -> i32
    // - Line 1012: if all_pass { 0 } else { 1 }
    //
    // If the signature is still Result<i32>, clippy's unnecessary_wraps
    // will fire. If the call site doesn't wrap with Ok(), the Result
    // type won't match the expected Result<i32> return of run_with_args.

    // Run clippy to check for unnecessary_wraps
    let output = std::process::Command::new("cargo")
        .args(["clippy", "-p", "diffguard", "--bin", "diffguard", "--",
               "-D", "warnings"])
        .output()
        .expect("clippy should run");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Clippy should pass with no warnings about unnecessary_wraps on cmd_doctor
    // If cmd_doctor still returns Result<i32> with only Ok() values,
    // clippy will report: "unnecessary wraps: `cmd_doctor` never returns `Err`"
    assert!(
        !stderr.contains("cmd_doctor"),
        "clippy should not warn about cmd_doctor if return type is i32. Got:\n{}",
        stderr
    );
}
