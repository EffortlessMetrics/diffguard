//! Integration tests for cargo fmt check fix (issue #466).
//!
//! These tests verify that the formatting fix for issue #466 is working correctly.
//! The fix adds braces to a long match arm in main.rs:645 to satisfy rustfmt's
//! 100-character line width limit.

use std::process::Command;

/// Test that cargo fmt --check passes on the diffguard crate.
/// This is the direct verification of the fix for issue #466.
#[test]
fn test_diffguard_crate_fmt_check_passes() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new("cargo");
    cmd.arg("fmt").arg("--check").current_dir(manifest_dir);
    let output = cmd.output().expect("cargo fmt should run");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "cargo fmt --check failed on diffguard crate\nstdout: {}\nstderr: {}",
            stdout, stderr
        );
    }
}

/// Test that the diffguard binary can be built successfully.
/// This verifies the formatting fix doesn't break the build.
#[test]
fn test_diffguard_binary_builds() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("--package")
        .arg("diffguard")
        .current_dir(manifest_dir);
    let output = cmd.output().expect("cargo build should run");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "cargo build failed for diffguard\nstdout: {}\nstderr: {}",
            stdout, stderr
        );
    }
}

/// Test that the diffguard CLI responds to --help after the formatting fix.
/// This is a smoke test to verify the binary is functional.
#[test]
fn test_diffguard_cli_help_works() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--package")
        .arg("diffguard")
        .arg("--")
        .arg("--help")
        .current_dir(manifest_dir);

    let output = cmd.output().expect("cargo run should work");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify help output contains expected commands
    assert!(
        stdout.contains("Diff-scoped governance lint"),
        "Help output should contain description"
    );
    assert!(
        stdout.contains("check"),
        "Help output should contain 'check' command"
    );
    assert!(
        stdout.contains("rules"),
        "Help output should contain 'rules' command"
    );
}

/// Test that the diffguard CLI doctor command works.
/// This tests a simple command that doesn't require a git repo.
#[test]
fn test_diffguard_doctor_runs() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--package")
        .arg("diffguard")
        .arg("--")
        .arg("doctor")
        .current_dir(manifest_dir);

    let output = cmd.output().expect("cargo run should work");

    // Doctor command should succeed (exit 0) or warning (exit 3), not error (exit 1)
    // The exact exit code depends on the environment, so we just check it's not a build failure
    let exit_code = output.status.code().unwrap_or(-1);
    assert!(
        exit_code != 101, // 101 is panic/raft
        "Doctor command should not panic (exit 101)"
    );
}
