//! Snapshot tests for `diffguard doctor` command output.
//!
//! These tests capture the console output of the `doctor` subcommand
//! for various scenarios. Any change to the output format will be
//! detected immediately.
//!
//! Snapshots captured:
//! 1. All checks pass (git repo with valid config)
//! 2. Not in git repository (git-repo check fails)
//! 3. Config file invalid (TOML parsing error)
//! 4. Explicit config file missing
//! 5. Valid config with --config flag

use assert_cmd::Command;
use assert_cmd::cargo;
use regex::Regex;
use tempfile::TempDir;

fn diffguard_cmd() -> Command {
    Command::new(cargo::cargo_bin!("diffguard"))
}

fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("git should run");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_git_repo() -> TempDir {
    let td = TempDir::new().expect("temp");
    let dir = td.path();
    run_git(dir, &["init"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Test"]);
    td
}

fn write_config(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
    let path = dir.join("diffguard.toml");
    std::fs::write(&path, contents).expect("write config");
    path
}

/// Normalize git version string since it varies by installation.
fn normalize_git_version(output: &str) -> String {
    let re = Regex::new(r"git: PASS \(git version [^)]+\)").unwrap();
    re.replace_all(output, "git: PASS (git version X.XX.X)").to_string()
}

/// Snapshot test: doctor with all checks passing.
/// This captures the happy-path output when git is available,
/// we're in a git repo, and a valid config exists.
#[test]
fn snapshot_doctor_all_pass() {
    let td = init_git_repo();
    let dir = td.path();

    let _config_path = write_config(
        dir,
        r#"
[[rules]]
id = "test.no_todo"
description = "No TODOs"
severity = "warn"
match = "TODO"
"#,
    );

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir).arg("doctor");

    let output = cmd.output().expect("doctor should run");
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let normalized_stdout = normalize_git_version(&stdout);

    insta::assert_snapshot!(
        "snapshot_doctor_all_pass",
        format!(
            "exit_code={:?}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
            exit_code, normalized_stdout, stderr
        )
    );
}

/// Snapshot test: doctor when not in a git repository.
/// This captures the output when git-repo check fails.
#[test]
fn snapshot_doctor_not_in_git_repo() {
    let td = TempDir::new().expect("temp");

    let mut cmd = diffguard_cmd();
    cmd.current_dir(td.path()).arg("doctor");

    let output = cmd.output().expect("doctor should run");
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let normalized_stdout = normalize_git_version(&stdout);

    insta::assert_snapshot!(
        "snapshot_doctor_not_in_git_repo",
        format!(
            "exit_code={:?}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
            exit_code, normalized_stdout, stderr
        )
    );
}

/// Snapshot test: doctor with invalid config file.
/// This captures the output when the TOML file has parsing errors.
#[test]
fn snapshot_doctor_invalid_config() {
    let td = init_git_repo();
    let dir = td.path();

    // Invalid TOML: [[rule]] instead of [[rules]]
    let _config_path = write_config(
        dir,
        r#"
[[rule]]
id = "test.bad"
description = "Bad"
severity = "error"
match = "[invalid(regex"
"#,
    );

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir).arg("doctor");

    let output = cmd.output().expect("doctor should run");
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let normalized_stdout = normalize_git_version(&stdout);

    insta::assert_snapshot!(
        "snapshot_doctor_invalid_config",
        format!(
            "exit_code={:?}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
            exit_code, normalized_stdout, stderr
        )
    );
}

/// Snapshot test: doctor with explicit --config pointing to missing file.
/// This captures the output when user specifies a non-existent config.
#[test]
fn snapshot_doctor_missing_config() {
    let td = init_git_repo();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(td.path())
        .arg("doctor")
        .arg("--config")
        .arg("nonexistent.toml");

    let output = cmd.output().expect("doctor should run");
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let normalized_stdout = normalize_git_version(&stdout);

    insta::assert_snapshot!(
        "snapshot_doctor_missing_config",
        format!(
            "exit_code={:?}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
            exit_code, normalized_stdout, stderr
        )
    );
}

/// Snapshot test: doctor with valid config via --config flag.
/// This captures output when using explicit --config with valid file.
#[test]
fn snapshot_doctor_valid_config_explicit() {
    let td = init_git_repo();
    let dir = td.path();

    let config_path = dir.join("custom.toml");
    std::fs::write(
        &config_path,
        r#"
[[rules]]
id = "custom.rule"
description = "Custom rule"
severity = "warn"
match = "breakpoint"
"#,
    )
    .unwrap();

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir)
        .arg("doctor")
        .arg("--config")
        .arg("custom.toml");

    let output = cmd.output().expect("doctor should run");
    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let normalized_stdout = normalize_git_version(&stdout);

    insta::assert_snapshot!(
        "snapshot_doctor_valid_config_explicit",
        format!(
            "exit_code={:?}\n\nSTDOUT:\n{}\n\nSTDERR:\n{}",
            exit_code, normalized_stdout, stderr
        )
    );
}