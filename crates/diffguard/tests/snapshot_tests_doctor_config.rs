//! Snapshot tests for `diffguard doctor` subcommand config validation output.
//!
//! These tests capture the exact stdout output from `validate_config_for_doctor`
//! through the CLI interface, verifying the structured output format.
//!
//! Run with: cargo insta test -p diffguard --include-ignored
//! Review snapshots with: cargo insta review -p diffguard

use assert_cmd::Command;
use assert_cmd::cargo;
use tempfile::TempDir;

fn diffguard_cmd() -> Command {
    Command::new(cargo::cargo_bin!("diffguard"))
}

/// Create a git repo in a temp directory for testing
fn init_git_repo() -> TempDir {
    let td = TempDir::new().expect("temp dir");

    // Initialize git repo
    let mut cmd = std::process::Command::new("git");
    cmd.current_dir(td.path())
        .args(["init", "--initial-branch=main"]);
    cmd.output().expect("git init should work");

    // Set git user config so git commands don't fail
    let mut cmd = std::process::Command::new("git");
    cmd.current_dir(td.path())
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .args(["config", "user.email", "test@test.com"])
        .args(["config", "user.name", "test"]);
    cmd.output().expect("git config should work");

    // Create initial commit
    let mut cmd = std::process::Command::new("git");
    cmd.current_dir(td.path())
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@test.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@test.com")
        .args(["commit", "--allow-empty", "-m", "initial"]);
    cmd.output().expect("git commit should work");

    td
}

/// Run diffguard doctor and return stdout
fn run_doctor_capture_stdout(dir: &std::path::Path) -> String {
    let output = diffguard_cmd()
        .current_dir(dir)
        .arg("doctor")
        .output()
        .expect("doctor command should run");
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Snapshot test: doctor with no config file outputs "config: PASS (using defaults)"
///
/// Input: Running `doctor` in a git repo with no diffguard.toml present
/// Expected output: Line containing "config: PASS (using defaults)"
#[test]
fn snapshot_doctor_no_config_outputs_pass_using_defaults() {
    let td = init_git_repo();
    let stdout = run_doctor_capture_stdout(td.path());

    // Extract just the config validation line
    let config_line: String = stdout
        .lines()
        .find(|line| line.starts_with("config:"))
        .unwrap_or_default()
        .to_string();

    insta::assert_snapshot!("config_no_config_pass_using_defaults", config_line);
}

/// Snapshot test: doctor with explicit --config pointing to nonexistent file outputs failure
///
/// Input: Running `doctor --config nonexistent.toml` in a git repo
/// Expected output: Line containing "config: FAIL (config file not found)"
#[test]
fn snapshot_doctor_explicit_config_missing_file() {
    let td = init_git_repo();

    let output = diffguard_cmd()
        .current_dir(td.path())
        .arg("doctor")
        .arg("--config")
        .arg("nonexistent.toml")
        .output()
        .expect("doctor command should run");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Extract just the config validation line
    let config_line: String = stdout
        .lines()
        .find(|line| line.starts_with("config:"))
        .unwrap_or_default()
        .to_string();

    insta::assert_snapshot!("config_explicit_missing_file", config_line);
}

/// Snapshot test: doctor with empty but valid config file
///
/// Input: Running `doctor` with an empty diffguard.toml file
/// Expected output: "config: PASS" (empty rules array is valid)
#[test]
fn snapshot_doctor_empty_config_passes() {
    let td = init_git_repo();
    std::fs::write(td.path().join("diffguard.toml"), "rules = []").expect("write config");

    let stdout = run_doctor_capture_stdout(td.path());

    // Extract just the config validation line
    let config_line: String = stdout
        .lines()
        .find(|line| line.starts_with("config:"))
        .unwrap_or_default()
        .to_string();

    insta::assert_snapshot!("config_empty_rules_pass", config_line);
}

/// Snapshot test: doctor with invalid TOML (malformed syntax)
///
/// Input: Running `doctor` with a malformed diffguard.toml file
/// Expected output: Line containing "config: FAIL" with TOML parse error
#[test]
fn snapshot_doctor_invalid_toml_fails() {
    let td = init_git_repo();
    std::fs::write(
        td.path().join("diffguard.toml"),
        "this is { not valid [ toml",
    )
    .expect("write config");

    let stdout = run_doctor_capture_stdout(td.path());

    // Extract just the config validation line
    let config_line: String = stdout
        .lines()
        .find(|line| line.starts_with("config:"))
        .unwrap_or_default()
        .to_string();

    insta::assert_snapshot!("config_invalid_toml_fails", config_line);
}

/// Snapshot test: doctor with valid minimal config
///
/// Input: Running `doctor` with a valid minimal diffguard.toml
/// Expected output: "config: PASS"
#[test]
fn snapshot_doctor_valid_minimal_config_passes() {
    let td = init_git_repo();
    let config = r#"
[[rules]]
id = "test.no_todo"
message = "No TODOs"
patterns = ["TODO"]
"#;
    std::fs::write(td.path().join("diffguard.toml"), config).expect("write config");

    let stdout = run_doctor_capture_stdout(td.path());

    // Extract just the config validation line
    let config_line: String = stdout
        .lines()
        .find(|line| line.starts_with("config:"))
        .unwrap_or_default()
        .to_string();

    insta::assert_snapshot!("config_valid_minimal_pass", config_line);
}
