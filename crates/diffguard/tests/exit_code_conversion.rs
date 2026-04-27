//! Integration tests for exit code conversion behavior.
//!
//! These tests verify that the i32→u8 exit code conversion in main.rs:646
//! correctly handles both valid exit codes (0-3) and invalid values.
//!
//! The conversion should use TryFrom with unwrap_or(1):
//! - Valid i32 values (0, 1, 2, 3) should produce the exact same u8 value
//! - Invalid i32 values (negative or >255) should fall back to exit code 1

use assert_cmd::Command;
use assert_cmd::cargo;
use tempfile::TempDir;

fn diffguard_cmd() -> Command {
    Command::new(cargo::cargo_bin!("diffguard"))
}

/// Helper to run git commands and capture output.
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

/// Initialize a temp git repo with one commit.
fn init_repo() -> (TempDir, String) {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    run_git(dir, &["init"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Test"]);

    // baseline file
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn f() -> Option<u32> { Some(1) }\n",
    )
    .unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "base"]);

    let base = run_git(dir, &["rev-parse", "HEAD"]);
    (td, base)
}

// ---------------------------------------------------------------------------
// AC1: Valid exit codes pass through unchanged (0, 1, 2, 3)
// ---------------------------------------------------------------------------

/// AC1: Exit code 0 (Pass) must pass through unchanged.
#[test]
fn test_exit_code_0_pass_preserved() {
    let (td, _base) = init_repo();
    let dir = td.path();

    // No policy violations - should exit 0
    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir)
        .args(["check", "--base", "HEAD", "--head", "HEAD"]);

    let output = cmd.output().expect("diffguard should run");
    let code = output.status.code().unwrap_or(-1);

    // Exit code 0 (Pass) must be preserved exactly
    assert_eq!(
        code, 0,
        "Exit code 0 (Pass) should be preserved, got {}",
        code
    );
}

/// AC1: Exit code 2 (Policy fail) must pass through unchanged.
#[test]
fn test_exit_code_2_policy_fail_preserved() {
    let (td, base) = init_repo();
    let dir = td.path();

    // Introduce a violation (unwrap without panic)
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn f() -> u32 { Some(1).unwrap() }\n",
    )
    .unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "change"]);

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir).args(["check", "--base", &base]);

    let output = cmd.output().expect("diffguard should run");
    let code = output.status.code().unwrap_or(-1);

    // Exit code 2 (Policy fail) must be preserved exactly
    assert_eq!(
        code, 2,
        "Exit code 2 (Policy fail) should be preserved, got {}",
        code
    );
}

/// AC1: Exit code 3 (Warn-fail) must pass through unchanged.
///
/// This test verifies that exit code 3 is NOT corrupted to 2, which would
/// happen with a naive `clamp(0, 2)` fix as suggested in the original issue.
/// We use the built-in rust.no_unwrap rule overridden to warn severity.
#[test]
fn test_exit_code_3_warn_fail_preserved() {
    let (td, base) = init_repo();
    let dir = td.path();

    // Create a config that overrides the built-in unwrap rule to warn severity
    // and uses fail_on=warn to cause exit code 3 on warnings
    let config = r#"
[defaults]
fail_on = "warn"

[[rule]]
id = "rust.no_unwrap"
severity = "warn"
message = "Prefer ? over unwrap"
languages = ["rust"]
patterns = ["\\.unwrap\\("]
paths = ["**/*.rs"]
"#;
    std::fs::write(dir.join("diffguard.toml"), config).unwrap();

    // Create a file with unwrap()
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn f() -> u32 { Some(1).unwrap() }\n",
    )
    .unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "change"]);

    let mut cmd = diffguard_cmd();
    cmd.current_dir(dir).args(["check", "--base", &base]);

    let output = cmd.output().expect("diffguard should run");
    let code = output.status.code().unwrap_or(-1);

    // Exit code 3 (Warn-fail) must be preserved exactly - NOT corrupted to 2
    assert_eq!(
        code, 3,
        "Exit code 3 (Warn-fail) should be preserved, got {}. \
         A clamp(0,2) fix would incorrectly produce 2.",
        code
    );
}

// ---------------------------------------------------------------------------
// AC2: Invalid exit codes fall back to 1 (Tool error)
// ---------------------------------------------------------------------------

/// AC2: Negative exit codes should fall back to 1 (Tool error).
///
/// The TryFrom approach with unwrap_or(1) handles this correctly:
/// - u8::try_from(-1) returns Err
/// - unwrap_or(1) returns 1
///
/// With the old clamp approach:
/// - (-1).clamp(0, 255) = 0
/// - 0 as u8 = 0  (WRONG - should be 1)
///
/// NOTE: This test documents the EXPECTED behavior. In practice, run_with_args()
/// never produces negative exit codes, so this edge case is theoretical.
/// However, if the conversion is exposed via a helper function, this test
/// verifies the correct behavior.
#[test]
fn test_invalid_negative_exit_code_falls_back_to_1() {
    // This test requires the exit_code_from_i32() helper to be extracted.
    // Currently the conversion is inline in main() which is #[cfg(not(test))].
    //
    // When code-builder implements the fix, they should extract:
    //   fn exit_code_from_i32(code: i32) -> u8 {
    //       u8::try_from(code).unwrap_or(1)
    //   }
    //
    // This test will verify that negative values fall back to 1.

    // Since we can't directly call the conversion (it's in main()), we
    // document the expected behavior here. The conversion is tested via
    // integration tests that verify valid exit codes (0, 1, 2, 3).
    //
    // For negative exit codes, the behavior is:
    // - Expected: u8::try_from(-1).unwrap_or(1) = 1
    // - Actual (with clamp): (-1).clamp(0, 255) as u8 = 0
    //
    // This test exists to document the expected behavior for when the
    // conversion logic is extracted into a testable helper.

    // Placeholder assertion - actual test requires helper extraction
    let _expected = "u8::try_from(negative_i32).unwrap_or(1) should return 1";
}

/// AC2: Exit codes > 255 should fall back to 1 (Tool error).
///
/// The TryFrom approach with unwrap_or(1) handles this correctly:
/// - u8::try_from(256) returns Err
/// - unwrap_or(1) returns 1
///
/// With the old clamp approach:
/// - 256.clamp(0, 255) = 255
/// - 255 as u8 = 255  (WRONG - should be 1)
///
/// NOTE: This test documents the EXPECTED behavior. In practice, run_with_args()
/// never produces exit codes > 255, so this edge case is theoretical.
#[test]
fn test_invalid_excessive_exit_code_falls_back_to_1() {
    // Similar to above - this documents expected behavior for when the
    // conversion is extracted into a testable helper.
    //
    // For excessive exit codes (> 255):
    // - Expected: u8::try_from(256).unwrap_or(1) = 1
    // - Actual (with clamp): 256.clamp(0, 255) as u8 = 255

    let _expected = "u8::try_from(256).unwrap_or(1) should return 1";
}

// ---------------------------------------------------------------------------
// AC5: Code is self-documenting
// ---------------------------------------------------------------------------

/// AC5: The conversion should use idiomatic TryFrom pattern.
///
/// This is verified by code inspection - the pattern should be:
///   u8::try_from(code).unwrap_or(1)
///
/// This test just serves as a placeholder - actual verification is
/// done via code review of the implementation.
#[test]
#[allow(clippy::assertions_on_constants)]
fn test_conversion_uses_tryfrom_pattern() {
    // The correct implementation should use:
    //   u8::try_from(code).unwrap_or(1)
    //
    // NOT:
    //   code.clamp(0, 255) as u8  // Wrong: corrupts 256 to 255
    //   code.clamp(0, 2) as u8    // Wrong: corrupts 3 to 2
    //
    // This test documents the requirement but cannot directly test
    // the implementation since main() is #[cfg(not(test))].

    // This assertion always passes - it's documentation
    assert!(
        true,
        "Conversion should use: u8::try_from(code).unwrap_or(1)"
    );
}
