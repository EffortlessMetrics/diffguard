//! Tests for the `bool` debug artifact gitignore entry.
//!
//! These tests verify the repository hygiene fix for orphaned debug artifact
//! `bool` files in the repository root. The fix ensures `bool` files are
//! gitignored so they don't clutter `git status` output.
//!
//! Issue: #507 (duplicate of #508, fixed in #509)
//! PR: #509
//! Commit: a3aa613

use std::path::{Path, PathBuf};
use std::process::Command;

/// Get the repository root directory by running `git rev-parse --show-toplevel`.
fn get_repo_root() -> PathBuf {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .expect("git rev-parse should execute")
        .stdout;
    PathBuf::from(String::from_utf8_lossy(&output).trim().to_string())
}

/// Test that the `bool` file entry exists in `.gitignore` under the
/// `# Debug/test artifacts` section.
#[test]
fn test_bool_entry_exists_in_gitignore() {
    let repo_root = get_repo_root();
    let gitignore_path = repo_root.join(".gitignore");
    assert!(
        gitignore_path.exists(),
        ".gitignore file must exist in repository root at {:?}",
        gitignore_path
    );

    let content = std::fs::read_to_string(&gitignore_path).expect(".gitignore should be readable");

    // Check that "bool" appears in .gitignore
    assert!(
        content.contains("bool"),
        ".gitignore must contain 'bool' entry to prevent debug artifact commits"
    );

    // Verify it's in the Debug/test artifacts section
    let lines: Vec<&str> = content.lines().collect();
    let mut found_debug_section = false;
    let mut found_bool_in_section = false;

    for line in lines {
        let trimmed = line.trim();
        if trimmed == "# Debug/test artifacts" {
            found_debug_section = true;
        } else if found_debug_section && trimmed == "bool" {
            found_bool_in_section = true;
            break;
        } else if trimmed.starts_with('#') || trimmed.is_empty() {
            // Continue scanning
        } else if found_debug_section && !trimmed.is_empty() {
            // We've passed the debug section into other content
            break;
        }
    }

    assert!(
        found_debug_section,
        ".gitignore must have a '# Debug/test artifacts' section"
    );
    assert!(
        found_bool_in_section,
        "'bool' must appear under the '# Debug/test artifacts' section in .gitignore"
    );
}

/// Test that git correctly ignores a `bool` file in the repository root.
#[test]
fn test_git_ignores_bool_file() {
    // Use git check-ignore to verify bool is ignored
    let output = Command::new("git")
        .args(["check-ignore", "-v", "bool"])
        .output()
        .expect("git check-ignore should execute");

    assert!(
        output.status.success(),
        "git check-ignore -v bool should succeed for ignored files"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Output format is: .gitignore:27:bool\tbool
    assert!(
        stdout.contains(".gitignore"),
        "git check-ignore output should reference .gitignore, got stdout: {}, stderr: {}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("bool"),
        "git check-ignore output should contain 'bool', got stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

/// Test that no `bool` file exists in the repository working tree.
#[test]
fn test_no_bool_file_in_repository() {
    let output = Command::new("find")
        .args([".", "-name", "bool", "-type", "f"])
        .current_dir(Path::new("."))
        .output()
        .expect("find command should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // find returns empty stdout (just newline) when no files match
    // Non-empty stdout means a bool file was found
    let trimmed = stdout.trim();
    assert!(
        trimmed.is_empty(),
        "No 'bool' file should exist in repository, but found: {} (stderr: {})",
        stdout,
        stderr
    );
}

/// Test that `bool` does not appear in `git status --porcelain` as untracked.
#[test]
fn test_bool_not_in_git_status() {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .expect("git status should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Filter for untracked files only (lines starting with ??)
    let untracked_lines: Vec<&str> = stdout
        .lines()
        .filter(|line| line.starts_with("??"))
        .collect();

    for line in untracked_lines {
        let path = line.trim_start_matches("?? ").trim();
        assert!(
            !path.ends_with("bool") && !path.contains("/bool"),
            "git status should not show 'bool' as untracked, but found: {} (stderr: {})",
            line,
            stderr
        );
    }
}
