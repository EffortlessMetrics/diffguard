//! Test repository helper for BDD integration tests.
//!
//! Provides a `TestRepo` struct that encapsulates creating and manipulating
//! temporary git repositories for testing diffguard CLI scenarios.

#![allow(dead_code)]
#![allow(deprecated)]

use assert_cmd::Command;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// A test git repository for integration testing.
///
/// Provides helpers for:
/// - Creating commits with specific file content
/// - Running diffguard CLI commands
/// - Asserting on exit codes and output
pub struct TestRepo {
    /// The temporary directory containing the repo.
    pub dir: TempDir,
    /// The SHA of the base commit (first commit).
    pub base_sha: String,
}

impl TestRepo {
    /// Create a new empty git repository with an initial commit.
    ///
    /// The initial commit contains a simple baseline file at `src/lib.rs`.
    pub fn new() -> Self {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        // Initialize git repo
        run_git(path, &["init"]);
        run_git(path, &["config", "user.email", "test@example.com"]);
        run_git(path, &["config", "user.name", "Test"]);

        // Create baseline file
        std::fs::create_dir_all(path.join("src")).expect("create src dir");
        std::fs::write(
            path.join("src/lib.rs"),
            "pub fn f() -> Option<u32> { Some(1) }\n",
        )
        .expect("write baseline file");

        run_git(path, &["add", "."]);
        run_git(path, &["commit", "-m", "initial baseline"]);

        let base_sha = run_git(path, &["rev-parse", "HEAD"]);

        Self { dir, base_sha }
    }

    /// Create a new repository with custom initial content.
    pub fn with_initial_content(files: &[(&str, &str)]) -> Self {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        // Initialize git repo
        run_git(path, &["init"]);
        run_git(path, &["config", "user.email", "test@example.com"]);
        run_git(path, &["config", "user.name", "Test"]);

        // Create all files
        for (file_path, content) in files {
            let full_path = path.join(file_path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).expect("create parent dir");
            }
            std::fs::write(&full_path, content).expect("write file");
        }

        run_git(path, &["add", "."]);
        run_git(path, &["commit", "-m", "initial baseline"]);

        let base_sha = run_git(path, &["rev-parse", "HEAD"]);

        Self { dir, base_sha }
    }

    /// Get the path to the repository root.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Write content to a file in the repository.
    pub fn write_file(&self, relative_path: &str, content: &str) {
        let full_path = self.path().join(relative_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(&full_path, content).expect("write file");
    }

    /// Create a new commit with the current changes.
    ///
    /// Returns the SHA of the new commit.
    pub fn commit(&self, message: &str) -> String {
        run_git(self.path(), &["add", "."]);
        run_git(self.path(), &["commit", "-m", message]);
        run_git(self.path(), &["rev-parse", "HEAD"])
    }

    /// Create a config file in the repository.
    pub fn write_config(&self, content: &str) {
        self.write_file("diffguard.toml", content);
    }

    /// Run diffguard check command and return the result.
    pub fn run_check(&self, head_sha: &str) -> DiffguardResult {
        self.run_check_with_args(head_sha, &[])
    }

    /// Run diffguard check command with additional arguments.
    pub fn run_check_with_args(&self, head_sha: &str, extra_args: &[&str]) -> DiffguardResult {
        let out_path = self.path().join("artifacts/diffguard/report.json");

        let mut cmd = Command::cargo_bin("diffguard").expect("diffguard binary");
        cmd.current_dir(self.path())
            .arg("check")
            .arg("--base")
            .arg(&self.base_sha)
            .arg("--head")
            .arg(head_sha)
            .arg("--out")
            .arg(&out_path);

        for arg in extra_args {
            cmd.arg(arg);
        }

        let output = cmd.output().expect("run diffguard");

        let receipt = if out_path.exists() {
            Some(std::fs::read_to_string(&out_path).expect("read receipt"))
        } else {
            None
        };

        DiffguardResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            receipt,
            output_path: out_path,
        }
    }

    /// Run diffguard check with a custom config file.
    pub fn run_check_with_config(&self, head_sha: &str, config_path: &str) -> DiffguardResult {
        let out_path = self.path().join("artifacts/diffguard/report.json");

        let mut cmd = Command::cargo_bin("diffguard").expect("diffguard binary");
        cmd.current_dir(self.path())
            .arg("check")
            .arg("--base")
            .arg(&self.base_sha)
            .arg("--head")
            .arg(head_sha)
            .arg("--config")
            .arg(config_path)
            .arg("--out")
            .arg(&out_path);

        let output = cmd.output().expect("run diffguard");

        let receipt = if out_path.exists() {
            Some(std::fs::read_to_string(&out_path).expect("read receipt"))
        } else {
            None
        };

        DiffguardResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            receipt,
            output_path: out_path,
        }
    }

    /// Run git command that should fail (e.g., for testing missing refs).
    pub fn run_check_with_invalid_base(
        &self,
        head_sha: &str,
        invalid_base: &str,
    ) -> DiffguardResult {
        let out_path = self.path().join("artifacts/diffguard/report.json");

        let mut cmd = Command::cargo_bin("diffguard").expect("diffguard binary");
        cmd.current_dir(self.path())
            .arg("check")
            .arg("--base")
            .arg(invalid_base)
            .arg("--head")
            .arg(head_sha)
            .arg("--out")
            .arg(&out_path);

        let output = cmd.output().expect("run diffguard");

        let receipt = if out_path.exists() {
            Some(std::fs::read_to_string(&out_path).expect("read receipt"))
        } else {
            None
        };

        DiffguardResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            receipt,
            output_path: out_path,
        }
    }
}

/// The result of running a diffguard command.
#[derive(Debug)]
pub struct DiffguardResult {
    /// The exit code of the process.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
    /// The JSON receipt content (if written).
    pub receipt: Option<String>,
    /// Path where the receipt was written.
    pub output_path: PathBuf,
}

impl DiffguardResult {
    /// Assert that the exit code matches expected.
    pub fn assert_exit_code(&self, expected: i32) -> &Self {
        assert_eq!(
            self.exit_code, expected,
            "Expected exit code {} but got {}.\nstderr: {}\nstdout: {}",
            expected, self.exit_code, self.stderr, self.stdout
        );
        self
    }

    /// Assert that a receipt was written.
    pub fn assert_receipt_exists(&self) -> &Self {
        assert!(
            self.receipt.is_some(),
            "Expected receipt to be written at {:?}",
            self.output_path
        );
        self
    }

    /// Assert that the receipt contains the given string.
    pub fn assert_receipt_contains(&self, needle: &str) -> &Self {
        let receipt = self.receipt.as_ref().expect("receipt should exist");
        assert!(
            receipt.contains(needle),
            "Expected receipt to contain '{}', but it didn't.\nReceipt: {}",
            needle,
            receipt
        );
        self
    }

    /// Assert that the receipt does not contain the given string.
    pub fn assert_receipt_not_contains(&self, needle: &str) -> &Self {
        let receipt = self.receipt.as_ref().expect("receipt should exist");
        assert!(
            !receipt.contains(needle),
            "Expected receipt NOT to contain '{}', but it did.\nReceipt: {}",
            needle,
            receipt
        );
        self
    }

    /// Assert that stderr contains the given string.
    pub fn assert_stderr_contains(&self, needle: &str) -> &Self {
        assert!(
            self.stderr.contains(needle),
            "Expected stderr to contain '{}', but it didn't.\nstderr: {}",
            needle,
            self.stderr
        );
        self
    }

    /// Parse the receipt as JSON and return a parsed receipt.
    pub fn parse_receipt(&self) -> ParsedReceipt {
        let receipt = self.receipt.as_ref().expect("receipt should exist");
        let json: serde_json::Value =
            serde_json::from_str(receipt).expect("receipt should be valid JSON");
        ParsedReceipt { json }
    }
}

/// A parsed JSON receipt for detailed assertions.
pub struct ParsedReceipt {
    json: serde_json::Value,
}

impl ParsedReceipt {
    /// Get the number of findings in the receipt.
    pub fn findings_count(&self) -> usize {
        self.json["findings"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0)
    }

    /// Get the total count from verdict (info + warn + error).
    pub fn total_count(&self) -> u64 {
        let counts = &self.json["verdict"]["counts"];
        counts["info"].as_u64().unwrap_or(0)
            + counts["warn"].as_u64().unwrap_or(0)
            + counts["error"].as_u64().unwrap_or(0)
    }

    /// Get the error count from verdict.
    pub fn error_count(&self) -> u64 {
        self.json["verdict"]["counts"]["error"]
            .as_u64()
            .unwrap_or(0)
    }

    /// Get the warning count from verdict.
    pub fn warn_count(&self) -> u64 {
        self.json["verdict"]["counts"]["warn"].as_u64().unwrap_or(0)
    }

    /// Check if a specific rule ID appears in the findings.
    pub fn has_finding_with_rule(&self, rule_id: &str) -> bool {
        self.json["findings"]
            .as_array()
            .map(|findings| {
                findings
                    .iter()
                    .any(|f| f["rule_id"].as_str() == Some(rule_id))
            })
            .unwrap_or(false)
    }

    /// Check if a finding exists for a specific file and line.
    pub fn has_finding_at(&self, path: &str, line: u32) -> bool {
        self.json["findings"]
            .as_array()
            .map(|findings| {
                findings.iter().any(|f| {
                    f["path"].as_str() == Some(path) && f["line"].as_u64() == Some(line as u64)
                })
            })
            .unwrap_or(false)
    }

    /// Get the verdict status.
    pub fn verdict_status(&self) -> Option<&str> {
        self.json["verdict"]["status"].as_str()
    }

    /// Get all finding rule IDs.
    pub fn finding_rule_ids(&self) -> Vec<String> {
        self.json["findings"]
            .as_array()
            .map(|findings| {
                findings
                    .iter()
                    .filter_map(|f| f["rule_id"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Run a git command and return the trimmed stdout.
fn run_git(dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("git command should run");

    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repo_creates_valid_git_repo() {
        let repo = TestRepo::new();
        assert!(repo.path().join(".git").exists());
        assert!(!repo.base_sha.is_empty());
    }

    #[test]
    fn test_repo_can_write_and_commit() {
        let repo = TestRepo::new();
        repo.write_file("new_file.txt", "content");
        let new_sha = repo.commit("add new file");
        assert_ne!(repo.base_sha, new_sha);
    }
}
