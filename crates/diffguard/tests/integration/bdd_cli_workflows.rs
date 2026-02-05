//! BDD integration tests for complete CLI workflows.
//!
//! These tests cover end-to-end CLI behavior for diffguard, following
//! Given/When/Then patterns to verify complete workflows.
//!
//! Phase 1.13 from ROADMAP.md

use super::test_repo::{DiffguardResult, TestRepo};

// =============================================================================
// 1. Basic Workflow Tests
// =============================================================================

/// Scenario: Basic workflow with findings produces correct exit code and output.
///
/// Given: A config with a rule that flags "FORBIDDEN"
/// When: Running check on a diff containing "FORBIDDEN"
/// Then: Exit code is 2 (policy fail)
///   And: Receipt contains the finding with correct metadata
///   And: Receipt contains valid schema version
#[test]
fn given_diff_with_findings_when_check_then_exit_code_2_and_valid_receipt() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "test.no_forbidden"
severity = "error"
message = "FORBIDDEN keyword detected"
patterns = ["FORBIDDEN"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file("src/lib.rs", "// FORBIDDEN content here\npub fn f() {}\n");
    let head_sha = repo.commit("add forbidden content");

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);

    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("test.no_forbidden"));
    assert!(receipt.has_finding_at("src/lib.rs", 1));
    assert_eq!(receipt.error_count(), 1);
    result.assert_receipt_contains("diffguard.check.v1");
}

/// Scenario: Basic workflow verifies receipt structure.
#[test]
fn given_violation_when_check_then_receipt_has_correct_structure() {
    let repo = TestRepo::new();

    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("add unwrap");

    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    // Verify receipt has expected structure
    result.assert_receipt_contains("\"schema\"");
    result.assert_receipt_contains("\"verdict\"");
    result.assert_receipt_contains("\"findings\"");
    result.assert_receipt_contains("\"diff\"");
    result.assert_receipt_contains("\"tool\"");
}

// =============================================================================
// 2. Clean Diff Tests
// =============================================================================

/// Scenario: Clean diff with no violations exits with code 0.
#[test]
fn given_clean_diff_when_check_then_exit_0_and_pass_verdict() {
    let repo = TestRepo::new();

    repo.write_file(
        "src/lib.rs",
        r#"/// Documentation comment
pub fn safe_function() -> Option<u32> {
    Some(42)
}
"#,
    );
    let head_sha = repo.commit("add clean code");

    let result = repo.run_check(&head_sha);
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.verdict_status(), Some("pass"));
    assert_eq!(receipt.findings_count(), 0);
}

/// Scenario: Empty diff (no changes) exits with code 0.
#[test]
fn given_empty_diff_when_check_then_exit_0() {
    let repo = TestRepo::new();
    let result = repo.run_check(&repo.base_sha);
    result.assert_exit_code(0);
    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

// =============================================================================
// 3. Config Override Tests
// =============================================================================

/// Scenario: --config flag overrides default config discovery.
#[test]
fn given_custom_config_path_when_check_with_config_flag_then_config_applied() {
    let repo = TestRepo::new();

    repo.write_file(
        "custom/my-rules.toml",
        r#"
[[rule]]
id = "custom.path_test"
severity = "error"
message = "Custom config loaded"
patterns = ["CUSTOM_PATH_MARKER"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file("src/lib.rs", "// CUSTOM_PATH_MARKER\npub fn f() {}\n");
    let head_sha = repo.commit("add marker");

    let result = repo.run_check_with_args(
        &head_sha,
        &["--config", "custom/my-rules.toml", "--no-default-rules"],
    );

    result.assert_exit_code(2);
    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("custom.path_test"));
}

/// Scenario: --no-default-rules disables built-in rules.
#[test]
fn given_unwrap_when_no_default_rules_then_no_findings() {
    let repo = TestRepo::new();
    repo.write_config("");
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("add unwrap");

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(0);
    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

/// Scenario: Custom config rules merge with built-in rules by default.
#[test]
fn given_custom_and_builtin_rules_when_check_then_both_applied() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "custom.marker"
severity = "warn"
message = "Found marker"
patterns = ["MY_MARKER"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file(
        "src/lib.rs",
        "// MY_MARKER\npub fn f() -> u32 { Some(1).unwrap() }\n",
    );
    let head_sha = repo.commit("add violations");

    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("rust.no_unwrap"));
    assert!(receipt.has_finding_with_rule("custom.marker"));
}

// =============================================================================
// 4. Output Format Tests
// =============================================================================

/// Scenario: --md flag produces valid Markdown output.
#[test]
fn given_findings_when_md_flag_then_markdown_file_created() {
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("add unwrap");

    let md_path = repo.path().join("artifacts/diffguard/comment.md");
    let result = repo.run_check_with_args(&head_sha, &["--md", md_path.to_str().unwrap()]);

    result.assert_exit_code(2);
    assert!(md_path.exists(), "Markdown file should be created");
}

/// Scenario: --sarif flag produces valid SARIF output.
#[test]
fn given_findings_when_sarif_flag_then_sarif_file_created() {
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("add unwrap");

    let sarif_path = repo.path().join("artifacts/diffguard/report.sarif.json");
    let result = repo.run_check_with_args(&head_sha, &["--sarif", sarif_path.to_str().unwrap()]);

    result.assert_exit_code(2);
    assert!(sarif_path.exists(), "SARIF file should be created");

    let sarif_content = std::fs::read_to_string(&sarif_path).expect("read sarif");
    let sarif: serde_json::Value = serde_json::from_str(&sarif_content).expect("valid JSON");
    assert_eq!(sarif["version"].as_str().unwrap_or(""), "2.1.0");
    assert!(sarif["runs"].is_array());
}

/// Scenario: --junit flag produces valid JUnit XML output.
#[test]
fn given_findings_when_junit_flag_then_junit_file_created() {
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("add unwrap");

    let junit_path = repo.path().join("artifacts/diffguard/report.xml");
    let result = repo.run_check_with_args(&head_sha, &["--junit", junit_path.to_str().unwrap()]);

    result.assert_exit_code(2);
    assert!(junit_path.exists(), "JUnit file should be created");

    let junit_content = std::fs::read_to_string(&junit_path).expect("read junit");
    assert!(junit_content.contains("<?xml"));
    assert!(junit_content.contains("<testsuite"));
}

/// Scenario: --csv flag produces valid CSV output.
#[test]
fn given_findings_when_csv_flag_then_csv_file_created() {
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("add unwrap");

    let csv_path = repo.path().join("artifacts/diffguard/report.csv");
    let result = repo.run_check_with_args(&head_sha, &["--csv", csv_path.to_str().unwrap()]);

    result.assert_exit_code(2);
    assert!(csv_path.exists(), "CSV file should be created");

    let csv_content = std::fs::read_to_string(&csv_path).expect("read csv");
    let lines: Vec<&str> = csv_content.lines().collect();
    assert!(lines.len() >= 2);
    assert!(lines[0].contains("rule_id"));
}

/// Scenario: --tsv flag produces valid TSV output.
#[test]
fn given_findings_when_tsv_flag_then_tsv_file_created() {
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("add unwrap");

    let tsv_path = repo.path().join("artifacts/diffguard/report.tsv");
    let result = repo.run_check_with_args(&head_sha, &["--tsv", tsv_path.to_str().unwrap()]);

    result.assert_exit_code(2);
    assert!(tsv_path.exists(), "TSV file should be created");

    let tsv_content = std::fs::read_to_string(&tsv_path).expect("read tsv");
    assert!(tsv_content.contains('\t'));
}

// =============================================================================
// 5. Staged Mode Tests
// =============================================================================

/// Scenario: --staged flag uses git diff --cached.
#[test]
fn given_staged_changes_when_staged_flag_then_staged_diff_analyzed() {
    let repo = TestRepo::new();

    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    run_git(repo.path(), &["add", "src/lib.rs"]);

    let result = repo.run_check_staged();
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("rust.no_unwrap"));
}

/// Scenario: --staged with no staged changes exits cleanly.
#[test]
fn given_no_staged_changes_when_staged_flag_then_exit_0() {
    let repo = TestRepo::new();
    let result = repo.run_check_staged();
    result.assert_exit_code(0);
    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

/// Scenario: --staged only analyzes staged changes, not unstaged.
#[test]
fn given_mixed_staged_unstaged_when_staged_flag_then_only_staged_analyzed() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "test.staged"
severity = "error"
message = "STAGED marker found"
patterns = ["STAGED_MARKER"]
paths = ["**/*.rs"]

[[rule]]
id = "test.unstaged"
severity = "error"
message = "UNSTAGED marker found"
patterns = ["UNSTAGED_MARKER"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file("src/staged.rs", "// STAGED_MARKER\n");
    run_git(repo.path(), &["add", "src/staged.rs"]);
    repo.write_file("src/unstaged.rs", "// UNSTAGED_MARKER\n");

    let result = repo.run_check_staged_with_args(&["--no-default-rules"]);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("test.staged"));
    assert!(!receipt.has_finding_with_rule("test.unstaged"));
}

// =============================================================================
// 6. Multiple Output Format Tests
// =============================================================================

/// Scenario: Multiple output flags can be combined.
#[test]
fn given_findings_when_multiple_output_flags_then_all_files_created() {
    let repo = TestRepo::new();
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("add unwrap");

    let md_path = repo.path().join("out/comment.md");
    let sarif_path = repo.path().join("out/report.sarif.json");
    let junit_path = repo.path().join("out/report.xml");
    let csv_path = repo.path().join("out/report.csv");

    let result = repo.run_check_with_args(
        &head_sha,
        &[
            "--md", md_path.to_str().unwrap(),
            "--sarif", sarif_path.to_str().unwrap(),
            "--junit", junit_path.to_str().unwrap(),
            "--csv", csv_path.to_str().unwrap(),
        ],
    );

    result.assert_exit_code(2);
    assert!(md_path.exists());
    assert!(sarif_path.exists());
    assert!(junit_path.exists());
    assert!(csv_path.exists());
    result.assert_receipt_exists();
}

// =============================================================================
// 7. Error Handling Tests
// =============================================================================

/// Scenario: Invalid regex pattern in config produces tool error.
#[test]
fn given_invalid_regex_when_check_then_exit_1() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "bad.regex"
severity = "error"
message = "Bad regex"
patterns = ["[invalid(regex"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file("src/lib.rs", "pub fn f() {}\n");
    let head_sha = repo.commit("add code");

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(1);
}

// =============================================================================
// Helper Functions
// =============================================================================

fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
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

// =============================================================================
// TestRepo Extensions for Staged Mode
// =============================================================================

impl TestRepo {
    fn run_check_staged(&self) -> DiffguardResult {
        self.run_check_staged_with_args(&[])
    }

    fn run_check_staged_with_args(&self, extra_args: &[&str]) -> DiffguardResult {
        use assert_cmd::Command;

        let out_path = self.path().join("artifacts/diffguard/report.json");

        let mut cmd = Command::cargo_bin("diffguard").expect("diffguard binary");
        cmd.current_dir(self.path())
            .arg("check")
            .arg("--staged")
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
}
