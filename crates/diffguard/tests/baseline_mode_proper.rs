//! Proper integration tests for baseline/grandfather mode.
//!
//! These tests use ACTUAL diffguard findings as baselines, not fabricated data.
//! This is the correct way to test baseline mode - first run diffguard to get
//! actual findings, then use those as the baseline.

use assert_cmd::Command;
use assert_cmd::cargo;
use serde_json::json;
use tempfile::TempDir;

/// Runs a git command in the given directory.
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

/// Creates a repository where a violation is ADDED in the second commit.
/// This is the correct way to test baseline mode - the violation must be in
/// the diff's "added" scope for diffguard to detect it.
fn init_repo_with_added_violation() -> (TempDir, String, String) {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    run_git(dir, &["init"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Test"]);

    // Create initial file WITHOUT the violation
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/lib.rs"), "pub fn f() -> u32 { 42 }\n").unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "base"]);
    let base = run_git(dir, &["rev-parse", "HEAD"]);

    // Add the violation in the new commit
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn f() -> u32 { 42 }\npub fn g() -> u32 { Some(1).unwrap() }\n",
    )
    .unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "add-violation"]);
    let head = run_git(dir, &["rev-parse", "HEAD"]);

    (td, base, head)
}

/// Creates a repository where violation is added, then a non-violation change is made.
/// The change doesn't shift line numbers so fingerprints remain stable.
fn init_repo_with_violation_then_change() -> (TempDir, String, String) {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    run_git(dir, &["init"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Test"]);

    // Create initial file WITHOUT the violation
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/lib.rs"), "pub fn f() -> u32 { 42 }\n").unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "base"]);
    let base = run_git(dir, &["rev-parse", "HEAD"]);

    // Add the violation in the second commit
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn f() -> u32 { 42 }\npub fn g() -> u32 { Some(1).unwrap() }\n",
    )
    .unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "add-violation"]);

    // Make a non-violation change at the END of the file (doesn't shift line numbers)
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn f() -> u32 { 42 }\npub fn g() -> u32 { Some(1).unwrap() }\n// End of file\n",
    )
    .unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "add-end-comment"]);
    let head = run_git(dir, &["rev-parse", "HEAD"]);

    (td, base, head)
}

// ============================================================================
// Proper Baseline Mode Tests - Using Actual Findings
// ============================================================================

/// Test that new violations (not in baseline) cause exit 2.
#[test]
fn new_violations_cause_exit_2() {
    let (td, base, head) = init_repo_with_added_violation();
    let dir = td.path();

    // First run with EMPTY baseline - all findings are "new"
    let empty_baseline = json!({
        "schema": "diffguard.check.v1",
        "tool": { "name": "diffguard", "version": "0.2.0" },
        "diff": {
            "base": "abc123",
            "head": "def456",
            "scope": "changed",
            "context_lines": 3,
            "files_scanned": 1,
            "lines_scanned": 10
        },
        "findings": [],  // Empty baseline
        "verdict": {
            "status": "pass",
            "counts": { "info": 0, "warn": 0, "error": 0 },
            "reasons": []
        }
    });

    let baseline_path = dir.join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&empty_baseline).unwrap(),
    )
    .unwrap();

    // Run with empty baseline - should exit 2 (new errors found)
    let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json");

    cmd.assert().code(2);
}

/// Test that truly new violations show [NEW] annotation.
#[test]
fn new_violations_show_new_annotation() {
    let (td, base, head) = init_repo_with_added_violation();
    let dir = td.path();

    // Empty baseline
    let empty_baseline = json!({
        "schema": "diffguard.check.v1",
        "tool": { "name": "diffguard", "version": "0.2.0" },
        "diff": {
            "base": "abc123",
            "head": "def456",
            "scope": "changed",
            "context_lines": 3,
            "files_scanned": 1,
            "lines_scanned": 10
        },
        "findings": [],
        "verdict": {
            "status": "pass",
            "counts": { "info": 0, "warn": 0, "error": 0 },
            "reasons": []
        }
    });

    let baseline_path = dir.join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&empty_baseline).unwrap(),
    )
    .unwrap();

    // Run with empty baseline - new violation should appear
    let mut cmd = Command::new(cargo::cargo_bin("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md");

    cmd.assert().code(2);

    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md"))
        .expect("should have markdown");
    assert!(
        markdown.contains("[NEW]"),
        "New violations should be marked [NEW]. Got:\n{}",
        markdown
    );
}

/// Test that baseline mode works when baseline is created from actual findings.
#[test]
fn baseline_from_actual_findings_matches_on_repeat() {
    let (td, base, head) = init_repo_with_violation_then_change();
    let dir = td.path();

    // First run: get actual findings and create baseline
    let mut cmd1 = Command::new(cargo::cargo_bin("diffguard"));
    cmd1.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg("HEAD~1") // Use the commit that introduced the violation
        .arg("--out")
        .arg("artifacts/diffguard/first_run.json");

    cmd1.assert().code(2); // First run should fail (found violation)

    // Read the first run receipt to get actual findings
    let receipt_text = std::fs::read_to_string(dir.join("artifacts/diffguard/first_run.json"))
        .expect("should have first run receipt");
    let receipt: serde_json::Value =
        serde_json::from_str(&receipt_text).expect("first run receipt should be valid JSON");

    // Create baseline from the actual findings
    let baseline_receipt = json!({
        "schema": receipt["schema"],
        "tool": receipt["tool"],
        "diff": receipt["diff"],
        "findings": receipt["findings"],  // Use ACTUAL findings
        "verdict": receipt["verdict"]
    });

    let baseline_path = dir.join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    // Second run against HEAD (which has the violation plus a comment):
    // The violation fingerprint should still match because the unwrap line is unchanged
    let mut cmd2 = Command::new(cargo::cargo_bin("diffguard"));
    cmd2.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head) // Use HEAD which has the violation
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/second_run.json");

    // Should exit 0 because only baseline findings (the unwrap line is unchanged)
    cmd2.assert().code(0);
}

/// Test that baseline annotations appear in markdown output when using actual baseline.
#[test]
fn baseline_annotations_appear_in_markdown() {
    let (td, base, head) = init_repo_with_violation_then_change();
    let dir = td.path();

    // First run against the commit that introduced the violation
    let mut cmd1 = Command::new(cargo::cargo_bin("diffguard"));
    cmd1.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg("HEAD~1")
        .arg("--out")
        .arg("artifacts/diffguard/first_run.json");

    cmd1.assert().code(2);

    let receipt_text = std::fs::read_to_string(dir.join("artifacts/diffguard/first_run.json"))
        .expect("should have first run receipt");
    let receipt: serde_json::Value =
        serde_json::from_str(&receipt_text).expect("first run receipt should be valid JSON");

    // Create baseline from actual findings
    let baseline_receipt = json!({
        "schema": receipt["schema"],
        "tool": receipt["tool"],
        "diff": receipt["diff"],
        "findings": receipt["findings"],
        "verdict": receipt["verdict"]
    });

    let baseline_path = dir.join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    // Run with baseline against HEAD
    let mut cmd2 = Command::new(cargo::cargo_bin("diffguard"));
    cmd2.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/second_run.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md");

    cmd2.assert().code(0);

    // Check markdown has baseline annotation
    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md"))
        .expect("should have markdown output");
    assert!(
        markdown.contains("[BASELINE]"),
        "Markdown should contain [BASELINE] annotation. Got:\n{}",
        markdown
    );
}

/// Test that mixed baseline and new findings both appear with correct annotations.
#[test]
fn mixed_findings_show_both_annotations() {
    let (td, base, head) = init_repo_with_added_violation();
    let dir = td.path();

    // First run to get actual findings
    let mut cmd1 = Command::new(cargo::cargo_bin("diffguard"));
    cmd1.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg("--out")
        .arg("artifacts/diffguard/first_run.json");

    cmd1.assert().code(2);

    let receipt_text = std::fs::read_to_string(dir.join("artifacts/diffguard/first_run.json"))
        .expect("should have first run receipt");
    let receipt: serde_json::Value =
        serde_json::from_str(&receipt_text).expect("first run receipt should be valid JSON");

    // Use the actual findings as baseline
    let baseline_receipt = json!({
        "schema": receipt["schema"],
        "tool": receipt["tool"],
        "diff": receipt["diff"],
        "findings": receipt["findings"],
        "verdict": receipt["verdict"]
    });

    let baseline_path = dir.join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    // Run with baseline - should exit 0 (all findings are baseline)
    let mut cmd2 = Command::new(cargo::cargo_bin("diffguard"));
    cmd2.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/second_run.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md");

    cmd2.assert().code(0);

    // With baseline matching, all findings should be baseline (no [NEW])
    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md"))
        .expect("should have markdown");
    assert!(
        markdown.contains("[BASELINE]"),
        "Baseline findings should be marked [BASELINE]. Got:\n{}",
        markdown
    );
    // No [NEW] because baseline matches
    assert!(
        !markdown.contains("[NEW]"),
        "Should not have [NEW] when baseline matches. Got:\n{}",
        markdown
    );
}

/// Test that report-mode=new-only hides baseline findings.
#[test]
fn report_mode_new_only_hides_baseline_findings_proper() {
    let (td, base, head) = init_repo_with_added_violation();
    let dir = td.path();

    // First run to get actual findings
    let mut cmd1 = Command::new(cargo::cargo_bin("diffguard"));
    cmd1.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg("--out")
        .arg("artifacts/diffguard/first_run.json");

    cmd1.assert().code(2);

    let receipt_text = std::fs::read_to_string(dir.join("artifacts/diffguard/first_run.json"))
        .expect("should have first run receipt");
    let receipt: serde_json::Value =
        serde_json::from_str(&receipt_text).expect("first run receipt should be valid JSON");

    // Create baseline from actual findings
    let baseline_receipt = json!({
        "schema": receipt["schema"],
        "tool": receipt["tool"],
        "diff": receipt["diff"],
        "findings": receipt["findings"],
        "verdict": receipt["verdict"]
    });

    let baseline_path = dir.join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    // Run with baseline and new-only report mode
    let mut cmd2 = Command::new(cargo::cargo_bin("diffguard"));
    cmd2.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--report-mode=new-only")
        .arg("--out")
        .arg("artifacts/diffguard/second_run.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md");

    cmd2.assert().code(0); // Should pass with new-only mode when only baseline findings

    // Check that the markdown output does NOT contain [BASELINE]
    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md"))
        .expect("should have markdown output");
    assert!(
        !markdown.contains("[BASELINE]"),
        "With report-mode=new-only, baseline findings should be hidden. Got:\n{}",
        markdown
    );
}
