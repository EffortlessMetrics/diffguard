//! Snapshot tests for baseline/grandfather mode markdown output.
//!
//! These tests capture the current output of baseline mode for various scenarios.
//! The snapshots document what the output looks like NOW - any change to the output
//! will be detected by these tests.
//!
//! Coverage:
//! 1. Markdown with only NEW findings (empty baseline)
//! 2. Markdown with only BASELINE findings (no new findings)
//! 3. Markdown with mixed BASELINE and NEW findings
//! 4. Markdown with --report-mode=new-only (hides baseline findings)

use assert_cmd::Command;
use assert_cmd::cargo;
use serde_json::json;
use tempfile::TempDir;

// ============================================================================
// Helper Functions
// ============================================================================

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

/// Creates a repository with a violation that is added in the second commit.
/// The fingerprint of the finding is: rust.no_unwrap:src/lib.rs:1:Some(1).unwrap()
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

/// Creates a baseline receipt from the first run's findings.
fn create_baseline_from_first_run(dir: &std::path::Path) -> String {
    // First, run diffguard to get actual findings
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    let output = cmd
        .current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg("HEAD~1")
        .arg("--head")
        .arg("HEAD")
        .arg("--out")
        .arg("artifacts/diffguard/report.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md")
        .output()
        .expect("first diffguard run should succeed");

    assert!(
        output.status.success(),
        "first diffguard run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Read the generated receipt
    let receipt_path = dir.join("artifacts/diffguard/report.json");
    let receipt_content =
        std::fs::read_to_string(&receipt_path).expect("should be able to read generated receipt");

    // Write it as baseline
    let baseline_path = dir.join("baseline.json");
    std::fs::write(&baseline_path, &receipt_content).unwrap();

    baseline_path.to_string_lossy().to_string()
}

// ============================================================================
// Snapshot Tests
// ============================================================================

/// Snapshot test: baseline mode with empty baseline (all findings are NEW).
/// When the baseline has no findings, all current findings should be marked [NEW].
#[test]
fn baseline_mode_empty_baseline_all_new() {
    let (td, base, head) = init_repo_with_added_violation();
    let dir = td.path();

    // Create an empty baseline
    let empty_baseline = json!({
        "schema": "diffguard.check.v1",
        "tool": { "name": "diffguard", "version": "0.2.0" },
        "diff": {
            "base": base,
            "head": head,
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

    // Run diffguard with the empty baseline
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    let output = cmd
        .current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md")
        .output()
        .expect("diffguard should run");

    // With empty baseline, exit code should be 2 (new errors found)
    // since all findings are considered new
    let exit_code = output.status.code();
    assert!(
        exit_code == Some(2),
        "expected exit code 2 for new errors, got: {:?}",
        exit_code
    );

    // Read the markdown output
    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md"))
        .expect("should be able to read markdown output");

    insta::assert_snapshot!(
        "baseline_mode_empty_baseline_all_new",
        format!("exit_code={:?}\n\n{}", exit_code, markdown)
    );
}

/// Snapshot test: baseline mode with matching baseline (only BASELINE findings).
/// When all current findings match the baseline, exit code should be 0.
#[test]
fn baseline_mode_only_baseline_findings() {
    let (td, _base, _head) = init_repo_with_added_violation();
    let dir = td.path();

    // First run diffguard to get actual findings
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    let output = cmd
        .current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg("HEAD~1")
        .arg("--head")
        .arg("HEAD")
        .arg("--out")
        .arg("artifacts/diffguard/report.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md")
        .output()
        .expect("first diffguard run should succeed");

    // Use this as the baseline
    let baseline_path = dir.join("baseline.json");
    std::fs::copy(dir.join("artifacts/diffguard/report.json"), &baseline_path).unwrap();

    // Now re-run with the baseline - since the findings match, they should all be [BASELINE]
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    let output = cmd
        .current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg("HEAD~1")
        .arg("--head")
        .arg("HEAD")
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report2.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment2.md")
        .output()
        .expect("diffguard should run");

    let exit_code = output.status.code();
    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment2.md"))
        .expect("should be able to read markdown output");

    // Note: The exit code may not be 0 due to known bug - we snapshot the current behavior
    insta::assert_snapshot!(
        "baseline_mode_only_baseline_findings",
        format!("exit_code={:?}\n\n{}", exit_code, markdown)
    );
}

/// Snapshot test: baseline mode with mixed BASELINE and NEW findings.
/// This shows the annotation format when there are both baseline and new findings.
#[test]
fn baseline_mode_mixed_findings() {
    let (td, base, head) = init_repo_with_added_violation();
    let dir = td.path();

    // Create a baseline that has the finding from the first commit
    // The actual finding will be slightly different (match_text changes)
    let mixed_baseline = json!({
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
        "findings": [
            {
                "rule_id": "rust.no_unwrap",
                "severity": "error",
                "message": "Avoid unwrap/expect in production code.",
                "path": "src/lib.rs",
                "line": 2,
                "match_text": "Some(1).unwrap()",
                "snippet": "pub fn g() -> u32 { Some(1).unwrap() }"
            }
        ],
        "verdict": {
            "status": "fail",
            "counts": { "info": 0, "warn": 0, "error": 1 },
            "reasons": ["1 policy violations found"]
        }
    });

    let baseline_path = dir.join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&mixed_baseline).unwrap(),
    )
    .unwrap();

    // Run diffguard with the mixed baseline
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    let output = cmd
        .current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md")
        .output()
        .expect("diffguard should run");

    let exit_code = output.status.code();
    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md"))
        .expect("should be able to read markdown output");

    insta::assert_snapshot!(
        "baseline_mode_mixed_findings",
        format!("exit_code={:?}\n\n{}", exit_code, markdown)
    );
}

/// Snapshot test: baseline mode with --report-mode=new-only.
/// This shows the output when baseline findings are hidden.
#[test]
fn baseline_mode_report_mode_new_only() {
    let (td, base, head) = init_repo_with_added_violation();
    let dir = td.path();

    // Create a baseline with one finding
    let baseline = json!({
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
        "findings": [
            {
                "rule_id": "rust.no_unwrap",
                "severity": "error",
                "message": "Avoid unwrap/expect in production code.",
                "path": "src/lib.rs",
                "line": 2,
                "match_text": "Some(1).unwrap()",
                "snippet": "pub fn g() -> u32 { Some(1).unwrap() }"
            }
        ],
        "verdict": {
            "status": "fail",
            "counts": { "info": 0, "warn": 0, "error": 1 },
            "reasons": ["1 policy violations found"]
        }
    });

    let baseline_path = dir.join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline).unwrap(),
    )
    .unwrap();

    // Run diffguard with --report-mode=new-only
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    let output = cmd
        .current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--report-mode=new-only")
        .arg("--out")
        .arg("artifacts/diffguard/report.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md")
        .output()
        .expect("diffguard should run");

    let exit_code = output.status.code();
    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md"))
        .expect("should be able to read markdown output");

    insta::assert_snapshot!(
        "baseline_mode_report_mode_new_only",
        format!("exit_code={:?}\n\n{}", exit_code, markdown)
    );
}

/// Snapshot test: baseline mode - finding row annotation format.
/// This captures the exact format of a single finding row with [BASELINE] annotation.
#[test]
fn baseline_mode_finding_row_baseline_annotation() {
    let (td, base, head) = init_repo_with_added_violation();
    let dir = td.path();

    // Create a baseline that exactly matches the current finding
    let exact_baseline = json!({
        "schema": "diffguard.check.v1",
        "tool": { "name": "diffguard", "version": "0.2.0" },
        "diff": {
            "base": base.clone(),
            "head": head.clone(),
            "scope": "changed",
            "context_lines": 3,
            "files_scanned": 1,
            "lines_scanned": 10
        },
        "findings": [
            {
                "rule_id": "rust.no_unwrap",
                "severity": "error",
                "message": "Avoid unwrap/expect in production code.",
                "path": "src/lib.rs",
                "line": 2,
                "match_text": "Some(1).unwrap()",
                "snippet": "pub fn g() -> u32 { Some(1).unwrap() }"
            }
        ],
        "verdict": {
            "status": "fail",
            "counts": { "info": 0, "warn": 0, "error": 1 },
            "reasons": ["1 policy violations found"]
        }
    });

    let baseline_path = dir.join("baseline.json");
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&exact_baseline).unwrap(),
    )
    .unwrap();

    // Run diffguard with the exact baseline
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    let output = cmd
        .current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md")
        .output()
        .expect("diffguard should run");

    let exit_code = output.status.code();
    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md"))
        .expect("should be able to read markdown output");

    insta::assert_snapshot!(
        "baseline_mode_finding_row_baseline",
        format!("exit_code={:?}\n\n{}", exit_code, markdown)
    );
}

/// Snapshot test: baseline mode - [NEW] annotation on finding row.
/// This captures the exact format of a single finding row with [NEW] annotation.
#[test]
fn baseline_mode_finding_row_new_annotation() {
    let (td, base, head) = init_repo_with_added_violation();
    let dir = td.path();

    // Create an empty baseline - all findings will be NEW
    let empty_baseline = json!({
        "schema": "diffguard.check.v1",
        "tool": { "name": "diffguard", "version": "0.2.0" },
        "diff": {
            "base": base,
            "head": head,
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

    // Run diffguard with the empty baseline
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    let output = cmd
        .current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg("HEAD~1")
        .arg("--head")
        .arg("HEAD")
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json")
        .arg("--md")
        .arg("artifacts/diffguard/comment.md")
        .output()
        .expect("diffguard should run");

    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md"))
        .expect("should be able to read markdown output");

    insta::assert_snapshot!("baseline_mode_finding_row_new_annotation", markdown);
}
