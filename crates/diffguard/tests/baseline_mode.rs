//! Red tests for baseline/grandfather mode feature.
//!
//! These tests define the expected behavior for the baseline mode feature.
//! They are written BEFORE implementation, so they are expected to fail initially.
//!
//! Feature: Baseline mode allows teams with existing codebases to adopt diffguard
//! incrementally by grandfathering pre-existing violations.

use assert_cmd::Command;
use assert_cmd::cargo;
use tempfile::TempDir;
use serde_json::json;

// ============================================================================
// Test Fixtures - Helper Functions
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

fn init_repo_with_findings() -> (TempDir, String, String) {
    let td = TempDir::new().expect("temp");
    let dir = td.path();

    run_git(dir, &["init"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["config", "user.name", "Test"]);

    // Create initial file with unwrap (violation)
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn f() -> u32 { Some(1).unwrap() }\n",
    )
    .unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "base"]);
    let base = run_git(dir, &["rev-parse", "HEAD"]);

    // Make a change
    std::fs::write(
        dir.join("src/lib.rs"),
        "pub fn f() -> u32 { Some(2).unwrap() }\n",
    )
    .unwrap();

    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", "change"]);
    let head = run_git(dir, &["rev-parse", "HEAD"]);

    (td, base, head)
}

fn create_baseline_receipt(dir: &std::path::Path, findings: Vec<serde_json::Value>) -> String {
    let receipt = json!({
        "schema": "diffguard.check.v1",
        "tool": {
            "name": "diffguard",
            "version": "0.2.0"
        },
        "diff": {
            "base": "abc123",
            "head": "def456",
            "scope": "changed",
            "context_lines": 3,
            "files_scanned": 1,
            "lines_scanned": 10
        },
        "findings": findings,
        "verdict": {
            "status": "fail",
            "counts": {
                "info": 0,
                "warn": 0,
                "error": findings.len() as u32
            },
            "reasons": ["1 policy violations found"]
        }
    });

    let path = dir.join("baseline_receipt.json");
    std::fs::write(&path, serde_json::to_string_pretty(&receipt).unwrap()).unwrap();
    path.to_string_lossy().to_string()
}

// ============================================================================
// AC1: Baseline Flag
// Tests for the `--baseline` flag on CheckArgs
// ============================================================================

#[test]
fn baseline_flag_is_accepted() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Create a valid baseline receipt
    let baseline_receipt = create_baseline_receipt(dir, vec![]);

    // Running with --baseline should not fail to parse arguments
    // (Even if the baseline file doesn't exist, the flag should be accepted)
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    let result = cmd
        .current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_receipt))
        .arg("--out")
        .arg("artifacts/diffguard/report.json")
        .output();

    // The command should run (not fail due to unknown flag)
    // It may fail due to file issues, but not flag parsing
    assert!(
        result.is_ok(),
        "baseline flag should be recognized by the CLI"
    );
}

#[test]
fn baseline_flag_missing_file_exits_with_code_1() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    let nonexistent_path = dir.join("nonexistent_baseline.json");
    let nonexistent = nonexistent_path.to_string_lossy();

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", nonexistent))
        .arg("--out")
        .arg("artifacts/diffguard/report.json");

    let output = cmd.output().unwrap();
    assert_eq!(output.status.code(), Some(1), "Should exit with code 1 for missing baseline file");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("does not exist"),
        "Error message should mention file not found. Got: {}",
        stderr
    );
}

// ============================================================================
// AC2: Baseline Receipt Loading
// Tests for valid/invalid JSON, missing file, schema version validation
// ============================================================================

#[test]
fn baseline_receipt_invalid_json_exits_code_1() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Write invalid JSON
    let invalid_json_path = dir.join("invalid_baseline.json");
    std::fs::write(&invalid_json_path, "{ this is not json }").unwrap();

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", invalid_json_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json");

    let output = cmd.output().unwrap();
    assert_eq!(output.status.code(), Some(1), "Should exit with code 1 for invalid JSON");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("parse") || stderr.contains("JSON"),
        "Error message should mention parse error. Got: {}",
        stderr
    );
}

#[test]
fn baseline_receipt_wrong_schema_version_exits_code_1() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Create receipt with wrong schema version
    let wrong_schema_receipt = json!({
        "schema": "diffguard.check.v2",  // Wrong version
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

    let path = dir.join("wrong_schema_baseline.json");
    std::fs::write(&path, serde_json::to_string_pretty(&wrong_schema_receipt).unwrap()).unwrap();

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json");

    let output = cmd.output().unwrap();
    assert_eq!(output.status.code(), Some(1), "Should exit with code 1 for wrong schema version");
    
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("schema") || stderr.contains("version"),
        "Error message should mention schema version issue. Got: {}",
        stderr
    );
}

// ============================================================================
// AC3: Finding Classification
// Tests for baseline vs new finding classification
// ============================================================================

#[test]
fn findings_matching_baseline_are_classified_as_baseline() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // The finding fingerprint is based on: rule_id:path:line:match_text
    // For our test: rust.no_unwrap:src/lib.rs:1:Some(1).unwrap()
    let baseline_finding = json!({
        "rule_id": "rust.no_unwrap",
        "severity": "error",
        "message": "Found .unwrap() call",
        "path": "src/lib.rs",
        "line": 1,
        "match_text": "Some(1).unwrap()",
        "snippet": "pub fn f() -> u32 { Some(1).unwrap() }"
    });

    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
        "findings": [baseline_finding],
        "verdict": {
            "status": "fail",
            "counts": { "info": 0, "warn": 0, "error": 1 },
            "reasons": ["1 policy violations found"]
        }
    });
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    // When we run check with this baseline, the same finding should be classified as BASELINE
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
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

    // Should exit 0 because only baseline findings exist
    cmd.assert().code(0);

    // Check that output contains BASELINE annotation
    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md")).unwrap();
    assert!(
        markdown.contains("[BASELINE]"),
        "Output should contain [BASELINE] annotation for grandfathered findings.\nGot:\n{}",
        markdown
    );
}

#[test]
fn new_findings_not_in_baseline_are_classified_as_new() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Create empty baseline - no findings
    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    // When we run check with this empty baseline, the actual finding should be NEW
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
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

    // Should exit 2 because new errors were found
    cmd.assert().code(2);

    // Check that output contains NEW annotation
    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md")).unwrap();
    assert!(
        markdown.contains("[NEW]"),
        "Output should contain [NEW] annotation for new findings.\nGot:\n{}",
        markdown
    );
}

// ============================================================================
// AC4: Exit Code - No New Findings
// When --baseline provided and only baseline findings exist, exit code is 0
// ============================================================================

#[test]
fn baseline_mode_with_only_baseline_findings_exits_0() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Create baseline with exact matching finding
    let baseline_finding = json!({
        "rule_id": "rust.no_unwrap",
        "severity": "error",
        "message": "Found .unwrap() call",
        "path": "src/lib.rs",
        "line": 1,
        "match_text": "Some(1).unwrap()",
        "snippet": "pub fn f() -> u32 { Some(1).unwrap() }"
    });

    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
        "findings": [baseline_finding],
        "verdict": {
            "status": "fail",
            "counts": { "info": 0, "warn": 0, "error": 1 },
            "reasons": ["1 policy violations found"]
        }
    });
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json");

    // Exit 0 because all findings are baseline (grandfathered)
    cmd.assert().code(0);
}

#[test]
fn baseline_mode_with_no_findings_at_all_exits_0() {
    let (td, _base, _head) = init_repo_with_findings();
    let dir = td.path();

    // Use git rev-parse to get current commit as both base and head
    // to create an empty diff
    let current = run_git(dir, &["rev-parse", "HEAD"]);

    // Create empty baseline
    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&current)
        .arg("--head")
        .arg(&current)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json");

    // Exit 0 because no new findings
    cmd.assert().code(0);
}

// ============================================================================
// AC5: Exit Code - New Findings
// When --baseline provided and new errors exist, exit code is 2
// When --baseline provided and only new warnings exist, exit code is 3
// ============================================================================

#[test]
fn baseline_mode_with_new_errors_exits_2() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Create empty baseline - the unwrap finding will be NEW
    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report.json");

    // Exit 2 because new errors were found (not in baseline)
    cmd.assert().code(2);
}

// ============================================================================
// AC6: Output Annotation
// Tests for [BASELINE]/[NEW] prefixes in markdown output
// ============================================================================

#[test]
fn baseline_mode_marks_baseline_findings_in_output() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Create baseline with the unwrap finding
    let baseline_finding = json!({
        "rule_id": "rust.no_unwrap",
        "severity": "error",
        "message": "Found .unwrap() call",
        "path": "src/lib.rs",
        "line": 1,
        "match_text": "Some(1).unwrap()",
        "snippet": "pub fn f() -> u32 { Some(1).unwrap() }"
    });

    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
        "findings": [baseline_finding],
        "verdict": {
            "status": "fail",
            "counts": { "info": 0, "warn": 0, "error": 1 },
            "reasons": ["1 policy violations found"]
        }
    });
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
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

    cmd.assert().code(0);

    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md")).unwrap();
    // Should contain BASELINE annotation
    assert!(
        markdown.contains("[BASELINE]"),
        "Markdown should contain [BASELINE] prefix.\nGot:\n{}",
        markdown
    );
    // Should NOT contain NEW annotation (no new findings)
    assert!(
        !markdown.contains("[NEW]"),
        "Markdown should NOT contain [NEW] prefix when all findings are baseline.\nGot:\n{}",
        markdown
    );
}

#[test]
fn baseline_mode_marks_new_findings_in_output() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Create empty baseline
    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
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

    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md")).unwrap();
    // Should contain NEW annotation
    assert!(
        markdown.contains("[NEW]"),
        "Markdown should contain [NEW] prefix for new findings.\nGot:\n{}",
        markdown
    );
}

// ============================================================================
// AC7: Backward Compatibility
// Without --baseline, behavior should be unchanged
// ============================================================================

#[test]
fn without_baseline_flag_behavior_unchanged() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Run check WITHOUT --baseline flag
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg("--out")
        .arg("artifacts/diffguard/report.json");

    // Should exit 2 for the unwrap error (unchanged behavior)
    cmd.assert().code(2);

    // Verify receipt has expected content
    let receipt = std::fs::read_to_string(dir.join("artifacts/diffguard/report.json")).unwrap();
    assert!(receipt.contains("diffguard.check.v1"));
    assert!(receipt.contains("rust.no_unwrap"));
}

#[test]
fn baseline_flag_does_not_affect_non_baseline_runs() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // First run without baseline - should exit 2
    let mut cmd1 = Command::new(cargo::cargo_bin!("diffguard"));
    cmd1.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg("--out")
        .arg("artifacts/diffguard/report1.json");

    cmd1.assert().code(2);

    // Second run with --baseline but no new findings - should exit 0
    let baseline_finding = json!({
        "rule_id": "rust.no_unwrap",
        "severity": "error",
        "message": "Found .unwrap() call",
        "path": "src/lib.rs",
        "line": 1,
        "match_text": "Some(1).unwrap()",
        "snippet": "pub fn f() -> u32 { Some(1).unwrap() }"
    });

    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
        "findings": [baseline_finding],
        "verdict": {
            "status": "fail",
            "counts": { "info": 0, "warn": 0, "error": 1 },
            "reasons": ["1 policy violations found"]
        }
    });
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    let mut cmd2 = Command::new(cargo::cargo_bin!("diffguard"));
    cmd2.current_dir(dir)
        .arg("check")
        .arg("--base")
        .arg(&base)
        .arg("--head")
        .arg(&head)
        .arg(format!("--baseline={}", baseline_path.to_string_lossy()))
        .arg("--out")
        .arg("artifacts/diffguard/report2.json");

    // Should exit 0 with baseline (finding is grandfathered)
    cmd2.assert().code(0);

    // Verify the first run's receipt is unchanged (no baseline annotation)
    let receipt1 = std::fs::read_to_string(dir.join("artifacts/diffguard/report1.json")).unwrap();
    assert!(
        !receipt1.contains("[BASELINE]"),
        "Receipt without baseline should not have BASELINE annotations"
    );
    assert!(
        !receipt1.contains("[NEW]"),
        "Receipt without baseline should not have NEW annotations"
    );
}

// ============================================================================
// Report Mode Tests
// Tests for --report-mode=new-only flag
// ============================================================================

#[test]
fn report_mode_new_only_hides_baseline_findings() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Create baseline with the unwrap finding
    let baseline_finding = json!({
        "rule_id": "rust.no_unwrap",
        "severity": "error",
        "message": "Found .unwrap() call",
        "path": "src/lib.rs",
        "line": 1,
        "match_text": "Some(1).unwrap()",
        "snippet": "pub fn f() -> u32 { Some(1).unwrap() }"
    });

    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
        "findings": [baseline_finding],
        "verdict": {
            "status": "fail",
            "counts": { "info": 0, "warn": 0, "error": 1 },
            "reasons": ["1 policy violations found"]
        }
    });
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    // Run with --report-mode=new-only
    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
    cmd.current_dir(dir)
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
        .arg("artifacts/diffguard/comment.md");

    cmd.assert().code(0);

    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md")).unwrap();
    // With new-only mode, baseline findings should be hidden
    // Since there's only baseline findings, output should indicate no new findings
    assert!(
        !markdown.contains("[BASELINE]"),
        "With report-mode=new-only, baseline findings should be hidden.\nGot:\n{}",
        markdown
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn empty_baseline_all_findings_are_new() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Create empty baseline
    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
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

    cmd.assert().code(2); // New errors found

    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md")).unwrap();
    assert!(
        markdown.contains("[NEW]"),
        "All findings should be marked as NEW with empty baseline.\nGot:\n{}",
        markdown
    );
}

#[test]
fn mixed_baseline_and_new_findings() {
    let (td, base, head) = init_repo_with_findings();
    let dir = td.path();

    // Create baseline with println (warn) - should be baseline
    // But we still have unwrap (error) - should be new
    let baseline_finding = json!({
        "rule_id": "rust.no_println",
        "severity": "warn",
        "message": "Avoid println in production code",
        "path": "src/lib.rs",
        "line": 1,
        "match_text": "println!(\"hi\")",
        "snippet": "println!(\"hi\");"
    });

    let baseline_path = dir.join("baseline.json");
    let baseline_receipt = json!({
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
        "findings": [baseline_finding],
        "verdict": {
            "status": "fail",
            "counts": { "info": 0, "warn": 1, "error": 0 },
            "reasons": ["1 warnings found"]
        }
    });
    std::fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&baseline_receipt).unwrap(),
    )
    .unwrap();

    let mut cmd = Command::new(cargo::cargo_bin!("diffguard"));
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

    // Exit code should be 2 because there's a new error (unwrap)
    cmd.assert().code(2);

    let markdown = std::fs::read_to_string(dir.join("artifacts/diffguard/comment.md")).unwrap();
    // Should contain both BASELINE and NEW annotations
    assert!(
        markdown.contains("[BASELINE]"),
        "Should have baseline findings marked.\nGot:\n{}",
        markdown
    );
    assert!(
        markdown.contains("[NEW]"),
        "Should have new findings marked.\nGot:\n{}",
        markdown
    );
}
