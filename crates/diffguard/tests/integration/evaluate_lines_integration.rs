//! Integration tests for `evaluate_lines_with_overrides_and_language` component handoffs.
//!
//! These tests verify the integration between:
//! - Preprocessor (masking comments/strings)
//! - Suppression tracker
//! - Rule matcher
//! - The full CLI pipeline
//!
//! Unlike unit tests in diffguard-domain, these tests exercise the full CLI binary
//! with real git diffs to verify end-to-end behavior.

#[path = "test_repo.rs"]
mod test_repo;

use super::test_repo::TestRepo;

/// =============================================================================
/// Test: Force language CLI flag end-to-end
/// =============================================================================

/// Scenario: --language flag forces preprocessing for .txt files
///
/// Given: A .txt file with content that looks like Python comments
/// When: diffguard runs with --language python
/// Then: The comment preprocessing is applied based on Python rules
#[test]
fn given_txt_file_with_comment_when_language_python_then_comment_masked() {
    let repo = TestRepo::new();

    // Write a Python-style comment in a .txt file (which normally has no preprocessing)
    repo.write_file(
        "notes.txt",
        "# TODO: this looks like a comment but txt has no preprocessing\n",
    );
    let head_sha = repo.commit("add txt file");

    // Create a rule that matches "TODO" in non-comment context
    repo.write_config(
        r#"
use_built_in_rules = false

[[rule]]
id = "python.todo"
severity = "warn"
message = "TODO found"
languages = ["python"]
patterns = ["TODO"]
paths = ["**/*.txt"]
ignore_comments = true
ignore_strings = false
"#,
    );

    // Without --language, this would match because .txt has unknown language
    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(0); // .txt is unknown, rule requires python, so no match

    // Now with --language python, the # should be treated as a comment
    let result =
        repo.run_check_with_args(&head_sha, &["--no-default-rules", "--language", "python"]);
    result.assert_exit_code(0);
    let receipt = result.parse_receipt();
    // The TODO in the comment should be masked, so no finding
    assert_eq!(receipt.findings_count(), 0);
}

/// =============================================================================
/// Test: Multiple files with different languages via CLI
/// =============================================================================

/// Scenario: Multiple files with different extensions are evaluated with correct preprocessing
///
/// Given: Files with different extensions that require different preprocessing
/// When: diffguard runs
/// Then: Each file is preprocessed according to its detected language
#[test]
fn given_multiple_files_different_languages_then_correct_preprocessing() {
    let repo = TestRepo::new();

    // Write Python file with comment containing secret
    repo.write_file("script.py", "# secret in comment should be ignored\n");
    // Write Rust file with comment containing secret
    repo.write_file("code.rs", "// secret in comment should be ignored\n");
    // Write Go file with comment containing secret
    repo.write_file("main.go", "// secret in comment should be ignored\n");

    let head_sha = repo.commit("add multiple language files");

    // Rule that matches "secret" in code but not comments
    repo.write_config(
        r#"
use_built_in_rules = false

[[rule]]
id = "no_secrets"
severity = "error"
message = "secret found"
patterns = ["secret"]
ignore_comments = true
ignore_strings = false
"#,
    );

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    // No findings because secret is in comments for all files
    assert_eq!(receipt.findings_count(), 0);
}

/// =============================================================================
/// Test: JavaScript template literal masking
///
/// Scenario: JavaScript template literals are correctly preprocessed
///
/// Given: A JavaScript file with pattern inside template literal
/// When: diffguard runs with JavaScript preprocessing
/// Then: The pattern inside template literal is ignored (ignore_strings=true)
#[test]
fn given_js_template_literal_when_ignore_strings_then_not_flagged() {
    let repo = TestRepo::new();

    // secret is inside a string, so with ignore_strings=true it should be masked
    repo.write_file("app.js", "let x = `this has secret inside`;\n");
    let head_sha = repo.commit("add js file with template literal");

    repo.write_config(
        r#"
use_built_in_rules = false

[[rule]]
id = "no_secrets"
severity = "error"
message = "secret found"
languages = ["javascript"]
patterns = ["secret"]
ignore_comments = false
ignore_strings = true
"#,
    );

    // With ignore_strings=true, the secret inside the template literal should be masked
    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

/// =============================================================================
/// Test: evaluate_lines_with_overrides through CLI directory overrides
/// =============================================================================

/// Scenario: Directory-level rule overrides affect evaluation
///
/// Given: A directory with override configuration
/// When: diffguard runs
/// Then: The overrides are applied to matching files
#[test]
fn given_directory_override_when_check_then_override_applied() {
    let repo = TestRepo::new();

    // Root config defines the rule
    repo.write_config(
        r#"
use_built_in_rules = false

[[rule]]
id = "custom.no_unwrap"
severity = "error"
message = "No unwrap"
patterns = ["\\.unwrap\\("]
paths = ["**/*.rs"]
ignore_comments = true
ignore_strings = true
"#,
    );

    // Create subdirectory with override that disables the rule
    repo.write_file(
        "src/generated/.diffguard.toml",
        r#"
[[rule]]
id = "custom.no_unwrap"
enabled = false
"#,
    );

    repo.write_file("src/lib.rs", "pub fn a() { let _ = Some(1).unwrap(); }\n");
    repo.write_file(
        "src/generated/lib.rs",
        "pub fn b() { let _ = Some(2).unwrap(); }\n",
    );
    let head_sha = repo.commit("add unwraps with generated override");

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(2); // One error expected

    let receipt = result.parse_receipt();
    // src/lib.rs should have a finding
    assert!(receipt.has_finding_at("src/lib.rs", 1));
    // src/generated/lib.rs should NOT have a finding (disabled)
    assert!(!receipt.has_finding_at("src/generated/lib.rs", 1));
}

/// =============================================================================
/// Test: Suppression directive integration through CLI
/// =============================================================================

/// Scenario: Inline suppression directives work through the full pipeline
///
/// Given: A file with inline suppression directive
/// When: diffguard runs
/// Then: The suppressed finding does not appear in output
#[test]
fn given_inline_suppression_when_check_then_finding_suppressed() {
    let repo = TestRepo::new();

    repo.write_file(
        "src/lib.rs",
        "let x = Some(1).unwrap(); // diffguard: ignore rust.no_unwrap\n",
    );
    let head_sha = repo.commit("add file with suppression");

    // This uses the built-in rust.no_unwrap rule
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 0);
}

/// =============================================================================
/// Test: files_scanned and lines_scanned accuracy through CLI
/// =============================================================================

/// Scenario: Receipt correctly reports files_scanned and lines_scanned
///
/// Given: A diff with multiple files and lines
/// When: diffguard runs
/// Then: The receipt shows correct counts
#[test]
fn given_multiple_files_and_lines_then_counts_accurate() {
    let repo = TestRepo::new();

    // Create multiple files with multiple lines
    repo.write_file("a.txt", "line1\nline2\nline3\n");
    repo.write_file("b.txt", "line1\nline2\n");
    repo.write_file("c.txt", "line1\n");

    let head_sha = repo.commit("add multiple files");

    // Rule that matches "line1" in all files - using error severity so it causes exit code 2
    repo.write_config(
        r#"
use_built_in_rules = false

[[rule]]
id = "no_line1"
severity = "error"
message = "found line1"
patterns = ["line1"]
"#,
    );

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    // Should have 3 findings (one per file for line1)
    assert_eq!(receipt.findings_count(), 3);
    // Verify the files_scanned is in the receipt under diff
    let receipt_json: serde_json::Value =
        serde_json::from_str(result.receipt.as_ref().unwrap()).unwrap();
    let files_scanned = receipt_json["diff"]["files_scanned"].as_u64().unwrap();
    let lines_scanned = receipt_json["diff"]["lines_scanned"].as_u64().unwrap();
    assert_eq!(files_scanned, 3);
    assert_eq!(lines_scanned, 6); // 3 + 2 + 1 lines
}

/// =============================================================================
/// Test: max_findings truncation through CLI
/// =============================================================================

/// Scenario: When findings exceed max_findings, findings are truncated
///
/// Given: A diff with many findings
/// When: diffguard runs with --max-findings cap
/// Then: Only max_findings are returned in output
#[test]
fn given_many_findings_when_max_findings_set_then_truncated() {
    let repo = TestRepo::new();

    // Create many files with the same pattern
    for i in 0..10 {
        repo.write_file(&format!("file{}.txt", i), "pattern\n");
    }

    let head_sha = repo.commit("add many files");

    // Rule that matches " pattern" - using error severity so it causes exit code 2
    repo.write_config(
        r#"
use_built_in_rules = false

[[rule]]
id = "no_pattern"
severity = "error"
message = "found pattern"
patterns = ["pattern"]
"#,
    );

    // Set max-findings to 3
    let result =
        repo.run_check_with_args(&head_sha, &["--no-default-rules", "--max-findings", "3"]);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    // Should only have 3 findings (the max)
    assert_eq!(receipt.findings_count(), 3);
    // Exit code is still 2 (errors found, policy fails)
    assert_eq!(result.exit_code, 2);
}

/// =============================================================================
/// Test: MatchMode::Absent through CLI
/// =============================================================================

/// Scenario: Absent mode rules fire when pattern is missing
///
/// Given: A file that does NOT contain an expected pattern
/// When: diffguard runs
/// Then: The absent finding is reported
#[test]
fn given_missing_expected_pattern_when_absent_mode_then_finding() {
    let repo = TestRepo::new();

    repo.write_file("config.py", "database = 'sqlite'\n");
    let head_sha = repo.commit("add config without logging");

    repo.write_config(
        r#"
use_built_in_rules = false

[[rule]]
id = "require_logging"
severity = "error"
message = "logging config missing"
match_mode = "absent"
patterns = ["logging"]
paths = ["**/*.py"]
"#,
    );

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.findings_count(), 1);
    let rule_ids = receipt.finding_rule_ids();
    assert!(rule_ids.contains(&"require_logging".to_string()));
}
