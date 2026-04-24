//! BDD integration tests for JSON file preprocessing and rule evaluation.
//!
//! These tests verify the end-to-end flow for JSON files:
//! - Language detection for .json files
//! - Preprocessing (string and comment masking) for JSON content
//! - Rule evaluation against preprocessed JSON
//! - CLI entrypoint with JSON files
//!
//! The issue (work-05d48a76) is about removing a redundant `Language::Json`
//! match arm in `string_syntax()`. This is a cosmetic change - the functional
//! behavior is identical before and after (both produce StringSyntax::CStyle
//! via wildcard). These integration tests verify the full pipeline still works.

use super::test_repo::TestRepo;

/// Scenario: JSON files are processed through the full pipeline.
/// Given: A .json file with content
/// When: diffguard check runs
/// Then: The JSON file is processed without errors
///
/// Flow: CLI -> git diff -> parse diff -> detect language (Json) ->
///       preprocess -> evaluate rules -> produce findings
#[test]
fn given_json_file_when_check_then_processed() {
    // Given: A repository with a simple JSON file
    let repo = TestRepo::new();

    repo.write_file("data/config.json", r#"{"key": "value"}"#);
    let head_sha = repo.commit("add JSON config");

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Should complete without errors
    assert!(
        result.exit_code == 0 || result.exit_code == 2,
        "Check should complete successfully, got exit code {}",
        result.exit_code
    );
}

/// Scenario: JSON and Unknown languages both process through the pipeline.
/// Given: A .json file and a .unknown file
/// When: diffguard check runs
/// Then: Both files are processed without errors
///
/// This verifies that JSON (now via wildcard) and Unknown have identical
/// pipeline behavior.
#[test]
fn given_json_and_unknown_files_when_check_then_both_processed() {
    // Given: A repository with JSON and unknown files
    let repo = TestRepo::new();

    repo.write_file("data/config.json", r#"{"key": "value"}"#);
    repo.write_file("data/config.unknown", "some content");
    let head_sha = repo.commit("add files");

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Should complete without errors for both files
    assert!(
        result.exit_code == 0 || result.exit_code == 2,
        "Check should complete successfully for both files"
    );
}

/// Scenario: JSONC files (JSON with C-style comments) are handled correctly.
/// Given: A JSONC file (JSON with comments) containing a pattern
/// When: diffguard check runs
/// Then: The pattern in the comment is detected
///
/// Note: Standard JSON doesn't support comments, but the preprocessor
/// handles JSON as CStyle which includes // and /* */ comments.
#[test]
fn given_jsonc_file_with_pattern_in_comment_when_check_then_rule_fires() {
    // Given: A repository with a JSONC-like file
    let repo = TestRepo::new();

    // Create a config with a catch-all rule
    repo.write_config(
        r#"
[[rule]]
id = "all.no_fixme"
severity = "error"
message = "FIXME must be resolved"
patterns = ["FIXME"]
paths = ["**/*"]
"#,
    );

    // JSON with C-style line comment containing FIXME
    repo.write_file(
        "data/config.jsonc",
        r#"{
    // FIXME: this is a temporary workaround
    "setting": "value"
}"#,
    );

    let head_sha = repo.commit("add JSONC file with FIXME");

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: FIXME in comment should be detected
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(
        receipt.has_finding_at("data/config.jsonc", 2),
        "FIXME in JSONC comment should be flagged"
    );
}

/// Scenario: All CStyle languages (via wildcard) preprocess without errors.
/// Given: Files with .json, .c, .cpp, .java extensions
/// When: diffguard check runs
/// Then: All files are processed without errors
///
/// This tests that the wildcard handling is consistent across all
/// CStyle languages including JSON (now via wildcard after the fix).
#[test]
fn given_cstyle_languages_when_check_then_all_processed() {
    // Given: A repository with multiple C-style language files
    let repo = TestRepo::new();

    // Create files with C-style comments
    repo.write_file("data.json", "// C-style comment in JSON\n{}");
    repo.write_file("main.c", "// C-style comment in C\nint main() {}");
    repo.write_file("main.cpp", "// C-style comment in C++\nint main() {}");
    repo.write_file(
        "Main.java",
        "// C-style comment in Java\npublic class Main {}",
    );

    let head_sha = repo.commit("add all C-style files");

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: All files should be processed without errors
    assert!(
        result.exit_code == 0 || result.exit_code == 2,
        "All C-style files should be processed successfully"
    );
}

/// Scenario: CLI flow with JSON file through all components.
/// Given: A complete diff scenario with JSON file changes
/// When: diffguard check --base ... --head ... runs
/// Then: All components interact correctly
#[test]
fn given_json_diff_scenario_when_check_then_full_pipeline_works() {
    // Given: A repository with initial JSON
    let repo = TestRepo::new();

    repo.write_file("config.json", r#"{"setting": "original"}"#);
    let _base_sha = repo.commit("initial config");

    // Modify the JSON file to create a diff
    repo.write_file(
        "config.json",
        r#"{"setting": "modified", "newkey": "value"}"#,
    );
    let head_sha = repo.commit("modify config");

    // When: Running check (no custom rules, just testing pipeline)
    let result = repo.run_check(&head_sha);

    // Then: Should complete without errors
    assert!(
        result.exit_code == 0 || result.exit_code == 2,
        "Check should complete successfully, got exit code {}",
        result.exit_code
    );
}

/// Scenario: Multiple JSON files in different directories are processed.
/// Given: A repository with JSON files in multiple subdirectories
/// When: diffguard check runs
/// Then: All JSON files are processed correctly
#[test]
fn given_multiple_json_files_when_check_then_all_processed() {
    // Given: A repository with multiple JSON files
    let repo = TestRepo::new();

    repo.write_file("frontend/config.json", r#"{"key": "value"}"#);
    repo.write_file("backend/config.json", r#"{"key": "value"}"#);
    repo.write_file("shared/data.json", r#"{"key": "value"}"#);

    let head_sha = repo.commit("add JSON files in subdirs");

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Should complete without errors for all files
    assert!(
        result.exit_code == 0 || result.exit_code == 2,
        "All JSON files should be processed successfully"
    );
}
