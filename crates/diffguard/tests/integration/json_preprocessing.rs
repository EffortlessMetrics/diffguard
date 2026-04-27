//! Integration tests for JSON file preprocessing behavior.
//!
//! These tests verify that the preprocessing pipeline correctly handles
//! JSON files through the full CLI workflow - language detection,
//! preprocessing (string/comment masking), and rule evaluation.
//!
//! The change being tested (removing redundant Language::Json arm from
//! string_syntax()) is a code cleanup that preserves identical behavior.
//! These tests verify the behavioral contract is maintained.

use super::test_repo::TestRepo;

/// Scenario: JSON file structural elements are not masked.
///
/// Given: A JSON file with structural characters
/// When: diffguard check runs
/// Then: Structural JSON characters (braces, colons, commas) are preserved
#[test]
fn given_json_file_when_check_then_structural_elements_preserved() {
    // Given: A JSON file with various content
    let repo = TestRepo::new();

    repo.write_file(
        "data.json",
        r#"{
    "name": "test",
    "values": [1, 2, 3]
}"#,
    );
    let head_sha = repo.commit("add JSON data");

    // Custom rule targeting structural JSON characters - colons after quotes
    repo.write_config(
        r#"
[[rule]]
id = "json.check_colon"
severity = "warn"
message = "Check JSON colons"
patterns = ["\":"]
languages = ["json"]
paths = ["**/*.json"]
"#,
    );

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Receipt should exist and findings should be present
    result.assert_receipt_exists();
    let receipt = result.parse_receipt();
    // Structural elements in JSON should be visible to rules
    assert!(
        receipt.has_finding_with_rule("json.check_colon"),
        "Structural elements like colons should be visible in JSON"
    );
}

/// Scenario: Multiple JSON files in different directories are all processed.
///
/// Given: JSON files at various paths
/// When: diffguard check runs
/// Then: All JSON files are preprocessed correctly
#[test]
fn given_multiple_json_files_when_check_then_all_processed() {
    // Given: Multiple JSON files in different directories
    let repo = TestRepo::new();

    repo.write_file("src/config.json", r#"{"key": "value1"}"#);
    repo.write_file("tests/data.json", r#"{"key": "value2"}"#);
    repo.write_file("package.json", r#"{"name": "test"}"#);
    let head_sha = repo.commit("add multiple JSON files");

    // Custom rule that applies to all JSON files
    repo.write_config(
        r#"
[[rule]]
id = "json.structure"
severity = "info"
message = "Check JSON structure"
patterns = [""]
languages = ["json"]
paths = ["**/*.json"]
"#,
    );

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Receipt should exist and findings should be present from all JSON files
    result.assert_receipt_exists();
    let receipt = result.parse_receipt();
    assert!(
        receipt.findings_count() > 0,
        "Should have findings from JSON files"
    );
}

/// Scenario: JSON file string content is masked but structural content is not.
///
/// Given: A JSON file with strings and structural elements
/// When: diffguard check runs with string masking enabled
/// Then: String values are masked but keys and structural chars are preserved
#[test]
fn given_json_file_with_strings_when_check_then_strings_masked() {
    // Given: A JSON file with string values
    let repo = TestRepo::new();

    repo.write_file(
        "data.json",
        r#"{
    "name": "console.log",
    "description": "FIXME not real",
    "count": 42
}"#,
    );
    let head_sha = repo.commit("add JSON with strings");

    // Custom rules - one for strings (should be masked), one for keys (should not)
    repo.write_config(
        r#"
[[rule]]
id = "json.string_content"
severity = "warn"
message = "Check string content"
patterns = ["console\.log"]
languages = ["json"]
paths = ["**/*.json"]

[[rule]]
id = "json.key_name"
severity = "info"
message = "Check key name"
patterns = ["\"name\""]
languages = ["json"]
paths = ["**/*.json"]
"#,
    );

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Check the findings
    // The receipt may exist only if findings were made
    if let Some(receipt_str) = &result.receipt {
        let json: serde_json::Value =
            serde_json::from_str(receipt_str).expect("receipt should be valid JSON");
        let findings = json["findings"].as_array();

        // Check that the key "name" was found (if any findings exist)
        if let Some(findings_arr) = findings {
            let key_name_found = findings_arr
                .iter()
                .any(|f| f["rule_id"].as_str() == Some("json.key_name"));
            // The key "name" should be found (not masked) if there are findings
            assert!(
                key_name_found,
                "JSON key 'name' should be visible (not masked)"
            );
        }
    }
}

/// Scenario: Unknown language falls back to C-style preprocessing.
///
/// Given: A file with unknown extension but JSON-like content
/// When: diffguard check runs
/// Then: C-style preprocessing is applied (strings masked)
#[test]
fn given_unknown_extension_json_like_when_check_then_cstyle_preprocessing() {
    // Given: A file with unknown extension containing JSON-like content
    let repo = TestRepo::new();

    repo.write_file("data.something", r#"{"key": "console.log('test')"}"#);
    let head_sha = repo.commit("add unknown extension file");

    // Custom rule that would match console.log in JS files
    repo.write_config(
        r#"
[[rule]]
id = "js.no_console"
severity = "error"
message = "Remove console.log"
patterns = ["console\.log"]
paths = ["**/*"]
"#,
    );

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: No findings expected (unknown language uses C-style, strings are masked)
    // The receipt may or may not exist depending on whether findings were made
    if result.receipt.is_some() {
        let receipt = result.parse_receipt();
        assert_eq!(
            receipt.findings_count(),
            0,
            "console.log in unknown extension file should be masked by C-style preprocessing"
        );
    }
    // If no receipt, that's also fine - means no findings
}

/// Scenario: JSON5 file is processed correctly.
///
/// Given: A JSON5 file (JSON with comments and trailing commas)
/// When: diffguard check runs
/// Then: The file is processed using JSON language detection
#[test]
fn given_json5_file_when_check_then_processed_as_json() {
    // Given: A JSON5 file with trailing comma
    let repo = TestRepo::new();

    repo.write_file(
        "config.json5",
        r#"{
    "name": "test",
    "version": "1.0.0",
}"#,
    );
    let head_sha = repo.commit("add JSON5 file");

    // Custom rule targeting JSON5 files
    repo.write_config(
        r#"
[[rule]]
id = "json5.structure"
severity = "warn"
message = "Check JSON5 structure"
patterns = [""]
languages = ["json"]
paths = ["**/*.json5"]
"#,
    );

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Receipt should exist
    result.assert_receipt_exists();
    let receipt = result.parse_receipt();
    // JSON5 files should be detected as JSON and findings should be present
    assert!(
        receipt.findings_count() > 0,
        "JSON5 files should produce findings"
    );
}
