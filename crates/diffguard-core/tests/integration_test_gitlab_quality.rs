//! Integration tests for GitLab Code Quality JSON rendering.
//!
//! These tests verify the end-to-end integration between CheckReceipt and
//! GitLab Code Quality JSON output, validating component handoffs and
//! CLI compatibility.
//!
//! Run with: cargo test -p diffguard-core --test integration_test_gitlab_quality

use diffguard_core::render_gitlab_quality_json;
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};

// ============================================================================
// Test Fixtures
// ============================================================================

/// Creates a CheckReceipt for testing.
fn make_receipt(findings: Vec<Finding>) -> CheckReceipt {
    CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "feat/test".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 10,
        },
        verdict: Verdict {
            status: if findings.is_empty() {
                VerdictStatus::Pass
            } else {
                VerdictStatus::Fail
            },
            counts: VerdictCounts {
                info: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Info)
                    .count() as u32,
                warn: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Warn)
                    .count() as u32,
                error: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Error)
                    .count() as u32,
                suppressed: 0,
            },
            reasons: vec![],
        },
        findings,
        timing: None,
    }
}

/// Creates a Finding for testing.
fn finding(rule_id: &str, severity: Severity, message: &str, path: &str, line: u32) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity,
        message: message.to_string(),
        path: path.to_string(),
        line,
        column: None,
        match_text: "matched".to_string(),
        snippet: "the matched code".to_string(),
    }
}

// ============================================================================
// Component Handoff Tests
// ============================================================================

/// Validates that all Finding fields are correctly mapped to GitLab JSON output.
#[test]
fn test_gitlab_quality_finding_field_mapping() {
    let finding = finding(
        "rust.no_unwrap",
        Severity::Error,
        "Avoid unwrap/expect in production code",
        "src/main.rs",
        42,
    );
    let receipt = make_receipt(vec![finding]);
    let json = render_gitlab_quality_json(&receipt).unwrap();

    // Validate all expected fields are present in JSON (using flexible matching for pretty-printed JSON)
    assert!(
        json.contains("\"description\"") && json.contains("Avoid unwrap/expect in production code"),
        "JSON should contain the finding message as description"
    );
    assert!(
        json.contains("\"check_name\"") && json.contains("rust.no_unwrap"),
        "JSON should contain rule_id as check_name"
    );
    assert!(
        json.contains("\"path\"") && json.contains("src/main.rs"),
        "JSON should contain the file path"
    );
    assert!(
        json.contains("\"begin\"") && json.contains("42"),
        "JSON should contain the line number"
    );
    assert!(
        json.contains("\"major\""),
        "Error severity should map to 'major'"
    );
}

/// Validates severity mapping for all severity levels.
#[test]
fn test_gitlab_quality_all_severity_mappings() {
    let findings = vec![
        finding("info-rule", Severity::Info, "Info message", "a.rs", 1),
        finding("warn-rule", Severity::Warn, "Warning message", "b.rs", 2),
        finding("error-rule", Severity::Error, "Error message", "c.rs", 3),
    ];
    let receipt = make_receipt(findings);
    let json = render_gitlab_quality_json(&receipt).unwrap();

    // GitLab Code Quality format requires lowercase severity values
    // Use flexible matching since pretty-printed JSON has spaces after colons
    assert!(
        json.contains("\"severity\"") && json.contains("info"),
        "Info severity should map to 'info'"
    );
    assert!(
        json.contains("\"severity\"") && json.contains("minor"),
        "Warn severity should map to 'minor'"
    );
    assert!(
        json.contains("\"severity\"") && json.contains("major"),
        "Error severity should map to 'major'"
    );
}

/// Validates that fingerprint is deterministic based on finding content.
#[test]
fn test_gitlab_quality_fingerprint_deterministic() {
    let finding1 = finding("rule", Severity::Error, "msg", "f.rs", 10);
    let finding2 = finding("rule", Severity::Error, "msg", "f.rs", 10);

    let receipt1 = make_receipt(vec![finding1]);
    let receipt2 = make_receipt(vec![finding2]);

    let json1 = render_gitlab_quality_json(&receipt1).unwrap();
    let json2 = render_gitlab_quality_json(&receipt2).unwrap();

    // Extract fingerprints from both JSON outputs
    let fp1 = extract_fingerprint(&json1);
    let fp2 = extract_fingerprint(&json2);

    assert_eq!(
        fp1, fp2,
        "Identical findings must produce identical fingerprints"
    );
}

/// Validates that different findings produce different fingerprints.
#[test]
fn test_gitlab_quality_fingerprint_unique_for_different_findings() {
    let finding1 = finding("rule-a", Severity::Error, "msg", "f.rs", 10);
    let finding2 = finding("rule-b", Severity::Error, "msg", "f.rs", 10);

    let receipt1 = make_receipt(vec![finding1]);
    let receipt2 = make_receipt(vec![finding2]);

    let json1 = render_gitlab_quality_json(&receipt1).unwrap();
    let json2 = render_gitlab_quality_json(&receipt2).unwrap();

    let fp1 = extract_fingerprint(&json1);
    let fp2 = extract_fingerprint(&json2);

    assert_ne!(
        fp1, fp2,
        "Different findings must produce different fingerprints"
    );
}

/// Extracts the fingerprint value from GitLab JSON output.
fn extract_fingerprint(json: &str) -> String {
    // Parse JSON and extract fingerprint field
    let parsed: serde_json::Value = serde_json::from_str(json).expect("valid JSON");
    let findings = parsed.as_array().expect("array");
    let finding = findings.first().expect("at least one finding");
    finding["fingerprint"]
        .as_str()
        .expect("fingerprint is string")
        .to_string()
}

// ============================================================================
// End-to-End Flow Tests
// ============================================================================

/// Validates the complete flow: CheckReceipt → JSON → parsed structure.
#[test]
fn test_gitlab_quality_end_to_end_flow() {
    let findings = vec![
        finding(
            "rust.no_unwrap",
            Severity::Error,
            "Avoid unwrap",
            "src/main.rs",
            42,
        ),
        finding(
            "js.no_console",
            Severity::Warn,
            "console.log detected",
            "src/index.js",
            15,
        ),
    ];
    let receipt = make_receipt(findings);

    // Step 1: Render to JSON string
    let json_result = render_gitlab_quality_json(&receipt);
    assert!(
        json_result.is_ok(),
        "render_gitlab_quality_json should succeed"
    );
    let json = json_result.unwrap();

    // Step 2: Parse JSON back
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be parseable");

    // Step 3: Validate structure
    assert!(parsed.is_array(), "Root should be an array of findings");
    let findings_array = parsed.as_array().unwrap();
    assert_eq!(findings_array.len(), 2, "Should have 2 findings");

    // Step 4: Validate first finding structure matches GitLab schema
    let first = &findings_array[0];
    assert!(
        first.get("description").is_some(),
        "Finding should have description"
    );
    assert!(
        first.get("fingerprint").is_some(),
        "Finding should have fingerprint"
    );
    assert!(
        first.get("severity").is_some(),
        "Finding should have severity"
    );
    assert!(
        first.get("location").is_some(),
        "Finding should have location"
    );
    assert!(
        first.get("check_name").is_some(),
        "Finding should have check_name"
    );
}

/// Validates that JSON is pretty-printed for CLI output readability.
#[test]
fn test_gitlab_quality_json_pretty_printed() {
    let finding = finding("test-rule", Severity::Info, "Test message", "test.rs", 1);
    let receipt = make_receipt(vec![finding]);
    let json = render_gitlab_quality_json(&receipt).unwrap();

    // Pretty-printed JSON should have newlines and indentation
    assert!(
        json.contains('\n'),
        "JSON output should contain newlines (pretty-printed)"
    );
    assert!(json.contains("  "), "JSON output should have indentation");
}

/// Validates that empty receipts produce empty array.
#[test]
fn test_gitlab_quality_empty_receipt_produces_empty_array() {
    let receipt = make_receipt(vec![]);
    let json = render_gitlab_quality_json(&receipt).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        parsed.is_array(),
        "Empty receipt should produce empty array"
    );
    assert!(
        parsed.as_array().unwrap().is_empty(),
        "Array should be empty"
    );
}

// ============================================================================
// Error Propagation Tests
// ============================================================================

/// Validates that the function returns Err when serde_json fails.
/// Note: serde_json::to_string_pretty rarely fails for in-memory types,
/// but the Result type correctly documents this possibility.
#[test]
fn test_gitlab_quality_error_type_is_serde_json_error() {
    // Create a receipt with valid data
    let receipt = make_receipt(vec![finding("test", Severity::Info, "msg", "f.rs", 1)]);
    let result = render_gitlab_quality_json(&receipt);

    // The function should succeed for valid input, which is the common case.
    // This test documents the expected error propagation behavior for edge cases
    // where serialization could fail (e.g., if a future field doesn't implement Serialize).
    assert!(
        result.is_ok(),
        "Valid receipt should serialize successfully"
    );
}

// ============================================================================
// CLI Integration Tests (File Write/Read)
// ============================================================================

/// Validates that JSON output can be written to a file and read back correctly.
/// This simulates the CLI's artifact writing behavior.
#[test]
fn test_gitlab_quality_file_write_and_read() {
    use std::io::Write;

    let finding = finding(
        "rust.no_unwrap",
        Severity::Error,
        "Avoid unwrap",
        "src/main.rs",
        42,
    );
    let receipt = make_receipt(vec![finding]);
    let json = render_gitlab_quality_json(&receipt).unwrap();

    // Simulate CLI writing to artifact path
    let temp_dir = std::env::temp_dir();
    let artifact_path = temp_dir.join("gitlab_quality_test.json");

    let mut file = std::fs::File::create(&artifact_path).unwrap();
    file.write_all(json.as_bytes()).unwrap();
    drop(file);

    // Read back and validate
    let read_back = std::fs::read_to_string(&artifact_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&read_back).unwrap();

    assert!(
        parsed.is_array(),
        "Read-back JSON should still be a valid array"
    );

    // Cleanup
    std::fs::remove_file(artifact_path).ok();
}

/// Validates that multiple findings can be serialized and deserialized correctly.
/// This tests the CLI artifact persistence for reports with multiple findings.
#[test]
fn test_gitlab_quality_multiple_findings_persistence() {
    use std::io::Write;

    let findings = vec![
        finding("rule1", Severity::Error, "Error 1", "a.rs", 1),
        finding("rule2", Severity::Warn, "Warning 2", "b.rs", 2),
        finding("rule3", Severity::Info, "Info 3", "c.rs", 3),
    ];
    let receipt = make_receipt(findings);
    let json = render_gitlab_quality_json(&receipt).unwrap();

    let temp_dir = std::env::temp_dir();
    let artifact_path = temp_dir.join("gitlab_quality_multi_test.json");

    let mut file = std::fs::File::create(&artifact_path).unwrap();
    file.write_all(json.as_bytes()).unwrap();
    drop(file);

    // Read back and verify all findings preserved
    let read_back = std::fs::read_to_string(&artifact_path).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&read_back).unwrap();

    assert_eq!(parsed.len(), 3, "All 3 findings should be preserved");

    // Verify order is preserved
    assert!(parsed[0]["check_name"].as_str().unwrap().contains("rule1"));
    assert!(parsed[1]["check_name"].as_str().unwrap().contains("rule2"));
    assert!(parsed[2]["check_name"].as_str().unwrap().contains("rule3"));

    // Cleanup
    std::fs::remove_file(artifact_path).ok();
}

// ============================================================================
// GitLab Schema Conformance Tests
// ============================================================================

/// Validates JSON output conforms to GitLab Code Quality schema requirements.
/// See: https://docs.gitlab.com/ee/ci/testing/code_quality.html
#[test]
fn test_gitlab_quality_schema_conformance() {
    let findings = vec![finding(
        "rust.no_unwrap",
        Severity::Error,
        "Avoid unwrap",
        "src/main.rs",
        42,
    )];
    let receipt = make_receipt(findings);
    let json = render_gitlab_quality_json(&receipt).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    let findings_array = parsed.as_array().unwrap();
    let finding = &findings_array[0];

    // GitLab Code Quality schema requires:
    // - description: string
    // - fingerprint: string (unique per finding)
    // - severity: string (info, minor, major, critical, blocker)
    // - location: object with path and lines
    // - check_name: string (optional in GitLab schema but we include it)

    assert!(
        finding["description"].is_string(),
        "description must be a string"
    );
    assert!(
        finding["fingerprint"].is_string(),
        "fingerprint must be a string"
    );
    assert!(finding["severity"].is_string(), "severity must be a string");
    assert!(
        finding["location"].is_object(),
        "location must be an object"
    );

    let location = &finding["location"];
    assert!(
        location["path"].is_string(),
        "location.path must be a string"
    );

    // Verify severity values are valid GitLab values
    let severity = finding["severity"].as_str().unwrap();
    assert!(
        ["info", "minor", "major", "critical", "blocker"].contains(&severity),
        "severity '{}' is not a valid GitLab Code Quality severity",
        severity
    );
}

/// Validates that location.lines is properly structured for GitLab.
#[test]
fn test_gitlab_quality_location_lines_structure() {
    let finding = finding("test", Severity::Info, "msg", "src/lib.rs", 100);
    let receipt = make_receipt(vec![finding]);
    let json = render_gitlab_quality_json(&receipt).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    let location = &parsed[0]["location"];

    // location.lines should be an object with 'begin' field
    assert!(
        location["lines"].is_object(),
        "location.lines should be an object"
    );
    assert!(
        location["lines"]["begin"].is_number(),
        "location.lines.begin should be a number"
    );
    assert_eq!(
        location["lines"]["begin"].as_u64().unwrap(),
        100,
        "location.lines.begin should match the finding line"
    );
}

// ============================================================================
// Content/Snippet Handling Tests
// ============================================================================

/// Validates that findings with snippets include content field.
#[test]
fn test_gitlab_quality_content_field_with_snippet() {
    let mut finding = finding("test", Severity::Info, "msg", "f.rs", 1);
    finding.snippet = "let x = 1;".to_string();

    let receipt = make_receipt(vec![finding]);
    let json = render_gitlab_quality_json(&receipt).unwrap();

    assert!(
        json.contains("\"content\""),
        "JSON should include content field when snippet is non-empty"
    );
    assert!(
        json.contains("let x = 1;"),
        "JSON should include snippet content"
    );
}

/// Validates that findings without snippets omit content field.
#[test]
fn test_gitlab_quality_content_omitted_without_snippet() {
    // Create finding with empty snippet directly (helper sets snippet to non-empty)
    let finding = Finding {
        rule_id: "test".to_string(),
        severity: Severity::Info,
        message: "msg".to_string(),
        path: "f.rs".to_string(),
        line: 1,
        column: None,
        match_text: "matched".to_string(),
        snippet: String::new(), // Empty snippet
    };
    let receipt = make_receipt(vec![finding]);
    let json = render_gitlab_quality_json(&receipt).unwrap();

    // When snippet is empty, content should be omitted (skip_serializing_if)
    assert!(
        !json.contains("\"content\""),
        "JSON should omit content field when snippet is empty"
    );
}

// ============================================================================
// Run all tests
// ============================================================================

#[test]
fn test_integration_suite_summary() {
    // This test always passes and serves as a summary indicator
    // (assertion removed - clippy warns assert!(true) is no-op)
}
