//! Snapshot tests for SensorFinding JSON serialization (work-a3ef8bf6)
//!
//! This change is a doc-only fix: wrapping `rule_id` in backticks in the doc comment
//! for SensorFinding::code. These snapshot tests capture the JSON serialization
//! output as a baseline to detect any future changes to the struct or its serialization.
//!
//! Feature: snapshot-test-coverage for work-a3ef8bf6

use diffguard_types::{SensorFinding, SensorLocation, Severity};
use serde_json::Value;

/// Helper to create a SensorFinding with given code field.
fn make_finding(code: &str) -> SensorFinding {
    SensorFinding {
        check_id: "diffguard.pattern".to_string(),
        code: code.to_string(),
        severity: Severity::Warn,
        message: "test message".to_string(),
        location: SensorLocation {
            path: "test.rs".to_string(),
            line: 1,
            column: Some(10),
        },
        fingerprint: "a".repeat(64),
        help: None,
        url: None,
        data: None,
    }
}

/// Helper to create a SensorFinding with all optional fields populated.
fn make_finding_full(code: &str) -> SensorFinding {
    SensorFinding {
        check_id: "diffguard.pattern".to_string(),
        code: code.to_string(),
        severity: Severity::Error,
        message: "Full finding with all fields".to_string(),
        location: SensorLocation {
            path: "src/main.rs".to_string(),
            line: 42,
            column: Some(20),
        },
        fingerprint: "abcd".repeat(16), // 64 hex chars
        help: Some("See https://docs.example.com/rule".to_string()),
        url: Some("https://example.com/rule".to_string()),
        data: Some(serde_json::json!({
            "snippet": "fn example() { unwrap!() }",
            "match_text": "unwrap!()"
        })),
    }
}

// ============================================================================
// Snapshot Tests: SensorFinding JSON Serialization
// ============================================================================

/// Snapshot: SensorFinding with typical rule code serializes correctly.
/// Input: code = "rust.no_unwrap"
/// Output shape: JSON object with check_id, code, severity, message, location, fingerprint
#[test]
fn snapshot_sensor_finding_typical_code() {
    let finding = make_finding("rust.no_unwrap");
    let json: Value = serde_json::to_value(&finding).expect("serialize to JSON");
    let json_str = serde_json::to_string_pretty(&finding).expect("serialize to string");

    // Verify structure
    assert!(json["check_id"].is_string());
    assert!(json["code"].is_string());
    assert!(json["severity"].is_string());
    assert!(json["message"].is_string());
    assert!(json["location"].is_object());
    assert!(json["fingerprint"].is_string());
    assert!(json["help"].is_null());
    assert!(json["url"].is_null());
    assert!(json["data"].is_null());

    // Snapshot: code field value
    assert_eq!(
        json["code"].as_str().expect("code is string"),
        "rust.no_unwrap"
    );

    // Snapshot: severity serializes to string
    assert_eq!(
        json["severity"].as_str().expect("severity is string"),
        "warn"
    );

    // Snapshot: location structure
    assert_eq!(
        json["location"]["path"].as_str().expect("path is string"),
        "test.rs"
    );
    assert_eq!(json["location"]["line"].as_u64().expect("line is u64"), 1);
    assert_eq!(
        json["location"]["column"].as_u64().expect("column is u64"),
        10
    );

    // Snapshot: fingerprint is 64 hex chars
    assert_eq!(json["fingerprint"].as_str().expect("fingerprint").len(), 64);

    // Print snapshot for reference
    println!("SNAPSHOT: typical_code_json =\n{}", json_str);
}

/// Snapshot: SensorFinding with all fields populated serializes correctly.
/// Input: full finding with help, url, data
/// Output shape: JSON object with all optional fields present
#[test]
fn snapshot_sensor_finding_full_fields() {
    let finding = make_finding_full("security.hardcoded_secret");
    let json: Value = serde_json::to_value(&finding).expect("serialize to JSON");
    let json_str = serde_json::to_string_pretty(&finding).expect("serialize to string");

    // Verify structure
    assert_eq!(
        json["check_id"].as_str().expect("check_id"),
        "diffguard.pattern"
    );
    assert_eq!(
        json["code"].as_str().expect("code"),
        "security.hardcoded_secret"
    );
    assert_eq!(json["severity"].as_str().expect("severity"), "error");
    assert_eq!(
        json["message"].as_str().expect("message"),
        "Full finding with all fields"
    );

    // Snapshot: optional fields present
    assert!(json["help"].is_string());
    assert!(json["url"].is_string());
    assert!(json["data"].is_object());

    // Snapshot: data contents
    assert_eq!(
        json["data"]["snippet"].as_str().expect("snippet"),
        "fn example() { unwrap!() }"
    );
    assert_eq!(
        json["data"]["match_text"].as_str().expect("match_text"),
        "unwrap!()"
    );

    // Print snapshot for reference
    println!("SNAPSHOT: full_fields_json =\n{}", json_str);
}

/// Snapshot: SensorFinding code field accepts dot-separated rule codes.
/// Input: code = "python.no_print"
/// Output: code field preserves dots
#[test]
fn snapshot_sensor_finding_dotted_rule_code() {
    let finding = make_finding("python.no_print");
    let json: Value = serde_json::to_value(&finding).expect("serialize to JSON");

    assert_eq!(json["code"].as_str().expect("code"), "python.no_print");
}

/// Snapshot: SensorFinding code field accepts alphanumeric with dots.
/// Input: code = "terraform.security.S3_bucket_acl"
/// Output: code field preserves full string
#[test]
fn snapshot_sensor_finding_complex_rule_code() {
    let finding = make_finding("terraform.security.S3_bucket_acl");
    let json: Value = serde_json::to_value(&finding).expect("serialize to JSON");

    assert_eq!(
        json["code"].as_str().expect("code"),
        "terraform.security.S3_bucket_acl"
    );
}

/// Snapshot: SensorFinding with empty code field serializes.
/// Input: code = ""
/// Output: empty string preserved in code field
#[test]
fn snapshot_sensor_finding_empty_code() {
    let finding = make_finding("");
    let json: Value = serde_json::to_value(&finding).expect("serialize to JSON");
    let json_str = serde_json::to_string_pretty(&finding).expect("serialize to string");

    assert_eq!(json["code"].as_str().expect("code"), "");

    // Print snapshot for reference
    println!("SNAPSHOT: empty_code_json =\n{}", json_str);
}

/// Snapshot: SensorFinding with all severity variants serialize to lowercase strings.
/// Input: various severity values
/// Output: severity always serializes to "info", "warn", or "error"
#[test]
fn snapshot_sensor_finding_all_severities() {
    for (severity, expected) in [
        (Severity::Info, "info"),
        (Severity::Warn, "warn"),
        (Severity::Error, "error"),
    ] {
        let mut finding = make_finding("test.rule");
        finding.severity = severity;
        let json: Value = serde_json::to_value(&finding).expect("serialize to JSON");

        assert_eq!(
            json["severity"].as_str().expect("severity is string"),
            expected,
            "severity {:?} should serialize to {}",
            severity,
            expected
        );
    }
}

/// Snapshot: SensorFinding fingerprint is exactly 64 hex characters.
/// Input: any finding (fingerprint generated as "a".repeat(64))
/// Output: fingerprint field is 64-char hex string
#[test]
fn snapshot_sensor_finding_fingerprint_format() {
    let finding = make_finding("test.rule");
    let json: Value = serde_json::to_value(&finding).expect("serialize to JSON");
    let fingerprint = json["fingerprint"].as_str().expect("fingerprint is string");

    assert_eq!(fingerprint.len(), 64, "fingerprint should be 64 hex chars");
    assert!(
        fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint should be all hex digits"
    );
}

/// Snapshot: SensorFinding JSON roundtrip preserves all fields exactly.
/// Input: full finding with all fields
/// Output: deserialize(serialize(finding)) == finding
#[test]
fn snapshot_sensor_finding_json_roundtrip() {
    let original = make_finding_full("rust.no_unwrap");
    let json_bytes = serde_json::to_vec(&original).expect("serialize to JSON");
    let deserialized: SensorFinding = serde_json::from_slice(&json_bytes).expect("deserialize");

    assert_eq!(original.check_id, deserialized.check_id);
    assert_eq!(original.code, deserialized.code);
    assert_eq!(original.severity, deserialized.severity);
    assert_eq!(original.message, deserialized.message);
    assert_eq!(original.location.path, deserialized.location.path);
    assert_eq!(original.location.line, deserialized.location.line);
    assert_eq!(original.location.column, deserialized.location.column);
    assert_eq!(original.fingerprint, deserialized.fingerprint);
    assert_eq!(original.help, deserialized.help);
    assert_eq!(original.url, deserialized.url);
    // data is Value, compare serialized form
    assert_eq!(
        serde_json::to_value(&original.data).expect("serialize data"),
        serde_json::to_value(&deserialized.data).expect("serialize deserialized data")
    );
}
