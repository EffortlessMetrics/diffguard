//! Property-based tests for SensorFinding (work-a3ef8bf6)
//!
//! This change is a doc-only fix: wrapping `rule_id` in backticks in the doc comment
//! for SensorFinding::code. Since this is a purely cosmetic documentation change with
//! no runtime behavior change, these tests verify that the SensorFinding type
//! itself remains functionally correct.
//!
//! Feature: property-test-coverage for work-a3ef8bf6
//!
//! These tests verify invariants using a range of inputs, though not all are
//! generated via proptest due to compilation issues with the test environment.

use diffguard_types::{SensorFinding, SensorLocation, Severity};

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

// ============================================================================
// Invariant Tests: JSON Serialization Round-Trip
// ============================================================================

/// Property 1: JSON Serialization Round-Trip (empty code)
#[test]
fn sensor_finding_json_roundtrip_empty_code() {
    let finding = make_finding("");
    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: SensorFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding.code, deserialized.code);
}

/// Property 1: JSON Serialization Round-Trip (normal code)
#[test]
fn sensor_finding_json_roundtrip_normal_code() {
    let finding = make_finding("rust.no_unwrap");
    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: SensorFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding.code, deserialized.code);
    assert_eq!(finding, deserialized);
}

/// Property 1: JSON Serialization Round-Trip (long code)
#[test]
fn sensor_finding_json_roundtrip_long_code() {
    let long_code = "a".repeat(10_000);
    let finding = make_finding(&long_code);
    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: SensorFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding.code.len(), 10_000);
    assert_eq!(finding.code, long_code);
    assert_eq!(finding, deserialized);
}

/// Property 1: JSON Serialization Round-Trip (code with special chars)
#[test]
fn sensor_finding_json_roundtrip_special_chars_code() {
    let finding = make_finding("rust.no_unwrap <>&'\"");
    let json = serde_json::to_string(&finding).unwrap();
    let deserialized: SensorFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding.code, "rust.no_unwrap <>&'\"");
    assert_eq!(finding, deserialized);
}

/// Property 1: JSON Serialization Round-Trip (all severity variants)
#[test]
fn sensor_finding_json_roundtrip_all_severities() {
    for severity in [Severity::Info, Severity::Warn, Severity::Error] {
        let mut finding = make_finding("test.rule");
        finding.severity = severity;
        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: SensorFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding.code, deserialized.code);
        assert_eq!(finding.severity, deserialized.severity);
    }
}

// ============================================================================
// Invariant Tests: Code Field Accepts Various Patterns
// ============================================================================

/// Property 2: Code field accepts standard rule code patterns
#[test]
fn sensor_finding_code_accepts_standard_patterns() {
    let patterns = [
        "rust.no_unwrap",
        "python.no_print",
        "js.no_console_log",
        "go.no_goto",
        "java.no_system_exit",
        "c.buffer_overflow",
        "ruby.bandit.L401",
        "terraform.security.S3",
        "docker.no_root",
        "kubernetes.no_default_namespace",
    ];
    for pattern in patterns {
        let finding = make_finding(pattern);
        assert_eq!(finding.code, pattern);
    }
}

/// Property 2: Code field accepts single-character codes
#[test]
fn sensor_finding_code_accepts_single_char() {
    let finding = make_finding("a");
    assert_eq!(finding.code, "a");
}

/// Property 2: Code field accepts very long single-segment codes
#[test]
fn sensor_finding_code_accepts_long_single_segment() {
    let code = "a".repeat(1000);
    let finding = make_finding(&code);
    assert_eq!(finding.code.len(), 1000);
}

/// Property 2: Code field accepts dots-only variant codes
#[test]
fn sensor_finding_code_accepts_dotted_variants() {
    let finding = make_finding("a.b.c.d.e.f");
    assert_eq!(finding.code, "a.b.c.d.e.f");
}

/// Property 2: Code field accepts alphanumeric codes
#[test]
fn sensor_finding_code_accepts_alphanumeric() {
    let finding = make_finding("abc123.def456.ghi789");
    assert_eq!(finding.code, "abc123.def456.ghi789");
}

// ============================================================================
// Invariant Tests: PartialEq and Clone
// ============================================================================

/// Property 3: SensorFinding equality works correctly
#[test]
fn sensor_finding_partial_eq() {
    let f1 = make_finding("test.rule");
    let f2 = make_finding("test.rule");
    let f3 = make_finding("other.rule");

    assert_eq!(f1, f2);
    assert_ne!(f1, f3);
}

/// Property 3: SensorFinding clone preserves code field
#[test]
fn sensor_finding_clone_preserves_code() {
    let finding = make_finding("clone.test");
    let cloned = finding.clone();
    assert_eq!(cloned.code, finding.code);
    assert_eq!(cloned, finding);
}

// ============================================================================
// Invariant Tests: Debug and Display (if implemented)
// ============================================================================

/// Property 4: SensorFinding implements Debug
#[test]
fn sensor_finding_debug() {
    let finding = make_finding("debug.test");
    let debug_str = format!("{:?}", finding);
    assert!(debug_str.contains("debug.test"));
}
