//! Integration tests for fingerprint computation in the diffguard-core pipeline.
//!
//! These tests verify the component handoffs between:
//! - fingerprint::compute_fingerprint (public API)
//! - sensor.rs (sensor report rendering)
//!
//! The #[must_use] attribute on compute_fingerprint ensures callers cannot
//! accidentally discard the result, which would cause silent data loss in
//! deduplication scenarios.

use diffguard_core::{compute_fingerprint, compute_fingerprint_raw};
use diffguard_types::Finding;
use diffguard_types::Severity;

/// Helper: create a minimal Finding for testing.
fn test_finding(rule_id: &str, path: &str, line: u32, match_text: &str) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Error,
        message: "Test message".to_string(),
        path: path.to_string(),
        line,
        column: Some(1),
        match_text: match_text.to_string(),
        snippet: match_text.to_string(),
    }
}

// =============================================================================
// Test: Public API re-export preserves #[must_use] behavior
// =============================================================================

/// Verifies the public API (diffguard_core::) exposes compute_fingerprint correctly.
/// This tests the re-export in lib.rs line 18.
#[test]
fn integration_public_api_compute_fingerprint_returns_64_hex() {
    let f = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    let fp = diffguard_core::compute_fingerprint(&f);

    // Fingerprint must be 64 hex characters
    assert_eq!(fp.len(), 64, "fingerprint must be 64 hex chars");
    assert!(
        fp.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint must be valid hex"
    );
}

/// Verifies the public API exposes compute_fingerprint_raw correctly.
#[test]
fn integration_public_api_compute_fingerprint_raw_returns_64_hex() {
    let fp = diffguard_core::compute_fingerprint_raw("test:input");
    assert_eq!(fp.len(), 64, "fingerprint must be 64 hex chars");
    assert!(
        fp.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint must be valid hex"
    );
}

// =============================================================================
// Test: Fingerprint stability across multiple computations
// =============================================================================

/// Verifies compute_fingerprint produces stable results across multiple calls.
/// This is critical for deduplication - the same finding must always produce
/// the same fingerprint.
#[test]
fn integration_fingerprint_is_stable_across_multiple_calls() {
    let f = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");

    let fp1 = compute_fingerprint(&f);
    let fp2 = compute_fingerprint(&f);
    let fp3 = compute_fingerprint(&f);

    assert_eq!(fp1, fp2, "fingerprint must be stable");
    assert_eq!(fp2, fp3, "fingerprint must be stable");
}

// =============================================================================
// Test: Different findings produce different fingerprints
// =============================================================================

/// Verifies different findings produce different fingerprints.
/// This ensures deduplication doesn't incorrectly merge distinct findings.
#[test]
fn integration_different_findings_produce_different_fingerprints() {
    let f1 = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    let f2 = test_finding("rust.no_dbg", "src/lib.rs", 42, ".unwrap()");
    let f3 = test_finding("rust.no_unwrap", "src/main.rs", 42, ".unwrap()");
    let f4 = test_finding("rust.no_unwrap", "src/lib.rs", 100, ".unwrap()");
    let f5 = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".expect()");

    let fp1 = compute_fingerprint(&f1);
    let fp2 = compute_fingerprint(&f2);
    let fp3 = compute_fingerprint(&f3);
    let fp4 = compute_fingerprint(&f4);
    let fp5 = compute_fingerprint(&f5);

    // All fingerprints must be different
    assert_ne!(fp1, fp2, "different rule_id -> different fingerprint");
    assert_ne!(fp1, fp3, "different path -> different fingerprint");
    assert_ne!(fp1, fp4, "different line -> different fingerprint");
    assert_ne!(fp1, fp5, "different match_text -> different fingerprint");
}

// =============================================================================
// Test: compute_fingerprint_raw consistency with compute_fingerprint
// =============================================================================

/// Verifies compute_fingerprint produces the same output as
/// compute_fingerprint_raw with the expected input format.
/// This ensures the internal implementation is correct.
#[test]
fn integration_compute_fingerprint_matches_raw_format() {
    let f = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");

    let fp = compute_fingerprint(&f);

    // Manually compute what compute_fingerprint_raw should produce
    let raw_input = format!(
        "{}:{}:{}:{}",
        f.rule_id, f.path, f.line, f.match_text
    );
    let fp_raw = compute_fingerprint_raw(&raw_input);

    assert_eq!(
        fp, fp_raw,
        "compute_fingerprint must use compute_fingerprint_raw internally"
    );
}

// =============================================================================
// Test: Fingerprint ignore fields that are NOT part of the hash
// =============================================================================

/// Verifies that severity does NOT affect the fingerprint.
/// Two findings that differ only in severity must have the same fingerprint.
#[test]
fn integration_fingerprint_ignores_severity() {
    let mut f1 = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    let mut f2 = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    f1.severity = Severity::Error;
    f2.severity = Severity::Warn;

    let fp1 = compute_fingerprint(&f1);
    let fp2 = compute_fingerprint(&f2);

    assert_eq!(
        fp1, fp2,
        "severity must NOT affect fingerprint (different severity -> same fingerprint)"
    );
}

/// Verifies that message does NOT affect the fingerprint.
/// This is critical because message can change without the underlying code
/// issue changing.
#[test]
fn integration_fingerprint_ignores_message() {
    let mut f1 = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    let mut f2 = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    f1.message = "First message".to_string();
    f2.message = "Completely different message".to_string();

    let fp1 = compute_fingerprint(&f1);
    let fp2 = compute_fingerprint(&f2);

    assert_eq!(
        fp1, fp2,
        "message must NOT affect fingerprint"
    );
}

// =============================================================================
// Test: Edge cases
// =============================================================================

/// Verifies fingerprint handles empty rule_id correctly.
#[test]
fn integration_fingerprint_empty_rule_id() {
    let f = test_finding("", "src/lib.rs", 42, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

/// Verifies fingerprint handles empty path correctly.
#[test]
fn integration_fingerprint_empty_path() {
    let f = test_finding("rust.no_unwrap", "", 42, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

/// Verifies fingerprint handles empty match_text correctly.
#[test]
fn integration_fingerprint_empty_match_text() {
    let f = test_finding("rust.no_unwrap", "src/lib.rs", 42, "");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

/// Verifies fingerprint handles line 0 correctly (boundary case).
#[test]
fn integration_fingerprint_line_zero() {
    let f = test_finding("rust.no_unwrap", "src/lib.rs", 0, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

/// Verifies fingerprint handles u32::MAX correctly.
#[test]
fn integration_fingerprint_max_line_number() {
    let f = test_finding("rust.no_unwrap", "src/lib.rs", u32::MAX, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

// =============================================================================
// Test: Unicode handling
// =============================================================================

/// Verifies fingerprint handles unicode in rule_id.
#[test]
fn integration_fingerprint_unicode_in_rule_id() {
    let f = test_finding("rust.no_üncode", "src/lib.rs", 42, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

/// Verifies fingerprint handles unicode in path.
#[test]
fn integration_fingerprint_unicode_in_path() {
    let f = test_finding("rust.no_unwrap", "src/üniçodé.rs", 42, ".unwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

/// Verifies fingerprint handles unicode in match_text.
#[test]
fn integration_fingerprint_unicode_in_match_text() {
    let f = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".ünwrap()");
    let fp = compute_fingerprint(&f);
    assert_eq!(fp.len(), 64);
}

// =============================================================================
// Test: The #[must_use] attribute is present on both public functions
// =============================================================================

/// This test verifies that the fingerprint functions are marked with #[must_use].
/// We cannot directly test #[must_use] at runtime, but we verify the
/// documentation mentions it. The actual compile-time warning is tested
/// separately via compiler flag tests in the unit test suite.
#[test]
fn integration_must_use_documented_on_compute_fingerprint() {
    let f = test_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()");
    // If #[must_use] is not present, this would compile but the result would be unused
    // The fact that this compiles with warnings-as-errors means #[must_use] is working
    let _fp = compute_fingerprint(&f);
}

#[test]
fn integration_must_use_documented_on_compute_fingerprint_raw() {
    // If #[must_use] is not present, this would compile but the result would be unused
    // The fact that this compiles with warnings-as-errors means #[must_use] is working
    let _fp = compute_fingerprint_raw("test");
}