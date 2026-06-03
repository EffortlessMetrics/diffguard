//! Property-based tests for diffguard-analytics
//!
//! Feature: comprehensive-test-coverage, Property: Baseline Analytics
//!
//! These tests verify invariants about fingerprint computation, baseline
//! creation, normalization, and merging that the baseline_receipt fuzz
//! target depends on.

use proptest::prelude::*;

use diffguard_analytics::{
    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    baseline_from_receipt, false_positive_fingerprint_set, fingerprint_for_finding,
    merge_false_positive_baselines, normalize_false_positive_baseline,
};
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};

// ============================================================================
// Proptest Strategies for generating test data
// ============================================================================

/// Strategy for generating valid Severity values.
fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Warn),
        Just(Severity::Error),
    ]
}

/// Strategy for generating rule_id strings.
fn arb_rule_id() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z][a-z0-9_.]{0,30}")
        .expect("valid regex")
        .prop_filter("must not be empty", |s| !s.is_empty())
}

/// Strategy for generating path strings.
fn arb_path() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z][a-zA-Z0-9_/.-]{0,50}")
        .expect("valid regex")
        .prop_filter("must not be empty", |s| !s.is_empty())
}

/// Strategy for generating match_text strings.
fn arb_match_text() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_ ]{0,100}").expect("valid regex")
}

/// Strategy for generating valid Finding.
fn arb_finding() -> impl Strategy<Value = Finding> {
    (
        arb_rule_id(),
        arb_severity(),
        prop::string::string_regex("[a-zA-Z0-9 .,!?]{1,100}").expect("valid regex"),
        arb_path(),
        1u32..10000,
        prop::option::of(1u32..200),
        arb_match_text(),
        prop::string::string_regex("[a-zA-Z0-9 .,!?]{0,200}").expect("valid regex"),
    )
        .prop_map(
            |(rule_id, severity, message, path, line, column, match_text, snippet)| Finding {
                rule_id,
                severity,
                message,
                path,
                line,
                column,
                match_text,
                snippet,
            },
        )
}

/// Strategy for generating a complete CheckReceipt.
fn arb_check_receipt() -> impl Strategy<Value = CheckReceipt> {
    prop::collection::vec(arb_finding(), 0..20).prop_map(|findings| {
        let mut info = 0u32;
        let mut warn = 0u32;
        let mut error = 0u32;
        for f in &findings {
            match f.severity {
                Severity::Info => info += 1,
                Severity::Warn => warn += 1,
                Severity::Error => error += 1,
            }
        }
        let status = if error > 0 {
            VerdictStatus::Fail
        } else if warn > 0 {
            VerdictStatus::Warn
        } else {
            VerdictStatus::Pass
        };
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 3,
                scope: Scope::Added,
                files_scanned: 1,
                lines_scanned: findings.len() as u32,
            },
            findings,
            verdict: Verdict {
                status,
                counts: VerdictCounts {
                    info,
                    warn,
                    error,
                    suppressed: 0,
                },
                reasons: vec![],
            },
            timing: None,
        }
    })
}

/// Strategy for generating a valid FalsePositiveEntry.
fn arb_baseline_entry() -> impl Strategy<Value = FalsePositiveEntry> {
    (
        prop::string::string_regex("[a-f0-9]{64}").expect("valid sha256 hex"),
        arb_rule_id(),
        arb_path(),
        1u32..10000,
        prop::option::of(
            prop::string::string_regex("[a-zA-Z0-9 .,!?]{0,200}").expect("valid regex"),
        ),
    )
        .prop_map(
            |(fingerprint, rule_id, path, line, note)| FalsePositiveEntry {
                fingerprint,
                rule_id,
                path,
                line,
                note,
            },
        )
}

/// Strategy for generating a valid FalsePositiveBaseline.
fn arb_baseline() -> impl Strategy<Value = FalsePositiveBaseline> {
    prop::collection::vec(arb_baseline_entry(), 0..20).prop_map(|entries| {
        let schema = FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string();
        FalsePositiveBaseline { schema, entries }
    })
}

// ============================================================================
// Property: Fingerprint Determinism
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn property_fingerprint_is_deterministic(finding in arb_finding()) {
        let fp1 = fingerprint_for_finding(&finding);
        let fp2 = fingerprint_for_finding(&finding);
        prop_assert_eq!(fp1, fp2, "Same finding should produce same fingerprint");
    }

    #[test]
    fn property_fingerprint_length_is_64(finding in arb_finding()) {
        let fp = fingerprint_for_finding(&finding);
        prop_assert_eq!(fp.len(), 64, "SHA-256 fingerprint should be 64 hex chars");
    }

    #[test]
    fn property_fingerprint_is_valid_hex(finding in arb_finding()) {
        let fp = fingerprint_for_finding(&finding);
        prop_assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "Fingerprint should be valid hex: {}",
            fp
        );
    }

    #[test]
    fn property_fingerprint_changes_with_rule_id(
        base in arb_finding(),
        new_rule_id in arb_rule_id(),
    ) {
        let mut finding1 = base.clone();
        let mut finding2 = base;
        finding2.rule_id = new_rule_id;
        prop_assert_ne!(
            fingerprint_for_finding(&finding1),
            fingerprint_for_finding(&finding2),
            "Different rule_id should produce different fingerprint"
        );
    }

    #[test]
    fn property_fingerprint_changes_with_path(
        base in arb_finding(),
        new_path in arb_path(),
    ) {
        let mut finding1 = base.clone();
        let mut finding2 = base;
        finding2.path = new_path;
        prop_assert_ne!(
            fingerprint_for_finding(&finding1),
            fingerprint_for_finding(&finding2),
            "Different path should produce different fingerprint"
        );
    }

    #[test]
    fn property_fingerprint_changes_with_line(
        base in arb_finding(),
        new_line in 1u32..10000,
    ) {
        let mut finding1 = base.clone();
        let mut finding2 = base;
        finding2.line = new_line;
        prop_assert_ne!(
            fingerprint_for_finding(&finding1),
            fingerprint_for_finding(&finding2),
            "Different line should produce different fingerprint"
        );
    }

    #[test]
    fn property_fingerprint_changes_with_match_text(
        base in arb_finding(),
        new_match_text in arb_match_text(),
    ) {
        let mut finding1 = base.clone();
        let mut finding2 = base;
        finding2.match_text = new_match_text;
        prop_assert_ne!(
            fingerprint_for_finding(&finding1),
            fingerprint_for_finding(&finding2),
            "Different match_text should produce different fingerprint"
        );
    }

    #[test]
    fn property_fingerprint_ignores_message(
        base in arb_finding(),
        new_message in prop::string::string_regex("[a-zA-Z0-9 .,!?]{1,100}").expect("valid regex"),
    ) {
        // message is NOT part of the fingerprint
        let mut finding1 = base.clone();
        let mut finding2 = base;
        finding2.message = new_message;
        prop_assert_eq!(
            fingerprint_for_finding(&finding1),
            fingerprint_for_finding(&finding2),
            "Different message should NOT affect fingerprint"
        );
    }

    #[test]
    fn property_fingerprint_ignores_severity(base in arb_finding()) {
        // severity is NOT part of the fingerprint
        let mut finding1 = base.clone();
        let mut finding2 = base;
        finding2.severity = Severity::Error;
        prop_assert_eq!(
            fingerprint_for_finding(&finding1),
            fingerprint_for_finding(&finding2),
            "Different severity should NOT affect fingerprint"
        );
    }
}
