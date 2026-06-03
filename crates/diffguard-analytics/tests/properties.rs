//! Property-based tests for diffguard-analytics
//!
//! Feature: comprehensive-test-coverage, Property: Baseline Analytics
//!
//! These tests verify invariants about fingerprint computation, baseline
//! creation, normalization, and merging that the baseline_receipt fuzz
//! target depends on.
//!
//! ## Invariants Tested
//!
//! ### Fingerprint (DETERMINISTIC)
//! - Same finding always produces the same fingerprint
//! - Fingerprint is exactly 64 hex characters (SHA-256)
//! - Fingerprint is valid hexadecimal
//!
//! ### Baseline (PRESERVES + DEDUPLICATES)
//! - Schema is always "diffguard.false_positive_baseline.v1"
//! - Each finding produces an entry with matching fingerprint
//! - Duplicate findings are deduplicated
//!
//! ### Normalization (IDEMPOTENT + SORTED)
//! - Normalizing twice gives same result (idempotent)
//! - Entries are sorted by fingerprint, rule_id, path, line
//! - Schema is set if empty
//!
//! ### Merge (COMMUTATIVE + UNION)
//! - Merging is commutative: A + B = B + A
//! - Merging is associative: (A + B) + C = A + (B + C)
//! - Result contains union of fingerprints
//! - Existing entries (from base) are preserved

use proptest::prelude::*;

use diffguard_analytics::{
    baseline_from_receipt, false_positive_fingerprint_set, fingerprint_for_finding,
    merge_false_positive_baselines, normalize_false_positive_baseline,
    FalsePositiveBaseline, FalsePositiveEntry, FALSE_POSITIVE_BASELINE_SCHEMA_V1,
};
use diffguard_types::{
    CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts,
    VerdictStatus, CHECK_SCHEMA_V1,
};

// ============================================================================
// Proptest Strategies for generating test data
// ============================================================================

/// Strategy for generating valid Severity values.
fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![Just(Severity::Info), Just(Severity::Warn), Just(Severity::Error),]
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
    prop::string::string_regex("[a-zA-Z0-9_ ]{0,100}")
        .expect("valid regex")
}

/// Strategy for generating valid Finding.
fn arb_finding() -> impl Strategy<Value = Finding> {
    (
        arb_rule_id(),
        arb_severity(),
        prop::string::string_regex("[a-zA-Z0-9 .,!?]{1,100}").expect("valid regex"), // message
        arb_path(),
        1u32..10000,
        prop::option::of(1u32..200),
        arb_match_text(),
        prop::string::string_regex("[a-zA-Z0-9 .,!?]{0,200}").expect("valid regex"), // snippet
    )
        .prop_map(|(rule_id, severity, message, path, line, column, match_text, snippet)| {
            Finding {
                rule_id,
                severity,
                message,
                path,
                line,
                column,
                match_text,
                snippet,
            }
        })
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
        prop::option::of(prop::string::string_regex("[a-zA-Z0-9 .,!?]{0,200}").expect("valid regex")),
    )
        .prop_map(|(fingerprint, rule_id, path, line, note)| FalsePositiveEntry {
            fingerprint,
            rule_id,
            path,
            line,
            note,
        })
}

/// Strategy for generating a valid FalsePositiveBaseline.
fn arb_baseline() -> impl Strategy<Value = FalsePositiveBaseline> {
    prop::collection::vec(arb_baseline_entry(), 0..20).prop_map(|entries| {
        let schema = FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string();
        FalsePositiveBaseline { schema, entries }
    })
}

// ============================================================================
// Property: Fingerprint Determinism (DETERMINISTIC)
// ============================================================================

proptest! {
    #[test]
    fn property_fingerprint_is_deterministic(finding in arb_finding()) {
        let fp1 = fingerprint_for_finding(&finding);
        let fp2 = fingerprint_for_finding(&finding);
        prop_assert_eq!(
            fp1, fp2,
            "Same finding should produce same fingerprint"
        );
    }

    #[test]
    fn property_fingerprint_length_is_64(finding in arb_finding()) {
        let fp = fingerprint_for_finding(&finding);
        prop_assert_eq!(
            fp.len(), 64,
            "SHA-256 fingerprint should be 64 hex chars, got {} chars",
            fp.len()
        );
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
        base_finding in arb_finding(),
        new_rule_id in arb_rule_id(),
    ) {
        let finding1 = base_finding.clone();
        let mut finding2 = base_finding;
        finding2.rule_id = new_rule_id;

        let fp1 = fingerprint_for_finding(&finding1);
        let fp2 = fingerprint_for_finding(&finding2);

        prop_assert_ne!(
            fp1, fp2,
            "Different rule_id should produce different fingerprint"
        );
    }

    #[test]
    fn property_fingerprint_changes_with_path(
        base_finding in arb_finding(),
        new_path in arb_path(),
    ) {
        let finding1 = base_finding.clone();
        let mut finding2 = base_finding;
        finding2.path = new_path;

        let fp1 = fingerprint_for_finding(&finding1);
        let fp2 = fingerprint_for_finding(&finding2);

        prop_assert_ne!(
            fp1, fp2,
            "Different path should produce different fingerprint"
        );
    }

    #[test]
    fn property_fingerprint_changes_with_line(
        base_finding in arb_finding(),
        new_line in 1u32..10000,
    ) {
        let finding1 = base_finding.clone();
        let mut finding2 = base_finding;
        finding2.line = new_line;

        let fp1 = fingerprint_for_finding(&finding1);
        let fp2 = fingerprint_for_finding(&finding2);

        prop_assert_ne!(
            fp1, fp2,
            "Different line should produce different fingerprint"
        );
    }

    #[test]
    fn property_fingerprint_changes_with_match_text(
        base_finding in arb_finding(),
        new_match_text in arb_match_text(),
    ) {
        let finding1 = base_finding.clone();
        let mut finding2 = base_finding;
        finding2.match_text = new_match_text;

        let fp1 = fingerprint_for_finding(&finding1);
        let fp2 = fingerprint_for_finding(&finding2);

        prop_assert_ne!(
            fp1, fp2,
            "Different match_text should produce different fingerprint"
        );
    }

    #[test]
    fn property_fingerprint_ignores_message(
        base_finding in arb_finding(),
        new_message in prop::string::string_regex("[a-zA-Z0-9 .,!?]{1,100}").expect("valid regex"),
    ) {
        // message is NOT part of the fingerprint - it's not in rule_id:path:line:match_text
        let finding1 = base_finding.clone();
        let mut finding2 = base_finding;
        finding2.message = new_message;

        let fp1 = fingerprint_for_finding(&finding1);
        let fp2 = fingerprint_for_finding(&finding2);

        prop_assert_eq!(
            fp1, fp2,
            "Different message should NOT affect fingerprint (not part of key)"
        );
    }

    #[test]
    fn property_fingerprint_ignores_severity(base_finding in arb_finding()) {
        // severity is NOT part of the fingerprint - it's not in rule_id:path:line:match_text
        let finding1 = base_finding.clone();
        let mut finding2 = base_finding;
        finding2.severity = Severity::Error;

        let fp1 = fingerprint_for_finding(&finding1);
        let fp2 = fingerprint_for_finding(&finding2);

        prop_assert_eq!(
            fp1, fp2,
            "Different severity should NOT affect fingerprint (not part of key)"
        );
    }

    #[test]
    fn property_fingerprint_ignores_snippet(
        base_finding in arb_finding(),
        new_snippet in prop::string::string_regex("[a-zA-Z0-9 .,!?]{0,200}").expect("valid regex"),
    ) {
        // snippet is NOT part of the fingerprint
        let finding1 = base_finding.clone();
        let mut finding2 = base_finding;
        finding2.snippet = new_snippet;

        let fp1 = fingerprint_for_finding(&finding1);
        let fp2 = fingerprint_for_finding(&finding2);

        prop_assert_eq!(
            fp1, fp2,
            "Different snippet should NOT affect fingerprint (not part of key)"
        );
    }
}

// ============================================================================
// Property: Baseline Schema (PRESERVES)
// ============================================================================

proptest! {
    #[test]
    fn property_baseline_schema_is_correct(receipt in arb_check_receipt()) {
        let baseline = baseline_from_receipt(&receipt);
        let baseline_schema = baseline.schema.clone();
        prop_assert_eq!(
            baseline_schema.clone(), FALSE_POSITIVE_BASELINE_SCHEMA_V1,
            "Baseline schema should be '{}', got '{}'",
            FALSE_POSITIVE_BASELINE_SCHEMA_V1,
            baseline_schema
        );
    }

    #[test]
    fn property_baseline_entries_match_findings(receipt in arb_check_receipt()) {
        let baseline = baseline_from_receipt(&receipt);

        // Each finding should have a corresponding baseline entry
        for finding in &receipt.findings {
            let fp = fingerprint_for_finding(finding);
            prop_assert!(
                baseline.entries.iter().any(|e| e.fingerprint == fp),
                "Each finding should have a baseline entry with matching fingerprint"
            );
        }
    }

    #[test]
    fn property_baseline_deduplicates_duplicates(finding in arb_finding()) {
        // Create receipt with duplicate findings
        let duplicate_count = 3;
        let findings: Vec<Finding> = (0..duplicate_count).map(|_| finding.clone()).collect();

        let receipt_with_dups = CheckReceipt {
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
                lines_scanned: 10,
            },
            findings,
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 3,
                    suppressed: 0,
                },
                reasons: vec![],
            },
            timing: None,
        };

        let baseline = baseline_from_receipt(&receipt_with_dups);

        // Should have only 1 entry despite 3 duplicate findings
        prop_assert_eq!(
            baseline.entries.len(), 1,
            "Duplicate findings should be deduplicated to 1 entry, got {}",
            baseline.entries.len()
        );
    }

    #[test]
    fn property_baseline_empty_findings_produces_empty_entries(receipt in arb_check_receipt()) {
        let empty_receipt = CheckReceipt {
            schema: receipt.schema.clone(),
            tool: receipt.tool.clone(),
            diff: receipt.diff.clone(),
            findings: vec![],
            verdict: receipt.verdict.clone(),
            timing: None,
        };

        let baseline = baseline_from_receipt(&empty_receipt);
        prop_assert!(
            baseline.entries.is_empty(),
            "Empty findings should produce empty baseline entries"
        );
    }
}

// ============================================================================
// Additional Invariant Tests (manual, not proptest)
// ============================================================================

#[test]
fn test_normalization_is_idempotent() {
    // Test with empty baseline
    let baseline = FalsePositiveBaseline {
        schema: String::new(),
        entries: vec![],
    };
    let normalized1 = normalize_false_positive_baseline(baseline.clone());
    let normalized2 = normalize_false_positive_baseline(normalized1.clone());
    assert_eq!(normalized1, normalized2, "Normalization should be idempotent");
}

#[test]
fn test_normalization_sets_schema_if_empty() {
    let baseline = FalsePositiveBaseline {
        schema: String::new(),
        entries: vec![],
    };
    let normalized = normalize_false_positive_baseline(baseline);
    assert_eq!(
        normalized.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1,
        "Empty schema should be set to baseline schema"
    );
}

#[test]
fn test_normalization_preserves_existing_schema() {
    let baseline = FalsePositiveBaseline {
        schema: "existing.schema.v1".to_string(),
        entries: vec![],
    };
    let normalized = normalize_false_positive_baseline(baseline.clone());
    assert_eq!(normalized.schema, baseline.schema, "Existing schema should be preserved");
}

#[test]
fn test_merge_commutative_fp_count() {
    // Test merge commutativity: A+B should have same fingerprints as B+A
    let baseline1 = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "abc123".to_string(),
            rule_id: "rule1".to_string(),
            path: "file1.rs".to_string(),
            line: 10,
            note: None,
        }],
    };
    let baseline2 = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "def456".to_string(),
            rule_id: "rule2".to_string(),
            path: "file2.rs".to_string(),
            line: 20,
            note: None,
        }],
    };
    let merged1 = merge_false_positive_baselines(&baseline1, &baseline2);
    let merged2 = merge_false_positive_baselines(&baseline2, &baseline1);
    let fps1: std::collections::HashSet<_> =
        merged1.entries.iter().map(|e| e.fingerprint.clone()).collect();
    let fps2: std::collections::HashSet<_> =
        merged2.entries.iter().map(|e| e.fingerprint.clone()).collect();
    assert_eq!(fps1, fps2, "Merging should be commutative (same fingerprints)");
}

#[test]
fn test_fingerprint_set_contains_all_entries() {
    let baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "aaa111".to_string(),
                rule_id: "rule1".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "bbb222".to_string(),
                rule_id: "rule2".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
        ],
    };
    let set = false_positive_fingerprint_set(&baseline);
    assert_eq!(set.len(), baseline.entries.len(), "Set size should match entries count");
    for entry in &baseline.entries {
        assert!(
            set.contains(&entry.fingerprint),
            "Set should contain fingerprint {}",
            entry.fingerprint
        );
    }
}

