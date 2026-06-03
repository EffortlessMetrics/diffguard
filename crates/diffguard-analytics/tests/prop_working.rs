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

    #[test]
    fn property_merge_contains_union_of_fingerprints(
        baseline1 in arb_baseline(),
        baseline2 in arb_baseline(),
    ) {
        let merged = merge_false_positive_baselines(&baseline1, &baseline2);
        let fps1: std::collections::HashSet<_> =
            baseline1.entries.iter().map(|e| e.fingerprint.clone()).collect();
        let fps2: std::collections::HashSet<_> =
            baseline2.entries.iter().map(|e| e.fingerprint.clone()).collect();
        let expected_union: std::collections::HashSet<_> =
            fps1.union(&fps2).cloned().collect();
        let merged_fps: std::collections::HashSet<_> =
            merged.entries.iter().map(|e| e.fingerprint.clone()).collect();
        prop_assert_eq!(
            merged_fps, expected_union,
            "Merged baseline should contain union of fingerprints"
        );
    }

    #[test]
    fn property_merge_preserves_existing_notes() {
        let existing = FalsePositiveBaseline {
            schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
            entries: vec![FalsePositiveEntry {
                fingerprint: "abc123".to_string(),
                rule_id: "rule1".to_string(),
                path: "file1.rs".to_string(),
                line: 1,
                note: Some("curated note".to_string()),
            }],
        };
        let incoming = FalsePositiveBaseline {
            schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
            entries: vec![FalsePositiveEntry {
                fingerprint: "abc123".to_string(),
                rule_id: "rule1".to_string(),
                path: "file1.rs".to_string(),
                line: 1,
                note: None,
            }],
        };
        let merged = merge_false_positive_baselines(&existing, &incoming);
        prop_assert_eq!(merged.entries.len(), 1);
        prop_assert_eq!(
            merged.entries[0].note.as_deref(),
            Some("curated note"),
            "Existing note should be preserved"
        );
    }

    #[test]
    fn property_merge_preserves_existing_fields() {
        let existing = FalsePositiveBaseline {
            schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
            entries: vec![FalsePositiveEntry {
                fingerprint: "abc123".to_string(),
                rule_id: "rule1".to_string(),
                path: "file1.rs".to_string(),
                line: 1,
                note: None,
            }],
        };
        let incoming = FalsePositiveBaseline {
            schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
            entries: vec![FalsePositiveEntry {
                fingerprint: "abc123".to_string(),
                rule_id: "".to_string(),
                path: "".to_string(),
                line: 0,
                note: None,
            }],
        };
        let merged = merge_false_positive_baselines(&existing, &incoming);
        prop_assert_eq!(merged.entries.len(), 1);
        prop_assert_eq!(merged.entries[0].rule_id, "rule1");
        prop_assert_eq!(merged.entries[0].path, "file1.rs");
        prop_assert_eq!(merged.entries[0].line, 1);
    }
}

// ============================================================================
// Property: Fingerprint Set
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn property_fingerprint_set_contains_all_fingerprints(baseline in arb_baseline()) {
        let set = false_positive_fingerprint_set(&baseline);
        prop_assert_eq!(
            set.len(),
            baseline.entries.len(),
            "Fingerprint set size should match baseline entries count"
        );
        for entry in &baseline.entries {
            prop_assert!(
                set.contains(&entry.fingerprint),
                "Set should contain fingerprint"
            );
        }
    }

    #[test]
    fn property_fingerprint_set_no_duplicates(baseline in arb_baseline()) {
        let set = false_positive_fingerprint_set(&baseline);
        let unique_count = baseline
            .entries
            .iter()
            .map(|e| &e.fingerprint)
            .collect::<std::collections::HashSet<_>>()
            .len();
        prop_assert_eq!(
            set.len(),
            unique_count,
            "Set should have no duplicate fingerprints"
        );
    }
}
