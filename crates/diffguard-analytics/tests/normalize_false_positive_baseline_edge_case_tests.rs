//! Edge case tests for `normalize_false_positive_baseline`.
//!
//! These tests complement the red tests (which verify the refactor signature
//! change compiles and the basic normalization behavior). These tests stress
//! edge cases: empty collections, boundary values, multi-field ordering,
//! and interaction between sort and dedup.
//!
//! All tests assume `normalize_false_positive_baseline` has the refactored
//! signature: `fn(&mut FalsePositiveBaseline)` returning `()`.

use diffguard_analytics::{
    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    normalize_false_positive_baseline,
};

/// Test: empty entries list is handled correctly.
/// Boundary case — zero entries should remain zero after normalization.
#[test]
fn test_normalize_empty_entries() {
    let mut baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![],
    };
    normalize_false_positive_baseline(&mut baseline);
    assert!(
        baseline.entries.is_empty(),
        "empty entries should remain empty"
    );
    assert_eq!(baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
}

/// Test: non-empty schema is preserved and not overwritten.
/// The function only sets schema when `schema.is_empty()`.
#[test]
fn test_normalize_preserves_existing_schema() {
    let custom_schema = "my.custom.schema.v99".to_string();
    let mut baseline = FalsePositiveBaseline {
        schema: custom_schema.clone(),
        entries: vec![],
    };
    normalize_false_positive_baseline(&mut baseline);
    assert_eq!(
        baseline.schema, custom_schema,
        "existing non-empty schema should not be modified"
    );
}

/// Test: sort is stable across all four fields (fingerprint, rule_id, path, line).
/// Entries with the same fingerprint should be ordered by rule_id, then path, then line.
#[test]
fn test_normalize_sort_order_all_fields() {
    let mut baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "b".to_string(),
                rule_id: "z".to_string(),
                path: "z.rs".to_string(),
                line: 99,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "a".to_string(),
                rule_id: "a".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "a".to_string(),
                rule_id: "b".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "a".to_string(),
                rule_id: "a".to_string(),
                path: "b.rs".to_string(),
                line: 3,
                note: None,
            },
        ],
    };

    normalize_false_positive_baseline(&mut baseline);

    // Three "a" fingerprints dedup to ONE entry (the first in sort order)
    // "a" + "a"/"a.rs"/1  <  "a" + "a"/"b.rs"/3  <  "a" + "b"/"b.rs"/2
    // So the first "a" entry (rule_id="a", path="a.rs", line=1) is kept
    assert_eq!(baseline.entries.len(), 2); // "a" (deduped to 1) + "b"
    assert_eq!(baseline.entries[0].fingerprint, "a");
    assert_eq!(baseline.entries[0].rule_id, "a");
    assert_eq!(baseline.entries[0].path, "a.rs");
    assert_eq!(baseline.entries[0].line, 1);
    assert_eq!(baseline.entries[1].fingerprint, "b");
}

/// Test: dedup_by removes subsequent duplicates, keeping the first occurrence.
/// After sorting by (fingerprint, rule_id, path, line), the first entry for
/// each fingerprint is kept and later duplicates are removed.
#[test]
fn test_normalize_dedupe_keeps_first_occurrence() {
    let mut baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "dup".to_string(),
                rule_id: "rule.b".to_string(), // second in sort order
                path: "b.rs".to_string(),
                line: 20,
                note: Some("should be discarded".to_string()),
            },
            FalsePositiveEntry {
                fingerprint: "dup".to_string(),
                rule_id: "rule.a".to_string(), // first in sort order — should be kept
                path: "a.rs".to_string(),
                line: 10,
                note: Some("should be kept".to_string()),
            },
            FalsePositiveEntry {
                fingerprint: "dup".to_string(),
                rule_id: "rule.c".to_string(), // third in sort order
                path: "c.rs".to_string(),
                line: 30,
                note: None,
            },
        ],
    };

    normalize_false_positive_baseline(&mut baseline);

    assert_eq!(baseline.entries.len(), 1);
    assert_eq!(baseline.entries[0].rule_id, "rule.a");
    assert_eq!(baseline.entries[0].note, Some("should be kept".to_string()));
}

/// Test: entries with empty fingerprint strings are all considered equal for dedup.
#[test]
fn test_normalize_empty_fingerprint_all_equal() {
    let mut baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "".to_string(),
                rule_id: "z".to_string(),
                path: "z.rs".to_string(),
                line: 99,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "".to_string(),
                rule_id: "a".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
        ],
    };

    normalize_false_positive_baseline(&mut baseline);

    // All empty fingerprints are deduplicated to one entry
    assert_eq!(baseline.entries.len(), 1);
    // Sort order: rule_id "a" < "z", so "a" entry is first and kept
    assert_eq!(baseline.entries[0].rule_id, "a");
}

/// Test: line number boundary — u32::MAX should sort correctly and not cause issues.
#[test]
fn test_normalize_max_line_number() {
    let mut baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "aaa".to_string(),
                rule_id: "rule".to_string(),
                path: "a.rs".to_string(),
                line: u32::MAX,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "aaa".to_string(),
                rule_id: "rule".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
        ],
    };

    normalize_false_positive_baseline(&mut baseline);

    // Both have same fingerprint, dedup keeps the first (line 1 after sort)
    assert_eq!(baseline.entries.len(), 1);
    assert_eq!(baseline.entries[0].line, 1);
}

/// Test: very long fingerprint strings are sorted correctly.
#[test]
fn test_normalize_long_fingerprints() {
    let long_a = "a".repeat(1000);
    let long_b = "b".repeat(1000);

    let mut baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: long_b.clone(),
                rule_id: "rule".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: long_a.clone(),
                rule_id: "rule".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
        ],
    };

    normalize_false_positive_baseline(&mut baseline);

    assert_eq!(baseline.entries.len(), 2);
    assert_eq!(baseline.entries[0].fingerprint, long_a);
    assert_eq!(baseline.entries[1].fingerprint, long_b);
}

/// Test: merge_false_positive_baselines — incoming is primary, base fills in missing fields.
/// When both have the same fingerprint, incoming wins as primary entry.
/// Base only fills in empty/missing fields from incoming (not overwrite non-empty ones).
#[test]
fn test_merge_incoming_fills_base_empty_fields() {
    use diffguard_analytics::merge_false_positive_baselines;

    let base = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "dup".to_string(),
            rule_id: "".to_string(), // empty — should be filled from incoming
            path: "".to_string(),    // empty — should be filled from incoming
            line: 0,                 // zero — should be filled from incoming
            note: Some("base note".to_string()), // non-empty — should be kept
        }],
    };
    let incoming = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "dup".to_string(),
                rule_id: "incoming-rule".to_string(),
                path: "incoming.rs".to_string(),
                line: 200,
                note: None, // empty — should be filled from base
            },
            FalsePositiveEntry {
                fingerprint: "new".to_string(),
                rule_id: "new-rule".to_string(),
                path: "new.rs".to_string(),
                line: 300,
                note: None,
            },
        ],
    };

    let merged = merge_false_positive_baselines(&base, &incoming);

    // "dup" entry: incoming is primary (rule_id, path, line), base fills note
    // "new" entry: from incoming
    assert_eq!(merged.entries.len(), 2);

    let dup_entry = merged
        .entries
        .iter()
        .find(|e| e.fingerprint == "dup")
        .expect("dup entry must exist");
    // incoming fields are primary
    assert_eq!(dup_entry.rule_id, "incoming-rule");
    assert_eq!(dup_entry.path, "incoming.rs");
    assert_eq!(dup_entry.line, 200);
    // base fills in the empty note
    assert_eq!(dup_entry.note, Some("base note".to_string()));

    let new_entry = merged
        .entries
        .iter()
        .find(|e| e.fingerprint == "new")
        .expect("new entry must exist");
    assert_eq!(new_entry.rule_id, "new-rule");
}

/// Test: merge_false_positive_baselines with empty base preserves incoming normalization.
#[test]
fn test_merge_with_empty_base() {
    use diffguard_analytics::merge_false_positive_baselines;

    let base = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![],
    };
    let incoming = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "aaa".to_string(),
                rule_id: "rule".to_string(),
                path: "a.rs".to_string(),
                line: 10,
                note: Some("note".to_string()),
            },
            FalsePositiveEntry {
                fingerprint: "bbb".to_string(),
                rule_id: "rule".to_string(),
                path: "b.rs".to_string(),
                line: 20,
                note: None,
            },
        ],
    };

    let merged = merge_false_positive_baselines(&base, &incoming);

    // Incoming entries are normalized and merged
    assert_eq!(merged.entries.len(), 2);
    assert_eq!(merged.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
    // Entries should be sorted by fingerprint
    assert_eq!(merged.entries[0].fingerprint, "aaa");
    assert_eq!(merged.entries[1].fingerprint, "bbb");
}

/// Test: normalize_false_positive_baseline is called multiple times in sequence
/// (simulating what happens in merge_false_positive_baselines) without issues.
#[test]
fn test_normalize_twice_in_sequence() {
    let mut baseline = FalsePositiveBaseline {
        schema: String::new(), // empty, will be set to V1 on first call
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "c".to_string(),
                rule_id: "rule".to_string(),
                path: "c.rs".to_string(),
                line: 3,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "a".to_string(),
                rule_id: "rule".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
        ],
    };

    // First normalization
    normalize_false_positive_baseline(&mut baseline);
    assert_eq!(baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
    assert_eq!(baseline.entries.len(), 2);
    assert_eq!(baseline.entries[0].fingerprint, "a");
    assert_eq!(baseline.entries[1].fingerprint, "c");

    // Second normalization — should be idempotent
    let first_state = baseline.clone();
    normalize_false_positive_baseline(&mut baseline);
    assert_eq!(baseline, first_state, "normalization should be idempotent");
}
