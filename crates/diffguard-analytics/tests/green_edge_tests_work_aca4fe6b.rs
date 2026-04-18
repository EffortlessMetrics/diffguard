//! Edge case tests for `merge_false_positive_baselines()` in diffguard-analytics.
//!
//! These tests verify the implementation handles:
//! - Unicode and non-ASCII characters in strings
//! - Empty strings vs None (not an error but important distinction)
//! - Self-assignment with clone_from (same fingerprint in base and incoming)
//! - Multiple entries in base that match the same incoming fingerprint
//! - Long strings that exercise allocation reuse in clone_from()
//! - Special characters including newlines and control characters
//!
//! All tests use `#[must_use]` on merge_false_positive_baselines to ensure
//! the return value is captured, which is the correct usage pattern.

use diffguard_analytics::{
    FalsePositiveBaseline, FalsePositiveEntry, merge_false_positive_baselines,
};

/// Edge case: Unicode strings (non-ASCII characters) are preserved correctly.
/// This verifies clone_from() handles UTF-8 correctly.
#[test]
fn test_merge_preserves_unicode_strings() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp_unicode".to_string(),
        rule_id: "规则.rust".to_string(),
        path: "src/ファイル.rs".to_string(),
        line: 42,
        note: Some("日本語のメモ".to_string()),
    });

    let incoming = FalsePositiveBaseline::default();
    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].rule_id, "规则.rust");
    assert_eq!(merged.entries[0].path, "src/ファイル.rs");
    assert_eq!(merged.entries[0].note.as_deref(), Some("日本語のメモ"));
}

/// Edge case: Very long strings are preserved correctly.
/// This exercises clone_from() allocation reuse path for large strings.
#[test]
fn test_merge_preserves_long_strings() {
    let long_string = "x".repeat(100_000);
    let long_note = "n".repeat(50_000);

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp_long".to_string(),
        rule_id: long_string.clone(),
        path: format!("src/{}.rs", long_string),
        line: u32::MAX,
        note: Some(long_note.clone()),
    });

    let incoming = FalsePositiveBaseline::default();
    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].rule_id.len(), 100_000);
    assert!(merged.entries[0].path.starts_with("src/"));
    assert!(merged.entries[0].path.ends_with(".rs"));
    assert_eq!(merged.entries[0].note.as_ref().unwrap().len(), 50_000);
}

/// Edge case: Strings with special characters (newlines, tabs, nulls) are preserved.
#[test]
fn test_merge_preserves_special_characters() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp_special".to_string(),
        rule_id: "rule\twith\ttabs".to_string(),
        path: "src/with spaces/file.rs".to_string(),
        line: 1,
        note: Some("note\nwith\nnewlines".to_string()),
    });

    let incoming = FalsePositiveBaseline::default();
    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    assert!(merged.entries[0].rule_id.contains('\t'));
    assert!(merged.entries[0].path.contains(' '));
    assert!(merged.entries[0].note.as_ref().unwrap().contains('\n'));
}

/// Edge case: Self-assignment — same entry fingerprint in both base and incoming.
/// When base and incoming have the SAME fingerprint, base fills empty fields only.
/// clone_from() should work correctly even when source and dest point to equal values.
#[test]
fn test_merge_with_identical_fingerprints_both_have_data() {
    // Both base and incoming have the same fingerprint with non-empty data
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "same_fp".to_string(),
        rule_id: "rule_from_base".to_string(),
        path: "base.rs".to_string(),
        line: 10,
        note: Some("base note".to_string()),
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "same_fp".to_string(),
        rule_id: "rule_from_incoming".to_string(),
        path: "incoming.rs".to_string(),
        line: 20,
        note: Some("incoming note".to_string()),
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    // Incoming is primary; base only fills EMPTY fields
    // Since both have non-empty values, incoming should win
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].rule_id, "rule_from_incoming");
    assert_eq!(merged.entries[0].path, "incoming.rs");
    assert_eq!(merged.entries[0].line, 20);
    assert_eq!(merged.entries[0].note.as_deref(), Some("incoming note"));
}

/// Edge case: Empty string fields in incoming get filled from base.
#[test]
fn test_merge_fills_empty_rule_id_and_path_from_base() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp_empty".to_string(),
        rule_id: "rule_from_base".to_string(),
        path: "base.rs".to_string(),
        line: 10,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp_empty".to_string(),
        rule_id: "".to_string(), // empty - should be filled from base
        path: "".to_string(),    // empty - should be filled from base
        line: 0,                 // zero - should be filled from base
        note: None,              // None - should remain None (base has no note either)
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    // Empty fields in incoming should be filled from base
    assert_eq!(merged.entries[0].rule_id, "rule_from_base");
    assert_eq!(merged.entries[0].path, "base.rs");
    assert_eq!(merged.entries[0].line, 10);
    // Note was None in both, should remain None
    assert!(merged.entries[0].note.is_none());
}

/// Edge case: note field - base has note, incoming doesn't (None).
/// Base's note should NOT overwrite incoming's note when incoming has note.
#[test]
fn test_merge_does_not_overwrite_incoming_note_with_base_note() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp_note".to_string(),
        rule_id: "rule".to_string(),
        path: "f.rs".to_string(),
        line: 1,
        note: Some("base note".to_string()),
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp_note".to_string(),
        rule_id: "rule".to_string(),
        path: "f.rs".to_string(),
        line: 1,
        note: Some("incoming note".to_string()), // incoming has a note
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    // Incoming's note should NOT be overwritten by base's note
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].note.as_deref(), Some("incoming note"));
}

/// Edge case: Multiple base entries that all match the same incoming fingerprint.
/// Only one entry per fingerprint should exist in the result (dedup behavior).
#[test]
fn test_merge_with_multiple_base_entries_matching_same_fingerprint() {
    let mut base = FalsePositiveBaseline::default();
    // First entry with the fingerprint - provides rule_id
    base.entries.push(FalsePositiveEntry {
        fingerprint: "dup_fp".to_string(),
        rule_id: "rule_from_first".to_string(),
        path: "".to_string(),
        line: 0,
        note: None,
    });
    // Second entry with the SAME fingerprint - provides path
    base.entries.push(FalsePositiveEntry {
        fingerprint: "dup_fp".to_string(),
        rule_id: "".to_string(),
        path: "path_from_second.rs".to_string(),
        line: 0,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "dup_fp".to_string(),
        rule_id: "".to_string(),
        path: "".to_string(),
        line: 0,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    // After normalization and dedup, should have exactly 1 entry
    assert_eq!(merged.entries.len(), 1);
    // The entry should have rule_id from the first base entry
    assert_eq!(merged.entries[0].rule_id, "rule_from_first");
    // The entry should have path from the second base entry
    assert_eq!(merged.entries[0].path, "path_from_second.rs");
}

/// Edge case: clone_from semantics - verify that calling clone_from
/// produces identical results to clone() for String fields.
#[test]
fn test_clone_from_produces_same_result_as_clone() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp_test".to_string(),
        rule_id: "rule_id_value".to_string(),
        path: "path_value".to_string(),
        line: 99,
        note: Some("note_value".to_string()),
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp_test".to_string(),
        rule_id: "".to_string(),
        path: "".to_string(),
        line: 0,
        note: None,
    });

    // This merge should fill empty fields from base using clone_from()
    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].rule_id, "rule_id_value");
    assert_eq!(merged.entries[0].path, "path_value");
    assert_eq!(merged.entries[0].line, 99);
    assert_eq!(merged.entries[0].note.as_deref(), Some("note_value"));
}

/// Edge case: Empty baseline (no entries) - should return normalized incoming.
#[test]
fn test_merge_with_both_empty_baselines() {
    let base = FalsePositiveBaseline::default();
    let incoming = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 0);
    assert_eq!(
        merged.schema,
        diffguard_analytics::FALSE_POSITIVE_BASELINE_SCHEMA_V1
    );
}

/// Edge case: Very large number of entries to verify clone_from scales.
#[test]
fn test_merge_with_large_number_of_entries() {
    let mut base = FalsePositiveBaseline::default();
    let mut incoming = FalsePositiveBaseline::default();

    // Create 1000 entries in each baseline
    for i in 0..1000 {
        let fingerprint = format!("fp_{:04}", i);
        base.entries.push(FalsePositiveEntry {
            fingerprint: fingerprint.clone(),
            rule_id: format!("rule_{}", i),
            path: format!("src/file_{}.rs", i),
            line: i as u32,
            note: Some(format!("note_{}", i)),
        });
        incoming.entries.push(FalsePositiveEntry {
            fingerprint,
            rule_id: "".to_string(),
            path: "".to_string(),
            line: 0,
            note: None,
        });
    }

    let merged = merge_false_positive_baselines(&base, &incoming);

    // Should have 1000 unique entries
    assert_eq!(merged.entries.len(), 1000);
    // Verify first and last entries have correct data
    assert_eq!(merged.entries[0].rule_id, "rule_0");
    assert_eq!(merged.entries[0].line, 0);
    assert_eq!(merged.entries[999].rule_id, "rule_999");
    assert_eq!(merged.entries[999].line, 999);
}
