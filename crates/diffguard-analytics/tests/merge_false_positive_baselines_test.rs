//! Edge case tests for `merge_false_positive_baselines`.
//!
//! These tests verify the function handles edge cases correctly:
//! - Empty inputs
//! - Boundary values (max, zero)
//! - Unicode and special characters
//! - Various field combinations
//! - Immutability of input parameters
//!
//! NOTE: The function starts with `incoming` as the base merged result,
//! then fills in missing (empty/zero) fields from `base` for overlapping fingerprints.

use diffguard_analytics::{
    FalsePositiveBaseline, FalsePositiveEntry, merge_false_positive_baselines,
};

/// Helper to create a baseline with a single entry.
fn baseline_with_entry(
    fingerprint: &str,
    rule_id: &str,
    path: &str,
    line: u32,
    note: Option<&str>,
) -> FalsePositiveBaseline {
    let mut baseline = FalsePositiveBaseline::default();
    baseline.entries.push(FalsePositiveEntry {
        fingerprint: fingerprint.to_string(),
        rule_id: rule_id.to_string(),
        path: path.to_string(),
        line,
        note: note.map(String::from),
    });
    baseline
}

// ============================================================================
// Empty inputs
// ============================================================================

#[test]
fn test_merge_both_baselines_empty() {
    let base = FalsePositiveBaseline::default();
    let incoming = FalsePositiveBaseline::default();
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert!(merged.entries.is_empty());
}

#[test]
fn test_merge_only_base_has_entries() {
    // base has entries, incoming is empty
    // Result should contain base's entries
    let base = baseline_with_entry("fp1", "rule1", "a.rs", 10, Some("known"));
    let incoming = FalsePositiveBaseline::default();
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].fingerprint, "fp1");
    assert_eq!(merged.entries[0].note.as_deref(), Some("known"));
}

#[test]
fn test_merge_only_incoming_has_entries() {
    // base is empty, incoming has entries
    // Result should contain incoming's entries
    let base = FalsePositiveBaseline::default();
    let incoming = baseline_with_entry("fp1", "rule1", "a.rs", 10, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].fingerprint, "fp1");
    assert!(merged.entries[0].note.is_none());
}

// ============================================================================
// Merge direction: incoming is primary, base fills empty fields
// ============================================================================

#[test]
fn test_merge_incoming_wins_for_non_empty_fields() {
    // Both have the same fingerprint with different values
    // Incoming has non-empty values, base has different values
    // Incoming should win (be preserved)
    let base = baseline_with_entry("fp1", "base.rule", "base.rs", 10, Some("base note"));
    let incoming = baseline_with_entry(
        "fp1",
        "incoming.rule",
        "incoming.rs",
        20,
        Some("incoming note"),
    );

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Incoming's values should be preserved (base only fills empty)
    assert_eq!(merged.entries[0].rule_id, "incoming.rule");
    assert_eq!(merged.entries[0].path, "incoming.rs");
    assert_eq!(merged.entries[0].line, 20);
    assert_eq!(merged.entries[0].note.as_deref(), Some("incoming note"));
}

#[test]
fn test_merge_base_fills_incoming_empty_fields() {
    // Incoming has empty fields, base has values
    // Base should fill in the empty fields
    let base = baseline_with_entry("fp1", "base.rule", "base.rs", 10, Some("base note"));
    let incoming = baseline_with_entry("fp1", "", "", 0, None);

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Base's values should fill the empty fields in incoming
    assert_eq!(merged.entries[0].rule_id, "base.rule");
    assert_eq!(merged.entries[0].path, "base.rs");
    assert_eq!(merged.entries[0].line, 10);
    assert_eq!(merged.entries[0].note.as_deref(), Some("base note"));
}

#[test]
fn test_merge_partial_fill_from_base() {
    // Incoming has some empty fields, base has values for those
    // Only empty fields should be filled
    let base = baseline_with_entry("fp1", "base.rule", "", 0, None);
    let incoming = baseline_with_entry("fp1", "", "incoming.rs", 5, Some("note"));

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Incoming's non-empty fields preserved, empty fields filled from base
    assert_eq!(merged.entries[0].rule_id, "base.rule"); // was empty, filled from base
    assert_eq!(merged.entries[0].path, "incoming.rs"); // was non-empty, preserved
    assert_eq!(merged.entries[0].line, 5); // was non-zero, preserved
    assert_eq!(merged.entries[0].note.as_deref(), Some("note")); // was Some, preserved
}

// ============================================================================
// Boundary values
// ============================================================================

#[test]
fn test_merge_with_zero_line_in_incoming_filled_from_base() {
    // Incoming has line=0 (empty-ish), base has line=100
    // line should be filled from base
    let base = baseline_with_entry("fp1", "", "", 100, None);
    let incoming = baseline_with_entry("fp1", "", "", 0, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].line, 100);
}

#[test]
fn test_merge_with_nonzero_line_in_incoming_preserved() {
    // Incoming has line=42 (non-zero), base has line=100
    // Incoming's line should be preserved
    let base = baseline_with_entry("fp1", "", "", 100, None);
    let incoming = baseline_with_entry("fp1", "", "", 42, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].line, 42);
}

#[test]
fn test_merge_with_max_line_value_preserved() {
    // Incoming has u32::MAX, base has 1
    // MAX should be preserved
    let base = baseline_with_entry("fp1", "", "", 1, None);
    let incoming = baseline_with_entry("fp1", "", "", u32::MAX, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].line, u32::MAX);
}

#[test]
fn test_merge_with_empty_rule_id_and_path_filled_from_base() {
    let base = baseline_with_entry("fp1", "rule1", "a.rs", 10, None);
    let incoming = baseline_with_entry("fp1", "", "", 0, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Empty strings in incoming should be filled from base
    assert_eq!(merged.entries[0].rule_id, "rule1");
    assert_eq!(merged.entries[0].path, "a.rs");
    assert_eq!(merged.entries[0].line, 10);
}

#[test]
fn test_merge_with_non_empty_rule_id_and_path_preserved() {
    let base = baseline_with_entry("fp1", "base.rule", "base.rs", 5, None);
    let incoming = baseline_with_entry("fp1", "incoming.rule", "incoming.rs", 99, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Non-empty values in incoming should be preserved
    assert_eq!(merged.entries[0].rule_id, "incoming.rule");
    assert_eq!(merged.entries[0].path, "incoming.rs");
    assert_eq!(merged.entries[0].line, 99);
}

// ============================================================================
// Unicode and special characters
// ============================================================================

#[test]
fn test_merge_with_unicode_fingerprint() {
    let base = baseline_with_entry("fp_with_unicode_αβγ", "", "", 0, None);
    let incoming = baseline_with_entry("fp_with_unicode_αβγ", "rule1", "a.rs", 1, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].fingerprint, "fp_with_unicode_αβγ");
}

#[test]
fn test_merge_with_unicode_path() {
    let base = baseline_with_entry("fp1", "rule1", "日本語.rs", 1, None);
    let incoming = baseline_with_entry("fp1", "", "", 0, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].path, "日本語.rs");
}

#[test]
fn test_merge_with_unicode_note() {
    let base = baseline_with_entry("fp1", "rule1", "a.rs", 1, Some("这是个笔记"));
    let incoming = baseline_with_entry("fp1", "", "", 0, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].note.as_deref(), Some("这是个笔记"));
}

#[test]
fn test_merge_with_special_chars_in_rule_id() {
    let base = baseline_with_entry("fp1", "rule-with-dashes_and_underscores", "a.rs", 1, None);
    let incoming = baseline_with_entry("fp1", "", "", 0, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(
        merged.entries[0].rule_id,
        "rule-with-dashes_and_underscores"
    );
}

#[test]
fn test_merge_with_whitespace_in_note_copied_when_incoming_note_is_none() {
    // Note: when incoming.note is None and base.note is Some("  "), the note IS copied
    // because None is the "empty" state for Option<String>
    let base = baseline_with_entry("fp1", "  ", "  ", 0, Some("  "));
    let incoming = baseline_with_entry("fp1", "incoming", "incoming.rs", 1, None);
    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // incoming's non-empty values are preserved for rule_id/path/line
    assert_eq!(merged.entries[0].rule_id, "incoming");
    assert_eq!(merged.entries[0].path, "incoming.rs");
    assert_eq!(merged.entries[0].line, 1);
    // BUT note is copied from base because incoming.note is None
    assert_eq!(merged.entries[0].note, Some("  ".to_string()));
}

// ============================================================================
// Multiple entries and fingerprint deduplication
// ============================================================================

#[test]
fn test_merge_multiple_entries_no_overlap() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp1".to_string(),
        rule_id: "rule1".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp2".to_string(),
        rule_id: "rule2".to_string(),
        path: "b.rs".to_string(),
        line: 2,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp3".to_string(),
        rule_id: "rule3".to_string(),
        path: "c.rs".to_string(),
        line: 3,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 3);
}

#[test]
fn test_merge_fingerprint_deduplication_incoming_wins() {
    // Same fingerprint, different metadata - incoming should win (base only fills empty)
    let base = baseline_with_entry("fp1", "base.rule", "base.rs", 10, Some("base note"));
    let incoming = baseline_with_entry(
        "fp1",
        "incoming.rule",
        "incoming.rs",
        20,
        Some("incoming note"),
    );

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Incoming values are preserved
    assert_eq!(merged.entries[0].rule_id, "incoming.rule");
    assert_eq!(merged.entries[0].path, "incoming.rs");
    assert_eq!(merged.entries[0].line, 20);
    assert_eq!(merged.entries[0].note.as_deref(), Some("incoming note"));
}

#[test]
fn test_merge_base_entry_fills_incoming_empty_fields() {
    // Base has some non-empty fields, incoming is mostly empty
    let base = baseline_with_entry("fp1", "rule1", "a.rs", 10, None);
    let incoming = baseline_with_entry("fp1", "", "", 0, None);

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Base's values should fill incoming's empty fields
    assert_eq!(merged.entries[0].rule_id, "rule1");
    assert_eq!(merged.entries[0].path, "a.rs");
    assert_eq!(merged.entries[0].line, 10);
}

#[test]
fn test_merge_normalize_removes_duplicates() {
    // Create incoming with duplicate fingerprints (after normalization only one survives)
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp1".to_string(),
        rule_id: "rule1".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp1".to_string(),
        rule_id: "rule2".to_string(),
        path: "b.rs".to_string(),
        line: 2,
        note: None,
    });

    let merged = merge_false_positive_baselines(&FalsePositiveBaseline::default(), &incoming);
    // Should only have one entry (deduplicated by normalize)
    assert_eq!(merged.entries.len(), 1);
}

// ============================================================================
// Immutability verification
// ============================================================================

#[test]
fn test_merge_does_not_mutate_base() {
    let base = baseline_with_entry("fp1", "rule1", "a.rs", 10, Some("base note"));
    let base_clone = base.clone();
    let incoming = baseline_with_entry("fp1", "rule2", "b.rs", 20, None);

    let _merged = merge_false_positive_baselines(&base, &incoming);
    // Base should be unchanged
    assert_eq!(base, base_clone);
}

#[test]
fn test_merge_does_not_mutate_incoming() {
    let incoming = baseline_with_entry("fp1", "rule1", "a.rs", 10, None);
    let incoming_clone = incoming.clone();
    let base = baseline_with_entry("fp1", "rule2", "b.rs", 20, Some("base note"));

    let _merged = merge_false_positive_baselines(&base, &incoming);
    // Incoming should be unchanged
    assert_eq!(incoming, incoming_clone);
}

// ============================================================================
// Schema preservation
// ============================================================================

#[test]
fn test_merge_preserves_schema() {
    let base = baseline_with_entry("fp1", "rule1", "a.rs", 1, None);
    let incoming = baseline_with_entry("fp1", "rule1", "a.rs", 1, None);

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert!(
        merged
            .schema
            .starts_with("diffguard.false_positive_baseline")
    );
}

#[test]
fn test_merge_normalizes_empty_schema() {
    let mut incoming = baseline_with_entry("fp1", "rule1", "a.rs", 1, None);
    incoming.schema = String::new();

    let merged = merge_false_positive_baselines(&FalsePositiveBaseline::default(), &incoming);
    assert!(
        merged
            .schema
            .starts_with("diffguard.false_positive_baseline")
    );
}

// ============================================================================
// Entry ordering (sorted by fingerprint after normalize)
// ============================================================================

#[test]
fn test_merge_entries_are_sorted() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "z_fingerprint".to_string(),
        rule_id: "rule".to_string(),
        path: "z.rs".to_string(),
        line: 1,
        note: None,
    });
    base.entries.push(FalsePositiveEntry {
        fingerprint: "a_fingerprint".to_string(),
        rule_id: "rule".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &FalsePositiveBaseline::default());
    // Entries should be sorted by fingerprint after normalization
    assert_eq!(merged.entries.len(), 2);
    assert_eq!(merged.entries[0].fingerprint, "a_fingerprint");
    assert_eq!(merged.entries[1].fingerprint, "z_fingerprint");
}
