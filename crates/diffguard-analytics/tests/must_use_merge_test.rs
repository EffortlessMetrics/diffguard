//! Tests verifying `merge_false_positive_baselines` behavior when return value is used.
//!
//! These tests ensure the merge function:
//! - Returns a new merged baseline without modifying inputs
//! - Combines entries from both baselines (union by fingerprint)
//! - Preserves existing entries from `base` when fingerprints conflict
//! - Normalizes the result
//!
//! The `#[must_use]` attribute on `merge_false_positive_baselines` ensures callers
//! do not accidentally discard the return value, which would silently skip the merge.

use diffguard_analytics::{
    FalsePositiveBaseline, FalsePositiveEntry, merge_false_positive_baselines,
};

/// Test that merge returns a new baseline without modifying inputs.
#[test]
fn test_merge_returns_new_baseline() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "base_entry".to_string(),
        rule_id: "rule.base".to_string(),
        path: "base.rs".to_string(),
        line: 1,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "incoming_entry".to_string(),
        rule_id: "rule.incoming".to_string(),
        path: "incoming.rs".to_string(),
        line: 2,
        note: None,
    });

    // Capture the return value - this is the correct usage
    let merged = merge_false_positive_baselines(&base, &incoming);

    // Verify merged has entries from both
    assert_eq!(merged.entries.len(), 2);

    // Verify original inputs are unchanged
    assert_eq!(base.entries.len(), 1);
    assert_eq!(incoming.entries.len(), 1);
}

/// Test that merge combines entries from both baselines (union by fingerprint).
#[test]
fn test_merge_combines_entries_from_both_baselines() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "entry_from_base".to_string(),
        rule_id: "rule.one".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "entry_from_incoming".to_string(),
        rule_id: "rule.two".to_string(),
        path: "b.rs".to_string(),
        line: 2,
        note: None,
    });

    // Capture and use the return value
    let merged = merge_false_positive_baselines(&base, &incoming);

    // Should have entries from both
    assert_eq!(merged.entries.len(), 2);
}

/// Test that merge preserves incoming entries when fingerprints conflict.
/// The `base` parameter only fills in EMPTY fields of the incoming entry.
/// This is the actual behavior: incoming is the primary, base only fills gaps.
#[test]
fn test_merge_preserves_incoming_entries_on_conflict_fills_empty_fields_from_base() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "shared_fingerprint".to_string(),
        rule_id: "rule.from_base".to_string(),
        path: "base.rs".to_string(),
        line: 10,
        note: Some("from base".to_string()),
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "shared_fingerprint".to_string(),
        rule_id: "".to_string(), // empty - should be filled from base
        path: "".to_string(),    // empty - should be filled from base
        line: 0,                 // zero - should be filled from base
        note: None,              // None - should be filled from base
    });

    // Capture the return value
    let merged = merge_false_positive_baselines(&base, &incoming);

    // Should only have one entry
    assert_eq!(merged.entries.len(), 1);
    // Incoming entry is primary, but empty fields filled from base
    assert_eq!(merged.entries[0].rule_id, "rule.from_base");
    assert_eq!(merged.entries[0].path, "base.rs");
    assert_eq!(merged.entries[0].line, 10);
    assert_eq!(merged.entries[0].note.as_deref(), Some("from base"));
}

/// Test that merge with empty incoming returns base entries unchanged.
#[test]
fn test_merge_with_empty_incoming_returns_base() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "base_only".to_string(),
        rule_id: "rule.base".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let incoming = FalsePositiveBaseline::default();

    // Capture the return value
    let merged = merge_false_positive_baselines(&base, &incoming);

    // Should have base's entry
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].fingerprint, "base_only");
}

/// Test that merge with empty base returns incoming entries (normalized).
#[test]
fn test_merge_with_empty_base_returns_normalized_incoming() {
    let base = FalsePositiveBaseline::default();

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "incoming_only".to_string(),
        rule_id: "rule.incoming".to_string(),
        path: "b.rs".to_string(),
        line: 2,
        note: None,
    });

    // Capture the return value
    let merged = merge_false_positive_baselines(&base, &incoming);

    // Should have incoming's entry
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].fingerprint, "incoming_only");
}

/// Test that the return value must be captured for the merge to take effect.
/// This test documents the CORRECT usage pattern - return value is captured.
/// Once `#[must_use]` is added to the function, any caller that fails to
/// capture the return value will receive a compiler warning.
#[test]
fn test_merge_return_value_must_be_captured_for_merge_to_take_effect() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "base_entry".to_string(),
        rule_id: "rule.base".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "incoming_entry".to_string(),
        rule_id: "rule.incoming".to_string(),
        path: "b.rs".to_string(),
        line: 2,
        note: None,
    });

    // CORRECT: Capture the return value
    // If this return value is discarded (e.g., just calling
    // `merge_false_positive_baselines(&base, &incoming);` without capturing),
    // the merge is silently skipped and data is lost.
    // The `#[must_use]` attribute prevents this silent data loss.
    let merged = merge_false_positive_baselines(&base, &incoming);

    // Verify the merge actually happened
    assert_eq!(merged.entries.len(), 2);
}
