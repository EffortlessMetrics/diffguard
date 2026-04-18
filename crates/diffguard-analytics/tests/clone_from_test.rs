//! Tests verifying `merge_false_positive_baselines` uses `clone_from()` correctly.
//!
//! These tests ensure the merge function:
//! - Preserves existing rule_id when base has one and incoming is empty
//! - Preserves existing path when base has one and incoming is empty
//! - Uses `clone_from()` pattern (verified via clippy check)

use diffguard_analytics::{
    FalsePositiveBaseline, FalsePositiveEntry, merge_false_positive_baselines,
};

/// Test that when base has a rule_id and incoming's rule_id is empty,
/// the existing rule_id is preserved (not overwritten with empty string).
#[test]
fn test_merge_preserves_existing_rule_id_when_incoming_is_empty() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.one".to_string(), // existing has rule_id
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "".to_string(), // incoming has empty rule_id
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // The existing rule_id should be preserved, not overwritten with empty string
    assert_eq!(merged.entries[0].rule_id, "rule.one");
}

/// Test that when base has a path and incoming's path is empty,
/// the existing path is preserved (not overwritten with empty string).
#[test]
fn test_merge_preserves_existing_path_when_incoming_is_empty() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.one".to_string(),
        path: "existing.rs".to_string(), // existing has path
        line: 1,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.one".to_string(),
        path: "".to_string(), // incoming has empty path
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // The existing path should be preserved, not overwritten with empty string
    assert_eq!(merged.entries[0].path, "existing.rs");
}

/// Test that when base has a path and incoming also has a path,
/// the incoming path is used (since base path is empty).
#[test]
fn test_merge_uses_incoming_path_when_base_path_is_empty() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.one".to_string(),
        path: "".to_string(), // base has empty path
        line: 1,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.one".to_string(),
        path: "incoming.rs".to_string(), // incoming has path
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Since base path is empty, incoming path should be used
    assert_eq!(merged.entries[0].path, "incoming.rs");
}

/// Test that when base has a rule_id and incoming also has a rule_id,
/// the incoming rule_id is used (since base rule_id is empty).
#[test]
fn test_merge_uses_incoming_rule_id_when_base_rule_id_is_empty() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "".to_string(), // base has empty rule_id
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.incoming".to_string(), // incoming has rule_id
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Since base rule_id is empty, incoming rule_id should be used
    assert_eq!(merged.entries[0].rule_id, "rule.incoming");
}
