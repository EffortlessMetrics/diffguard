//! Integration tests for merge_false_positive_baselines behavior.
//!
//! These tests document the expected behavior of the merge function:
//! - Existing metadata (note, rule_id, path, line) is preserved when present
//! - Input parameters (base, incoming) are not mutated
//! - Entries are properly merged by fingerprint
//!
//! NOTE: This work item (work-eefe7ef9) is CLOSED as NOT FEASIBLE because:
//! - The proposed optimization (using take() instead of clone()) cannot compile
//!   due to Rust borrowing rules (requires mutable access through shared reference)
//! - The optimization provides no benefit because conditional guards ensure
//!   destinations are always empty when assignment occurs
//!
//! These tests verify the CORRECT BEHAVIOR that any implementation must preserve.

use diffguard_analytics::{
    FalsePositiveBaseline, FalsePositiveEntry, merge_false_positive_baselines,
};

/// Test that existing rule_id is preserved when non-empty.
///
/// When merging entries with the same fingerprint, if the existing entry
/// has a non-empty rule_id, it should be preserved and not overwritten
/// by an empty rule_id from the incoming entry.
#[test]
fn test_merge_preserves_existing_rule_id_when_non_empty() {
    // Base has entry with non-empty rule_id
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc123".to_string(),
        rule_id: "rust.no_unwrap".to_string(), // non-empty
        path: "src/lib.rs".to_string(),
        line: 42,
        note: None,
    });

    // Incoming has same fingerprint but empty rule_id
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc123".to_string(),
        rule_id: "".to_string(), // empty
        path: "".to_string(),
        line: 0,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    // Existing non-empty rule_id should be preserved
    assert_eq!(
        merged.entries[0].rule_id, "rust.no_unwrap",
        "Expected existing rule_id 'rust.no_unwrap' to be preserved, got '{}'",
        merged.entries[0].rule_id
    );
}

/// Test that existing path is preserved when non-empty.
///
/// When merging entries with the same fingerprint, if the existing entry
/// has a non-empty path, it should be preserved and not overwritten
/// by an empty path from the incoming entry.
#[test]
fn test_merge_preserves_existing_path_when_non_empty() {
    // Base has entry with non-empty path
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc123".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "src/lib.rs".to_string(), // non-empty
        line: 42,
        note: None,
    });

    // Incoming has same fingerprint but empty path
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc123".to_string(),
        rule_id: "".to_string(),
        path: "".to_string(), // empty
        line: 0,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    // Existing non-empty path should be preserved
    assert_eq!(
        merged.entries[0].path, "src/lib.rs",
        "Expected existing path 'src/lib.rs' to be preserved, got '{}'",
        merged.entries[0].path
    );
}

/// Test that existing line is preserved when non-zero.
///
/// When merging entries with the same fingerprint, if the existing entry
/// has a non-zero line, it should be preserved and not overwritten
/// by line 0 from the incoming entry.
#[test]
fn test_merge_preserves_existing_line_when_nonzero() {
    // Base has entry with non-zero line
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc123".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42, // non-zero
        note: None,
    });

    // Incoming has same fingerprint but line 0
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc123".to_string(),
        rule_id: "".to_string(),
        path: "".to_string(),
        line: 0, // zero
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    // Existing non-zero line should be preserved
    assert_eq!(
        merged.entries[0].line, 42,
        "Expected existing line 42 to be preserved, got {}",
        merged.entries[0].line
    );
}

/// Test that base parameter is not mutated by merge operation.
///
/// The merge function receives shared references to base and incoming.
/// Neither should be mutated by the call.
#[test]
fn test_merge_does_not_mutate_base_parameter() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc123".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        note: Some("original note".to_string()),
    });

    // Capture original state
    let original_base = base.clone();

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc123".to_string(),
        rule_id: "different.rule".to_string(),
        path: "different/path.rs".to_string(),
        line: 100,
        note: Some("incoming note".to_string()),
    });

    // Perform merge
    let _merged = merge_false_positive_baselines(&base, &incoming);

    // Base should be unchanged
    assert_eq!(
        base.entries.len(),
        original_base.entries.len(),
        "Base entries count changed from {} to {}",
        original_base.entries.len(),
        base.entries.len()
    );
    assert_eq!(
        base.entries[0].rule_id, original_base.entries[0].rule_id,
        "Base rule_id changed from '{}' to '{}'",
        original_base.entries[0].rule_id, base.entries[0].rule_id
    );
    assert_eq!(
        base.entries[0].path, original_base.entries[0].path,
        "Base path changed from '{}' to '{}'",
        original_base.entries[0].path, base.entries[0].path
    );
    assert_eq!(
        base.entries[0].line, original_base.entries[0].line,
        "Base line changed from {} to {}",
        original_base.entries[0].line, base.entries[0].line
    );
    assert_eq!(
        base.entries[0].note, original_base.entries[0].note,
        "Base note changed from '{:?}' to '{:?}'",
        original_base.entries[0].note, base.entries[0].note
    );
}

/// Test that incoming parameter is not mutated by merge operation.
#[test]
fn test_merge_does_not_mutate_incoming_parameter() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc123".to_string(),
        rule_id: "incoming.rule".to_string(),
        path: "incoming/path.rs".to_string(),
        line: 99,
        note: Some("incoming note".to_string()),
    });

    // Capture original state
    let original_incoming = incoming.clone();

    let base = FalsePositiveBaseline::default();

    // Perform merge
    let _merged = merge_false_positive_baselines(&base, &incoming);

    // Incoming should be unchanged
    assert_eq!(
        incoming.entries.len(),
        original_incoming.entries.len(),
        "Incoming entries count changed from {} to {}",
        original_incoming.entries.len(),
        incoming.entries.len()
    );
    assert_eq!(
        incoming.entries[0].rule_id, original_incoming.entries[0].rule_id,
        "Incoming rule_id changed from '{}' to '{}'",
        original_incoming.entries[0].rule_id, incoming.entries[0].rule_id
    );
    assert_eq!(
        incoming.entries[0].path, original_incoming.entries[0].path,
        "Incoming path changed from '{}' to '{}'",
        original_incoming.entries[0].path, incoming.entries[0].path
    );
    assert_eq!(
        incoming.entries[0].line, original_incoming.entries[0].line,
        "Incoming line changed from {} to {}",
        original_incoming.entries[0].line, incoming.entries[0].line
    );
    assert_eq!(
        incoming.entries[0].note, original_incoming.entries[0].note,
        "Incoming note changed from '{:?}' to '{:?}'",
        original_incoming.entries[0].note, incoming.entries[0].note
    );
}

/// Test that entries unique to incoming are preserved in merged result.
#[test]
fn test_merge_includes_incoming_only_entries() {
    let base = FalsePositiveBaseline::default();

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "unique_fp".to_string(),
        rule_id: "some.rule".to_string(),
        path: "some/path.rs".to_string(),
        line: 10,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].fingerprint, "unique_fp");
    assert_eq!(merged.entries[0].rule_id, "some.rule");
}

/// Test that entries unique to base are preserved in merged result.
#[test]
fn test_merge_includes_base_only_entries() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "base_only_fp".to_string(),
        rule_id: "base.rule".to_string(),
        path: "base/path.rs".to_string(),
        line: 20,
        note: None,
    });

    let incoming = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].fingerprint, "base_only_fp");
    assert_eq!(merged.entries[0].rule_id, "base.rule");
}

/// Test that merged result is properly normalized (sorted, deduplicated).
#[test]
fn test_merge_result_is_normalized() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "zebra".to_string(),
        rule_id: "z.rule".to_string(),
        path: "z.rs".to_string(),
        line: 1,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "apple".to_string(),
        rule_id: "a.rule".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    // Should have 2 entries
    assert_eq!(merged.entries.len(), 2);
    // Should be sorted by fingerprint
    assert!(merged.entries[0].fingerprint < merged.entries[1].fingerprint);
}
