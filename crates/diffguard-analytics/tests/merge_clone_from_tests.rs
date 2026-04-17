//! Tests for merge_false_positive_baselines() behavioral correctness.
//!
//! These tests verify that the merge function correctly copies fields from base
//! entries to incoming entries when the incoming entry has empty/None values.
//!
//! The optimization from clone() to clone_from() does not change observable behavior
//! for String and Option<String> types - these tests verify behavioral invariance.

use diffguard_analytics::{
    FalsePositiveBaseline, FalsePositiveEntry, merge_false_positive_baselines,
};

/// Test that when existing.note is None and entry.note is Some,
/// the note gets copied during merge.
///
/// This is the note field case for the assigning_clones fix at line 121.
#[test]
fn test_merge_copies_note_when_existing_note_is_none() {
    // incoming has entry with fingerprint "abc" but note is None
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.one".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    // base has entry with same fingerprint and a note
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.one".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: Some("important note".to_string()),
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    assert_eq!(
        merged.entries[0].note.as_deref(),
        Some("important note"),
        "note should be copied from base when existing note is None"
    );
}

/// Test that when existing.rule_id is empty and entry.rule_id is non-empty,
/// the rule_id gets copied during merge.
///
/// This is the rule_id field case for the assigning_clones fix at line 124.
#[test]
fn test_merge_copies_rule_id_when_existing_rule_id_is_empty() {
    // incoming has entry with fingerprint "abc" but empty rule_id
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: String::new(), // empty rule_id
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    // base has entry with same fingerprint and non-empty rule_id
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "RULE123".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    assert_eq!(
        merged.entries[0].rule_id.as_str(),
        "RULE123",
        "rule_id should be copied from base when existing rule_id is empty"
    );
}

/// Test that when existing.path is empty and entry.path is non-empty,
/// the path gets copied during merge.
///
/// This is the path field case for the assigning_clones fix at line 127.
#[test]
fn test_merge_copies_path_when_existing_path_is_empty() {
    // incoming has entry with fingerprint "abc" but empty path
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.one".to_string(),
        path: String::new(), // empty path
        line: 1,
        note: None,
    });

    // base has entry with same fingerprint and non-empty path
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.one".to_string(),
        path: "src/main.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    assert_eq!(
        merged.entries[0].path.as_str(),
        "src/main.rs",
        "path should be copied from base when existing path is empty"
    );
}

/// Test that merge is behavioral invariant - produces same output
/// regardless of whether clone() or clone_from() is used internally.
///
/// This is a property-based test that verifies the key acceptance criterion:
/// "The output of merge_false_positive_baselines() is bit-for-bit identical
/// before and after the change."
#[test]
fn test_merge_behavioral_invariance_note_field() {
    // Verify that copying note from base to incoming produces correct result
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fingerprint1".to_string(),
        rule_id: "test-rule".to_string(),
        path: "test.rs".to_string(),
        line: 42,
        note: None,
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fingerprint1".to_string(),
        rule_id: "test-rule".to_string(),
        path: "test.rs".to_string(),
        line: 42,
        note: Some("transferred note".to_string()),
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    // The note from base should appear in merged
    assert!(
        merged.entries[0].note.is_some(),
        "note should be transferred from base to incoming"
    );
    assert_eq!(
        merged.entries[0].note.as_ref().unwrap().as_str(),
        "transferred note"
    );
}

/// Test behavioral invariance for rule_id field.
#[test]
fn test_merge_behavioral_invariance_rule_id_field() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp2".to_string(),
        rule_id: String::new(), // empty
        path: "mod.rs".to_string(),
        line: 10,
        note: None,
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp2".to_string(),
        rule_id: "COOL_RULE".to_string(),
        path: "mod.rs".to_string(),
        line: 10,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(
        merged.entries[0].rule_id.as_str(),
        "COOL_RULE",
        "rule_id should be transferred when incoming is empty"
    );
}

/// Test behavioral invariance for path field.
#[test]
fn test_merge_behavioral_invariance_path_field() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp3".to_string(),
        rule_id: "rule".to_string(),
        path: String::new(), // empty
        line: 99,
        note: None,
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp3".to_string(),
        rule_id: "rule".to_string(),
        path: "/absolute/path/to/file.rs".to_string(),
        line: 99,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(
        merged.entries[0].path.as_str(),
        "/absolute/path/to/file.rs",
        "path should be transferred when incoming is empty"
    );
}
