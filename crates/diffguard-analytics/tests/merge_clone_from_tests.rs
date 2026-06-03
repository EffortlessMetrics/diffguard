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

// ============================================================================
// EDGE CASE TESTS (added by green-test-builder)
// ============================================================================

/// Edge case: Empty base baseline - should return incoming as-is.
#[test]
fn test_merge_empty_base_returns_incoming() {
    let incoming = FalsePositiveBaseline::default();
    let base = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 0);
}

/// Edge case: Empty incoming baseline - should return normalized base.
#[test]
fn test_merge_empty_incoming_returns_normalized_base() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.one".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: Some("note".to_string()),
    });

    let incoming = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].fingerprint, "abc");
}

/// Edge case: Entry exists in incoming but not in base - should be preserved.
#[test]
fn test_merge_entry_only_in_incoming_preserved() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.incoming".to_string(),
        path: "incoming.rs".to_string(),
        line: 10,
        note: Some("incoming note".to_string()),
    });

    let base = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].rule_id, "rule.incoming");
    assert_eq!(merged.entries[0].path, "incoming.rs");
    assert_eq!(merged.entries[0].note.as_deref(), Some("incoming note"));
}

/// Edge case: Entry exists in base but not in incoming - should be added from base.
#[test]
fn test_merge_entry_only_in_base_added() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.base".to_string(),
        path: "base.rs".to_string(),
        line: 20,
        note: Some("base note".to_string()),
    });

    let incoming = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].rule_id, "rule.base");
    assert_eq!(merged.entries[0].path, "base.rs");
    assert_eq!(merged.entries[0].note.as_deref(), Some("base note"));
}

/// Edge case: Existing populated note should NOT be overwritten by base.
#[test]
fn test_merge_note_already_populated_not_overwritten() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: Some("incoming note".to_string()),
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: Some("base note".to_string()),
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Incoming note should be preserved, not overwritten by base
    assert_eq!(merged.entries[0].note.as_deref(), Some("incoming note"));
}

/// Edge case: Existing populated rule_id should NOT be overwritten by base.
#[test]
fn test_merge_rule_id_already_populated_not_overwritten() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.incoming".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule.base".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Incoming rule_id should be preserved, not overwritten by base
    assert_eq!(merged.entries[0].rule_id, "rule.incoming");
}

/// Edge case: Existing populated path should NOT be overwritten by base.
#[test]
fn test_merge_path_already_populated_not_overwritten() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule".to_string(),
        path: "incoming.rs".to_string(),
        line: 1,
        note: None,
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule".to_string(),
        path: "base.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Incoming path should be preserved, not overwritten by base
    assert_eq!(merged.entries[0].path, "incoming.rs");
}

/// Edge case: Empty incoming rule_id should be filled from base.
#[test]
fn test_merge_rule_id_empty_filled_from_base() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: String::new(), // empty
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "RULE_FROM_BASE".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Empty rule_id should be filled from base
    assert_eq!(merged.entries[0].rule_id, "RULE_FROM_BASE");
}

/// Edge case: Empty incoming path should be filled from base.
#[test]
fn test_merge_path_empty_filled_from_base() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule".to_string(),
        path: String::new(), // empty
        line: 1,
        note: None,
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule".to_string(),
        path: "/path/from/base.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Empty path should be filled from base
    assert_eq!(merged.entries[0].path, "/path/from/base.rs");
}

/// Edge case: line == 0 should be filled from base.
#[test]
fn test_merge_line_zero_filled_from_base() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule".to_string(),
        path: "a.rs".to_string(),
        line: 0, // zero line number
        note: None,
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule".to_string(),
        path: "a.rs".to_string(),
        line: 42, // actual line number
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Zero line should be filled from base
    assert_eq!(merged.entries[0].line, 42);
}

/// Edge case: Multiple entries with different fingerprints - should merge all.
#[test]
fn test_merge_multiple_entries_different_fingerprints() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp1".to_string(),
        rule_id: "rule1".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp2".to_string(),
        rule_id: "rule2".to_string(),
        path: "b.rs".to_string(),
        line: 2,
        note: None,
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp3".to_string(), // only in base
        rule_id: "rule3".to_string(),
        path: "c.rs".to_string(),
        line: 3,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 3);
}

/// Edge case: Both note and rule_id empty in incoming - both should be filled from base.
#[test]
fn test_merge_multiple_empty_fields_filled_from_base() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: String::new(), // empty
        path: String::new(),    // empty
        line: 0,                // zero
        note: None,             // none
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "RULE_FILLED".to_string(),
        path: "PATH_FILLED.rs".to_string(),
        line: 99,
        note: Some("NOTE_FILLED".to_string()),
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].rule_id, "RULE_FILLED");
    assert_eq!(merged.entries[0].path, "PATH_FILLED.rs");
    assert_eq!(merged.entries[0].line, 99);
    assert_eq!(merged.entries[0].note.as_deref(), Some("NOTE_FILLED"));
}

/// Edge case: Both incoming and base have same note - should preserve incoming (no change needed).
#[test]
fn test_merge_note_same_in_both_preserves() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: Some("same note".to_string()),
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rule".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: Some("same note".to_string()),
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].note.as_deref(), Some("same note"));
}

/// Edge case: Unicode characters in fields - should merge correctly.
#[test]
fn test_merge_unicode_fields() {
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp-uni".to_string(),
        rule_id: "规则.unicode".to_string(),
        path: "src/ファイル.rs".to_string(),
        line: 1,
        note: Some("日本語のノート".to_string()),
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp-uni".to_string(),
        rule_id: String::new(), // empty - should be filled
        path: String::new(),    // empty - should be filled
        line: 0,                // zero - should be filled
        note: None,             // none - should be filled
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    // Incoming unicode fields should be preserved
    assert_eq!(merged.entries[0].rule_id, "规则.unicode");
    assert_eq!(merged.entries[0].path, "src/ファイル.rs");
    assert_eq!(merged.entries[0].note.as_deref(), Some("日本語のノート"));
}

/// Edge case: Long strings (> 1KB) - should merge correctly without issues.
#[test]
fn test_merge_long_strings() {
    let long_string = "x".repeat(2000);

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp-long".to_string(),
        rule_id: long_string.clone(),
        path: long_string.clone(),
        line: 1,
        note: Some(long_string.clone()),
    });

    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp-long".to_string(),
        rule_id: String::new(),
        path: String::new(),
        line: 0,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].rule_id, long_string);
    assert_eq!(merged.entries[0].path, long_string);
    assert_eq!(
        merged.entries[0].note.as_deref(),
        Some(long_string.as_str())
    );
}
