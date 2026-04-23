//! Snapshot tests for `merge_false_positive_baselines()` output format.
//!
//! These tests capture the JSON output baseline for the merge function.
//! Any change to the output format (schema, field ordering, value formatting)
//! will be detected immediately by insta.
//!
//! The optimization from `clone()` to `clone_from()` is purely internal and
//! does not change the JSON output - these snapshots verify that invariance.

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
    FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: fingerprint.to_string(),
            rule_id: rule_id.to_string(),
            path: path.to_string(),
            line,
            note: note.map(String::from),
        }],
    }
}

/// Helper to serialize baseline to pretty JSON.
fn baseline_json(baseline: &FalsePositiveBaseline) -> String {
    serde_json::to_string_pretty(baseline).expect("serialize baseline")
}

// ============================================================================
// Happy Path Snapshots
// ============================================================================

/// Snapshot: merge empty base with incoming containing one entry.
/// Input: empty base, incoming with 1 entry
/// Output: normalized incoming entry
#[test]
fn snapshot_merge_empty_base_with_single_entry() {
    let incoming = baseline_with_entry("abc123", "RUST_NO_UNWRAP", "src/lib.rs", 42, None);
    let base = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

/// Snapshot: merge base with incoming where both have same fingerprint,
/// and base has note but incoming doesn't.
/// Input: base with note, incoming without note
/// Output: note preserved from base
#[test]
fn snapshot_merge_preserves_note_from_base() {
    let base = baseline_with_entry(
        "abc123",
        "RUST_NO_UNWRAP",
        "src/lib.rs",
        42,
        Some("intentional suppression"),
    );
    let incoming = baseline_with_entry("abc123", "RUST_NO_UNWRAP", "src/lib.rs", 42, None);

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

/// Snapshot: merge where base has empty rule_id and incoming has rule_id.
/// Input: base with empty rule_id, incoming with rule_id
/// Output: rule_id from incoming (since base is empty)
#[test]
fn snapshot_merge_fills_rule_id_from_incoming() {
    let base = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "abc123".to_string(),
            rule_id: String::new(), // empty
            path: "src/lib.rs".to_string(),
            line: 42,
            note: None,
        }],
    };
    let incoming = baseline_with_entry("abc123", "RUST_NO_UNWRAP", "src/lib.rs", 42, None);

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

/// Snapshot: merge where base has empty path and incoming has path.
/// Input: base with empty path, incoming with path
/// Output: path from incoming (since base is empty)
#[test]
fn snapshot_merge_fills_path_from_incoming() {
    let base = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "abc123".to_string(),
            rule_id: "RUST_NO_UNWRAP".to_string(),
            path: String::new(), // empty
            line: 42,
            note: None,
        }],
    };
    let incoming = baseline_with_entry("abc123", "RUST_NO_UNWRAP", "src/lib.rs", 42, None);

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

// ============================================================================
// Edge Case Snapshots
// ============================================================================

/// Snapshot: merge with zero line number.
/// Input: base has line=0, incoming has line=42
/// Output: line=42 from incoming (since base is zero)
#[test]
fn snapshot_merge_fills_line_from_incoming_when_base_zero() {
    let base = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "abc123".to_string(),
            rule_id: "RUST_NO_UNWRAP".to_string(),
            path: "src/lib.rs".to_string(),
            line: 0, // zero - should be filled from incoming
            note: None,
        }],
    };
    let incoming = baseline_with_entry("abc123", "RUST_NO_UNWRAP", "src/lib.rs", 42, None);

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

/// Snapshot: merge two baselines with different fingerprints (union).
/// Input: base with fingerprint A, incoming with fingerprint B
/// Output: both entries present
#[test]
fn snapshot_merge_union_of_different_fingerprints() {
    let base = baseline_with_entry("fingerprint_a", "RULE_A", "a.rs", 1, None);
    let incoming = baseline_with_entry("fingerprint_b", "RULE_B", "b.rs", 2, None);

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

/// Snapshot: merge with empty incoming (should normalize base).
/// Input: base with 1 entry, empty incoming
/// Output: normalized base entry
#[test]
fn snapshot_merge_with_empty_incoming() {
    let base = baseline_with_entry("abc123", "RUST_NO_UNWRAP", "src/lib.rs", 42, Some("note"));
    let incoming = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

/// Snapshot: merge with empty entries in both (should return normalized empty).
/// Input: empty base, empty incoming
/// Output: normalized empty baseline
#[test]
fn snapshot_merge_both_empty() {
    let base = FalsePositiveBaseline::default();
    let incoming = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

/// Snapshot: merge with duplicate fingerprint in both, base has all fields populated.
/// Input: same fingerprint in both, base has complete data
/// Output: base data preserved (incoming ignored for that fingerprint)
#[test]
fn snapshot_merge_duplicate_fingerprint_base_wins() {
    let base = baseline_with_entry(
        "shared_fp",
        "BASE_RULE",
        "base/path.rs",
        100,
        Some("base note"),
    );
    let incoming = baseline_with_entry(
        "shared_fp",
        "INCOMING_RULE",
        "incoming/path.rs",
        200,
        Some("incoming note"),
    );

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

// ============================================================================
// Unicode and Special Character Snapshots
// ============================================================================

/// Snapshot: merge with unicode in note field.
/// Input: base with unicode note
/// Output: unicode preserved
#[test]
fn snapshot_merge_unicode_in_note() {
    let base = baseline_with_entry(
        "fp1",
        "RULE",
        "main.rs",
        1,
        Some("笔记 - note with unicode"),
    );
    let incoming = baseline_with_entry("fp1", "RULE", "main.rs", 1, None);

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

/// Snapshot: merge with emoji in note field.
/// Input: base with emoji note
/// Output: emoji preserved
#[test]
fn snapshot_merge_emoji_in_note() {
    let base = baseline_with_entry(
        "fp1",
        "RULE",
        "main.rs",
        1,
        Some("🚨 important: suppress this"),
    );
    let incoming = baseline_with_entry("fp1", "RULE", "main.rs", 1, None);

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}

/// Snapshot: merge with long string values.
/// Input: long rule_id, path, note
/// Output: long strings preserved
#[test]
fn snapshot_merge_long_strings() {
    let long_rule = "RUST_LONGLONGLONGLONG_RULE_ID_THAT_EXCEEDS_TYPICAL_LENGTH".to_string();
    let long_path =
        "/very/long/path/to/some/deeply/nested/source/file/that/goes/on/for/a/while.rs".to_string();
    let long_note = "This is a very long note that contains many characters and should be preserved exactly as-is during the merge operation without any truncation or modification".to_string();

    let base = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "fp_long".to_string(),
            rule_id: long_rule.clone(),
            path: long_path.clone(),
            line: 9999,
            note: Some(long_note.clone()),
        }],
    };
    let incoming = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "fp_long".to_string(),
            rule_id: String::new(),
            path: String::new(),
            line: 0,
            note: None,
        }],
    };

    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = baseline_json(&merged);

    insta::assert_snapshot!(json);
}
