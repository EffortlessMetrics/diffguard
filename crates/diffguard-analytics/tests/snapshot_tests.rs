//! Snapshot tests for `merge_false_positive_baselines` output formats.
//!
//! These tests capture the current output of the merge function for various scenarios.
//! The snapshots document what the output looks like NOW - any change to the output
//! will be detected by these tests.
//!
//! Coverage:
//! 1. Both baselines empty
//! 2. Only base has entries
//! 3. Only incoming has entries
//! 4. Both have disjoint entries (union)
//! 5. Same fingerprint, different metadata (conflict resolution - base wins)
//! 6. Same fingerprint, base has note but incoming doesn't (note preserved)
//! 7. Same fingerprint, incoming has empty fields (filled from base)
//! 8. Normalization after merge (sorted, deduplicated)

use diffguard_analytics::{
    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    merge_false_positive_baselines, normalize_false_positive_baseline,
};

// ============================================================================
// Helper Functions
// ============================================================================

fn make_entry(
    fingerprint: &str,
    rule_id: &str,
    path: &str,
    line: u32,
    note: Option<&str>,
) -> FalsePositiveEntry {
    FalsePositiveEntry {
        fingerprint: fingerprint.to_string(),
        rule_id: rule_id.to_string(),
        path: path.to_string(),
        line,
        note: note.map(|s| s.to_string()),
    }
}

fn make_baseline(entries: Vec<FalsePositiveEntry>) -> FalsePositiveBaseline {
    let baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries,
    };
    // Always normalize to get deterministic output
    normalize_false_positive_baseline(baseline)
}

fn baseline_to_json(baseline: &FalsePositiveBaseline) -> String {
    serde_json::to_string_pretty(baseline).expect("serialize baseline")
}

// ============================================================================
// Snapshot Tests for merge_false_positive_baselines
// ============================================================================

/// Snapshot test: both baselines empty
#[test]
fn snapshot_merge_both_empty() {
    let base = make_baseline(vec![]);
    let incoming = make_baseline(vec![]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!("snapshot_merge_both_empty", baseline_to_json(&merged));
}

/// Snapshot test: only base has entries
#[test]
fn snapshot_merge_only_base_has_entries() {
    let base = make_baseline(vec![make_entry("aaa111", "rule.a", "a.rs", 1, None)]);
    let incoming = make_baseline(vec![]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!(
        "snapshot_merge_only_base_has_entries",
        baseline_to_json(&merged)
    );
}

/// Snapshot test: only incoming has entries
#[test]
fn snapshot_merge_only_incoming_has_entries() {
    let base = make_baseline(vec![]);
    let incoming = make_baseline(vec![make_entry("bbb222", "rule.b", "b.rs", 2, None)]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!(
        "snapshot_merge_only_incoming_has_entries",
        baseline_to_json(&merged)
    );
}

/// Snapshot test: both have disjoint entries (union)
#[test]
fn snapshot_merge_union_of_different_fingerprints() {
    let base = make_baseline(vec![make_entry("aaa111", "rule.a", "a.rs", 1, None)]);
    let incoming = make_baseline(vec![make_entry("bbb222", "rule.b", "b.rs", 2, None)]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!(
        "snapshot_merge_union_of_different_fingerprints",
        baseline_to_json(&merged)
    );
}

/// Snapshot test: same fingerprint, different note - base note preserved
#[test]
fn snapshot_merge_preserves_note_from_base() {
    let base = make_baseline(vec![make_entry(
        "aaa111",
        "rule.a",
        "a.rs",
        1,
        Some("curated note"),
    )]);
    let incoming = make_baseline(vec![make_entry("aaa111", "rule.a", "a.rs", 1, None)]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!(
        "snapshot_merge_preserves_note_from_base",
        baseline_to_json(&merged)
    );
}

/// Snapshot test: incoming has empty rule_id, filled from base
#[test]
fn snapshot_merge_fills_rule_id_from_incoming() {
    let base = make_baseline(vec![make_entry("aaa111", "rule.a", "a.rs", 1, None)]);
    let incoming = make_baseline(vec![make_entry("aaa111", "", "a.rs", 1, None)]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!(
        "snapshot_merge_fills_rule_id_from_incoming",
        baseline_to_json(&merged)
    );
}

/// Snapshot test: incoming has empty path, filled from base
#[test]
fn snapshot_merge_fills_path_from_incoming() {
    let base = make_baseline(vec![make_entry("aaa111", "rule.a", "a.rs", 1, None)]);
    let incoming = make_baseline(vec![make_entry("aaa111", "rule.a", "", 1, None)]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!(
        "snapshot_merge_fills_path_from_incoming",
        baseline_to_json(&merged)
    );
}

/// Snapshot test: incoming has line=0, filled from base
#[test]
fn snapshot_merge_fills_line_from_incoming_when_base_zero() {
    let base = make_baseline(vec![make_entry("aaa111", "rule.a", "a.rs", 1, None)]);
    let incoming = make_baseline(vec![make_entry("aaa111", "rule.a", "a.rs", 0, None)]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!(
        "snapshot_merge_fills_line_from_incoming_when_base_zero",
        baseline_to_json(&merged)
    );
}

/// Snapshot test: deduplication - same fingerprint in both
#[test]
fn snapshot_merge_duplicate_fingerprint_base_wins() {
    let base = make_baseline(vec![make_entry(
        "aaa111",
        "rule.a",
        "a.rs",
        1,
        Some("base"),
    )]);
    let incoming = make_baseline(vec![make_entry(
        "aaa111",
        "rule.a",
        "a.rs",
        1,
        Some("incoming"),
    )]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!(
        "snapshot_merge_duplicate_fingerprint_base_wins",
        baseline_to_json(&merged)
    );
}

/// Snapshot test: empty base with single incoming entry
#[test]
fn snapshot_merge_empty_base_with_single_entry() {
    let base = make_baseline(vec![]);
    let incoming = make_baseline(vec![make_entry("aaa111", "rule.a", "a.rs", 1, None)]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!(
        "snapshot_merge_empty_base_with_single_entry",
        baseline_to_json(&merged)
    );
}

/// Snapshot test: unicode in note
#[test]
fn snapshot_merge_unicode_in_note() {
    let base = make_baseline(vec![]);
    let incoming = make_baseline(vec![make_entry(
        "aaa111",
        "rule.a",
        "a.rs",
        1,
        Some("Héllo, wörld! 🌍"),
    )]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!("snapshot_merge_unicode_in_note", baseline_to_json(&merged));
}

/// Snapshot test: emoji in note
#[test]
fn snapshot_merge_emoji_in_note() {
    let base = make_baseline(vec![]);
    let incoming = make_baseline(vec![make_entry(
        "aaa111",
        "rule.a",
        "a.rs",
        1,
        Some("🚨⚠️✅❌"),
    )]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!("snapshot_merge_emoji_in_note", baseline_to_json(&merged));
}

/// Snapshot test: long strings in entry fields
#[test]
fn snapshot_merge_long_strings() {
    let long_rule = format!("rule.{}", "x".repeat(100));
    let long_path = format!("{}/{}", "src".repeat(20), "file.rs".repeat(10));
    let base = make_baseline(vec![]);
    let incoming = make_baseline(vec![make_entry(
        "aaa111",
        &long_rule,
        &long_path,
        1,
        Some(&"note".repeat(50)),
    )]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!("snapshot_merge_long_strings", baseline_to_json(&merged));
}

/// Snapshot test: incoming empty, base has entries
#[test]
fn snapshot_merge_with_empty_incoming() {
    let base = make_baseline(vec![make_entry("aaa111", "rule.a", "a.rs", 1, None)]);
    let incoming = make_baseline(vec![]);
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!(
        "snapshot_merge_with_empty_incoming",
        baseline_to_json(&merged)
    );
}
