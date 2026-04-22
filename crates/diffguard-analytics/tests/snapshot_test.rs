//! Snapshot tests for `false_positive_fingerprint_set()` output.
//!
//! These tests capture the deterministic output of `false_positive_fingerprint_set()`
//! for representative inputs, creating baselines that will detect any future
//! output changes.
//!
//! The function returns a `BTreeSet<String>` of fingerprints (SHA-256 hashes).
//! Since BTreeSet iteration order is deterministic, we can snapshot the debug
//! representation directly.

use diffguard_analytics::{
    FalsePositiveBaseline, FalsePositiveEntry, false_positive_fingerprint_set,
};

/// Helper to create a baseline from a list of (fingerprint, rule_id, path, line) tuples.
fn baseline_from_tuples(entries: Vec<(&str, &str, &str, u32)>) -> FalsePositiveBaseline {
    FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: entries
            .into_iter()
            .map(|(fp, rule_id, path, line)| FalsePositiveEntry {
                fingerprint: fp.to_string(),
                rule_id: rule_id.to_string(),
                path: path.to_string(),
                line,
                note: None,
            })
            .collect(),
    }
}

// ============================================================================
// Snapshot 1: Empty baseline — empty BTreeSet
// ============================================================================

#[test]
fn snapshot_empty_baseline_output() {
    let baseline = FalsePositiveBaseline::default();
    let result = false_positive_fingerprint_set(&baseline);

    // Snapshot the debug representation of the empty set
    let snapshot = format!("{:?}", result);
    insta::assert_snapshot!("empty_baseline_fingerprint_set", snapshot);
}

// ============================================================================
// Snapshot 2: Single entry — singleton BTreeSet with one fingerprint
// ============================================================================

#[test]
fn snapshot_single_entry_fingerprint_set() {
    let baseline = baseline_from_tuples(vec![("abc123def456", "rule1", "src/lib.rs", 10)]);
    let result = false_positive_fingerprint_set(&baseline);

    let snapshot = format!("{:?}", result);
    insta::assert_snapshot!("single_entry_fingerprint_set", snapshot);
}

// ============================================================================
// Snapshot 3: Multiple entries — sorted BTreeSet of fingerprints
// ============================================================================

#[test]
fn snapshot_multiple_entries_fingerprint_set() {
    // Note: fingerprints are already sorted alphabetically
    let baseline = baseline_from_tuples(vec![
        ("fp_alpha", "rule1", "a.rs", 1),
        ("fp_beta", "rule2", "b.rs", 2),
        ("fp_gamma", "rule3", "c.rs", 3),
    ]);
    let result = false_positive_fingerprint_set(&baseline);

    let snapshot = format!("{:?}", result);
    insta::assert_snapshot!("multiple_entries_fingerprint_set", snapshot);
}

// ============================================================================
// Snapshot 4: SHA-256 fingerprints (64 hex chars) — realistic output
// ============================================================================

#[test]
fn snapshot_sha256_fingerprints() {
    // Real SHA-256 hex strings are 64 characters
    let baseline = baseline_from_tuples(vec![
        (
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "rust.no_unwrap",
            "src/lib.rs",
            12,
        ),
        (
            "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
            "rust.no_expect",
            "src/main.rs",
            20,
        ),
    ]);
    let result = false_positive_fingerprint_set(&baseline);

    let snapshot = format!("{:?}", result);
    insta::assert_snapshot!("sha256_fingerprints", snapshot);
}

// ============================================================================
// Snapshot 5: Deduplication — duplicate fingerprints collapse to one
// ============================================================================

#[test]
fn snapshot_deduplication_behavior() {
    // Three entries but two share the same fingerprint
    let baseline = baseline_from_tuples(vec![
        ("dup_fp", "rule1", "a.rs", 1),
        ("unique_fp", "rule2", "b.rs", 2),
        ("dup_fp", "rule3", "c.rs", 3), // duplicate
    ]);
    let result = false_positive_fingerprint_set(&baseline);

    // Result should have only 2 entries (deduplicated)
    let snapshot = format!("{:?}", result);
    insta::assert_snapshot!("deduplicated_fingerprint_set", snapshot);
}

// ============================================================================
// Snapshot 6: Unicode fingerprints — UTF-8 in fingerprints
// ============================================================================

#[test]
fn snapshot_unicode_fingerprints() {
    let baseline = baseline_from_tuples(vec![
        ("fp_日本語", "rule1", "src/lib.rs", 1),
        ("fp_🎉", "rule2", "src/main.rs", 2),
    ]);
    let result = false_positive_fingerprint_set(&baseline);

    let snapshot = format!("{:?}", result);
    insta::assert_snapshot!("unicode_fingerprints", snapshot);
}

// ============================================================================
// Snapshot 7: Large baseline — 100 entries, verifying sorted order
// ============================================================================

#[test]
fn snapshot_large_baseline_sorted_order() {
    let entries: Vec<FalsePositiveEntry> = (0..100)
        .map(|i| FalsePositiveEntry {
            fingerprint: format!("fp_{:08}", i),
            rule_id: format!("rule_{}", i),
            path: format!("src_{}.rs", i),
            line: i,
            note: None,
        })
        .collect();
    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries,
    };
    let result = false_positive_fingerprint_set(&baseline);

    // Just snapshot the count and first/last few items to verify sorting
    let items: Vec<&String> = result.iter().collect();
    let summary = format!(
        "count={}, first={}, last={}, items={:?}",
        result.len(),
        items.first().unwrap(),
        items.last().unwrap(),
        &items[..5] // first 5 items
    );
    insta::assert_snapshot!("large_baseline_sorted_order", summary);
}
