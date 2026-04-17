//! Integration tests for baseline workflows in diffguard-analytics.
//!
//! These tests exercise the complete flow of creating, merging, and using
//! false-positive baselines through the public API.

use diffguard_analytics::{
    baseline_from_receipt, false_positive_fingerprint_set, merge_false_positive_baselines,
    normalize_false_positive_baseline, FalsePositiveBaseline, FalsePositiveEntry,
};
use diffguard_types::{CheckReceipt, DiffMeta, Finding, Severity, ToolMeta, Verdict,
                       VerdictCounts, VerdictStatus};
use std::collections::BTreeSet;

/// Creates a minimal CheckReceipt for testing.
fn make_receipt(findings: Vec<Finding>) -> CheckReceipt {
    CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 3,
            scope: diffguard_types::Scope::Added,
            files_scanned: 1,
            lines_scanned: 10,
        },
        findings,
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    }
}

/// Creates a Finding with the given rule_id, path, and line.
fn make_finding(rule_id: &str, path: &str, line: u32) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Error,
        message: format!("{} violation", rule_id),
        path: path.to_string(),
        line,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: format!("line {} in {}", line, path),
    }
}

// =============================================================================
// Integration Test 1: baseline_from_receipt → fingerprint_set pipeline
// =============================================================================

/// Scenario: Create baseline from receipt, then compute fingerprint set.
///
/// Flow: receipt → baseline_from_receipt → false_positive_fingerprint_set
///
/// This tests the complete pipeline from a check receipt to a fingerprint set
/// used for false-positive suppression.
#[test]
fn integration_receipt_to_fingerprint_set() {
    // Given: A receipt with findings
    let findings = vec![
        make_finding("rust.no_unwrap", "src/lib.rs", 10),
        make_finding("rust.no_unwrap", "src/lib.rs", 20),
        make_finding("rust.no_dbg", "src/main.rs", 5),
    ];
    let receipt = make_receipt(findings);

    // When: Creating a baseline from the receipt
    let baseline = baseline_from_receipt(&receipt);

    // Then: The baseline has the correct schema
    assert_eq!(baseline.schema, "diffguard.false_positive_baseline.v1");

    // And: The baseline has 3 entries
    assert_eq!(baseline.entries.len(), 3);

    // When: Computing the fingerprint set
    let fps = false_positive_fingerprint_set(&baseline);

    // Then: The fingerprint set has 3 entries
    assert_eq!(fps.len(), 3);

    // And: All fingerprints are 64-character hex strings (SHA-256)
    for fp in &fps {
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// =============================================================================
// Integration Test 2: merge_false_positive_baselines end-to-end
// =============================================================================

/// Scenario: Merge two baselines with disjoint entries.
///
/// Flow: base + incoming → merge_false_positive_baselines → merged baseline
#[test]
fn integration_merge_disjoint_baselines() {
    // Given: A base baseline with one entry
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "base_fp".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "src/base.rs".to_string(),
        line: 1,
        note: Some("intentional".to_string()),
    });

    // And: An incoming baseline with a different entry
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "incoming_fp".to_string(),
        rule_id: "rust.no_dbg".to_string(),
        path: "src/new.rs".to_string(),
        line: 5,
        note: None,
    });

    // When: Merging the baselines
    let merged = merge_false_positive_baselines(&base, &incoming);

    // Then: The merged baseline has both entries
    assert_eq!(merged.entries.len(), 2);

    // And: The entries are sorted by fingerprint
    let fingerprints: Vec<_> = merged.entries.iter().map(|e| &e.fingerprint).collect();
    assert!(fingerprints.windows(2).all(|w| w[0] <= w[1]));

    // And: The schema is set correctly
    assert_eq!(merged.schema, "diffguard.false_positive_baseline.v1");
}

/// Scenario: Merge where incoming has duplicate fingerprints to base.
///
/// Flow: base (with fp "abc") + incoming (with fp "abc") → merged (single entry)
#[test]
fn integration_merge_with_duplicate_fingerprint() {
    // Given: A base baseline with fingerprint "abc"
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "a.rs".to_string(),
        line: 10,
        note: Some("curated note".to_string()),
    });

    // And: An incoming baseline with the same fingerprint but different metadata
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "abc".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "a.rs".to_string(),
        line: 10,
        note: None, // No note in incoming - base should be preserved
    });

    // When: Merging the baselines
    let merged = merge_false_positive_baselines(&base, &incoming);

    // Then: The merged baseline has only one entry (deduplication worked)
    assert_eq!(merged.entries.len(), 1);

    // And: The note from base was preserved
    assert_eq!(merged.entries[0].note.as_deref(), Some("curated note"));
}

/// Scenario: Merge with empty base.
///
/// Flow: empty base + incoming → incoming (normalized)
#[test]
fn integration_merge_with_empty_base() {
    // Given: An empty base baseline
    let base = FalsePositiveBaseline::default();

    // And: An incoming baseline with entries
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "incoming1".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "src/lib.rs".to_string(),
        line: 1,
        note: None,
    });
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "incoming2".to_string(),
        rule_id: "rust.no_dbg".to_string(),
        path: "src/main.rs".to_string(),
        line: 5,
        note: None,
    });

    // When: Merging with empty base
    let merged = merge_false_positive_baselines(&base, &incoming);

    // Then: The merged baseline has both entries
    assert_eq!(merged.entries.len(), 2);

    // And: Entries are sorted and deduplicated
    let fps: Vec<_> = merged.entries.iter().map(|e| &e.fingerprint[..]).collect();
    assert!(fps.windows(2).all(|w| w[0] <= w[1]));
}

/// Scenario: Merge with empty incoming.
///
/// Flow: base + empty incoming → base (normalized)
#[test]
fn integration_merge_with_empty_incoming() {
    // Given: A base baseline with entries
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "base1".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "src/lib.rs".to_string(),
        line: 1,
        note: None,
    });

    // And: An empty incoming baseline
    let incoming = FalsePositiveBaseline::default();

    // When: Merging with empty incoming
    let merged = merge_false_positive_baselines(&base, &incoming);

    // Then: The merged baseline has the base entry
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].fingerprint, "base1");
}

// =============================================================================
// Integration Test 3: normalize_false_positive_baseline in isolation
// =============================================================================

/// Scenario: Normalize a baseline with empty schema.
///
/// Flow: baseline (empty schema) → normalize → baseline (schema set)
#[test]
fn integration_normalize_sets_empty_schema() {
    // Given: A baseline with empty schema
    let mut baseline = FalsePositiveBaseline {
        schema: String::new(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "fp1".to_string(),
                rule_id: "rust.no_unwrap".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "fp2".to_string(),
                rule_id: "rust.no_dbg".to_string(),
                path: "b.rs".to_string(),
                line: 5,
                note: None,
            },
        ],
    };

    // When: Normalizing the baseline
    normalize_false_positive_baseline(&mut baseline);

    // Then: The schema is set
    assert_eq!(baseline.schema, "diffguard.false_positive_baseline.v1");

    // And: Entries are still present
    assert_eq!(baseline.entries.len(), 2);
}

/// Scenario: Normalize sorts and deduplicates entries.
///
/// Flow: baseline (unsorted, duplicates) → normalize → baseline (sorted, deduped)
#[test]
fn integration_normalize_sorts_and_deduplicates() {
    // Given: A baseline with unsorted entries and duplicates
    let mut baseline = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "z_fp".to_string(), // Will be sorted last
                rule_id: "rust.no_unwrap".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "a_fp".to_string(), // Will be sorted first
                rule_id: "rust.no_dbg".to_string(),
                path: "b.rs".to_string(),
                line: 5,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "a_fp".to_string(), // Duplicate - should be removed
                rule_id: "rust.no_dbg".to_string(),
                path: "b.rs".to_string(),
                line: 5,
                note: None,
            },
        ],
    };

    // When: Normalizing the baseline
    normalize_false_positive_baseline(&mut baseline);

    // Then: Entries are sorted by fingerprint
    let fps: Vec<_> = baseline.entries.iter().map(|e| &e.fingerprint[..]).collect();
    assert!(fps.windows(2).all(|w| w[0] <= w[1]));

    // And: Duplicates are removed
    assert_eq!(baseline.entries.len(), 2);
    let fps: BTreeSet<_> = baseline.entries.iter().map(|e| &e.fingerprint[..]).collect();
    assert_eq!(fps.len(), 2);
}

// =============================================================================
// Integration Test 4: Multiple normalize calls in sequence
// =============================================================================

/// Scenario: Normalize can be called multiple times safely.
///
/// This is important because merge_false_positive_baselines calls normalize
/// twice: once on the incoming clone, and once on the final merged result.
#[test]
fn integration_normalize_idempotent_across_calls() {
    // Given: A baseline with unsorted entries
    let mut baseline = FalsePositiveBaseline {
        schema: String::new(), // Empty schema
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "z_fp".to_string(),
                rule_id: "rust.no_unwrap".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "a_fp".to_string(),
                rule_id: "rust.no_dbg".to_string(),
                path: "b.rs".to_string(),
                line: 5,
                note: None,
            },
        ],
    };

    // When: Normalizing multiple times
    normalize_false_positive_baseline(&mut baseline);
    let first_result = baseline.clone();
    normalize_false_positive_baseline(&mut baseline);
    let second_result = baseline.clone();
    normalize_false_positive_baseline(&mut baseline);
    let third_result = baseline;

    // Then: Results are identical (idempotent)
    assert_eq!(first_result, second_result);
    assert_eq!(second_result, third_result);

    // And: Schema is set
    assert_eq!(first_result.schema, "diffguard.false_positive_baseline.v1");

    // And: Entries are sorted
    let fps: Vec<_> = first_result.entries.iter().map(|e| &e.fingerprint[..]).collect();
    assert!(fps.windows(2).all(|w| w[0] <= w[1]));
}

// =============================================================================
// Integration Test 5: Full workflow - receipt → baseline → merge → fingerprint set
// =============================================================================

/// Scenario: Complete workflow from findings to fingerprint set.
///
/// Flow:
///   1. Create receipt with findings
///   2. Build baseline from receipt
///   3. Build another baseline from different receipt
///   4. Merge baselines
///   5. Compute fingerprint set for suppression
#[test]
fn integration_full_workflow_receipt_to_fingerprint_set() {
    // Step 1: Create first receipt and baseline
    let findings1 = vec![
        make_finding("rust.no_unwrap", "src/lib.rs", 10),
        make_finding("rust.no_dbg", "src/main.rs", 5),
    ];
    let receipt1 = make_receipt(findings1);
    let baseline1 = baseline_from_receipt(&receipt1);

    // Step 2: Create second receipt with overlapping and new findings
    let findings2 = vec![
        make_finding("rust.no_unwrap", "src/lib.rs", 10), // Same as in receipt1
        make_finding("rust.no_unwrap", "src/new.rs", 20), // New finding
    ];
    let receipt2 = make_receipt(findings2);
    let baseline2 = baseline_from_receipt(&receipt2);

    // Step 3: Merge the baselines
    let merged = merge_false_positive_baselines(&baseline1, &baseline2);

    // Step 4: Compute fingerprint set
    let fps = false_positive_fingerprint_set(&merged);

    // Then: The merged baseline has 3 unique fingerprints
    assert_eq!(fps.len(), 3);

    // And: The merged baseline is properly normalized (sorted, deduplicated)
    let fps_vec: Vec<_> = fps.iter().collect();
    assert!(fps_vec.windows(2).all(|w| w[0] <= w[1]));

    // And: The merged baseline has correct schema
    assert_eq!(merged.schema, "diffguard.false_positive_baseline.v1");
}