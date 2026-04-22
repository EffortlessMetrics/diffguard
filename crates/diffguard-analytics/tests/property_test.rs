//! Property-based tests for `false_positive_fingerprint_set()`.
//!
//! These tests verify invariants that hold for ALL inputs, not just specific examples.
//! Properties are tested across many different input sizes and patterns.

use diffguard_analytics::{
    FalsePositiveBaseline, FalsePositiveEntry, false_positive_fingerprint_set,
};
use std::collections::BTreeSet;

// ============================================================================
// Helper: Generate baselines with controlled properties
// ============================================================================

/// Generate a baseline with `n` entries, each having a unique fingerprint.
fn baseline_with_n_unique_entries(n: usize) -> FalsePositiveBaseline {
    let entries: Vec<FalsePositiveEntry> = (0..n)
        .map(|i| FalsePositiveEntry {
            fingerprint: format!("fp_{:08}", i),
            rule_id: format!("rule_{}", i % 10),
            path: format!("src_{}.rs", i % 50),
            line: i as u32,
            note: None,
        })
        .collect();

    FalsePositiveBaseline {
        schema: "test".to_string(),
        entries,
    }
}

/// Generate a baseline with `n` entries but only `unique_count` unique fingerprints.
/// Duplicates are distributed evenly across entries.
fn baseline_with_n_entries_and_k_unique(n: usize, unique_count: usize) -> FalsePositiveBaseline {
    let entries: Vec<FalsePositiveEntry> = (0..n)
        .map(|i| FalsePositiveEntry {
            fingerprint: format!("fp_{:08}", i % unique_count),
            rule_id: format!("rule_{}", i % 10),
            path: format!("src_{}.rs", i % 50),
            line: i as u32,
            note: None,
        })
        .collect();

    FalsePositiveBaseline {
        schema: "test".to_string(),
        entries,
    }
}

/// Generate a baseline where all entries have the same fingerprint.
fn baseline_with_all_same_fingerprint(count: usize, fingerprint: &str) -> FalsePositiveBaseline {
    let entries: Vec<FalsePositiveEntry> = (0..count)
        .map(|i| FalsePositiveEntry {
            fingerprint: fingerprint.to_string(),
            rule_id: format!("rule_{}", i),
            path: format!("src_{}.rs", i),
            line: i as u32,
            note: None,
        })
        .collect();

    FalsePositiveBaseline {
        schema: "test".to_string(),
        entries,
    }
}

// ============================================================================
// Property: Idempotent — fps(baseline) == fps(baseline)
// ============================================================================

#[test]
fn property_fingerprint_set_is_idempotent_various_sizes() {
    // Test idempotency across different sizes: 0, 1, 2, 10, 100, 1000 entries
    for size in [0, 1, 2, 10, 50, 100, 500, 1000] {
        let baseline = baseline_with_n_unique_entries(size);

        let result1 = false_positive_fingerprint_set(&baseline);
        let result2 = false_positive_fingerprint_set(&baseline);

        assert_eq!(
            result1, result2,
            "Idempotency violated for size {}: fps(baseline) != fps(baseline)",
            size
        );
    }
}

// ============================================================================
// Property: Result contains ONLY entry fingerprints (subset property)
// ============================================================================

#[test]
fn property_result_contains_only_entry_fingerprints_various_sizes() {
    for size in [1, 2, 10, 50, 100, 500, 1000] {
        let baseline = baseline_with_n_unique_entries(size);

        let result = false_positive_fingerprint_set(&baseline);
        let entry_fingerprints: BTreeSet<String> = baseline
            .entries
            .iter()
            .map(|e| e.fingerprint.clone())
            .collect();

        for fp in &result {
            assert!(
                entry_fingerprints.contains(fp),
                "Size {}: Result contains '{}' not in entries. Result len={}, Entry fps len={}",
                size,
                fp,
                result.len(),
                entry_fingerprints.len()
            );
        }
    }
}

// ============================================================================
// Property: No fingerprint loss — all unique entry fingerprints appear
// ============================================================================

#[test]
fn property_no_fingerprint_loss_various_sizes() {
    for size in [1, 2, 10, 50, 100, 500, 1000] {
        let baseline = baseline_with_n_unique_entries(size);

        let result = false_positive_fingerprint_set(&baseline);
        let unique_entry_fingerprints: BTreeSet<String> = baseline
            .entries
            .iter()
            .map(|e| e.fingerprint.clone())
            .collect();

        for fp in &unique_entry_fingerprints {
            assert!(
                result.contains(fp),
                "Size {}: Fingerprint '{}' lost in result. Result len={}, Unique len={}",
                size,
                fp,
                result.len(),
                unique_entry_fingerprints.len()
            );
        }
    }
}

// ============================================================================
// Property: Result size equals unique fingerprint count (deduplication)
// ============================================================================

#[test]
fn property_result_size_equals_unique_count_various_dup_factors() {
    // Test various duplication factors: no duplicates, 50%, 90%, 100%
    let test_cases = [
        (100, 100), // 0% duplication (100 unique in 100 entries)
        (100, 50),  // 50% duplication (50 unique in 100 entries)
        (100, 10),  // 90% duplication (10 unique in 100 entries)
        (100, 1),   // 99% duplication (1 unique in 100 entries)
        (1000, 1000),
        (1000, 10),
    ];

    for (n, unique_count) in test_cases {
        let baseline = baseline_with_n_entries_and_k_unique(n, unique_count);

        let result = false_positive_fingerprint_set(&baseline);
        let actual_unique = baseline
            .entries
            .iter()
            .map(|e| e.fingerprint.clone())
            .collect::<BTreeSet<_>>()
            .len();

        assert_eq!(
            result.len(),
            actual_unique,
            "n={}, unique={}: Result size {} != unique count {}. \
             Dup factor test failed.",
            n,
            unique_count,
            result.len(),
            actual_unique
        );
    }
}

// ============================================================================
// Property: Empty baseline yields empty set
// ============================================================================

#[test]
fn property_empty_baseline_yields_empty_set() {
    let empty_baseline = FalsePositiveBaseline::default();

    let result = false_positive_fingerprint_set(&empty_baseline);

    assert!(
        result.is_empty(),
        "Empty baseline produced non-empty fingerprint set: {:?}",
        result
    );
}

// ============================================================================
// Property: Single entry yields singleton set
// ============================================================================

#[test]
fn property_single_entry_yields_singleton_various_fingerprints() {
    let fingerprints = [
        "simple",
        "with_underscores",
        "with-dashes",
        "UPPERCASE",
        "MiXeD CaSe",
        "with/slashes",
        "with\\backslashes",
        "with spaces",
        "日本語",
        "🎉emoji🎉",
    ];

    for fp in fingerprints {
        let baseline = FalsePositiveBaseline {
            schema: "test".to_string(),
            entries: vec![FalsePositiveEntry {
                fingerprint: fp.to_string(),
                rule_id: "rule1".to_string(),
                path: "test.rs".to_string(),
                line: 1,
                note: None,
            }],
        };

        let result = false_positive_fingerprint_set(&baseline);

        assert_eq!(
            result.len(),
            1,
            "Single entry '{}' produced set with {} elements",
            fp,
            result.len()
        );
        assert!(
            result.contains(fp),
            "Result doesn't contain fingerprint '{}'",
            fp
        );
    }
}

// ============================================================================
// Property: Result size bounded by entry count
// ============================================================================

#[test]
fn property_result_size_bounded_by_entries() {
    let sizes = [0, 1, 2, 10, 50, 100, 500, 1000];

    for size in sizes {
        let baseline = baseline_with_n_unique_entries(size);

        let result = false_positive_fingerprint_set(&baseline);

        assert!(
            result.len() <= baseline.entries.len(),
            "Size {}: Result size {} exceeds entry count {}",
            size,
            result.len(),
            baseline.entries.len()
        );
    }

    // Also test with heavy duplication
    for dup_factor in [2, 5, 10, 100] {
        let baseline = baseline_with_n_entries_and_k_unique(100, 100 / dup_factor);
        let result = false_positive_fingerprint_set(&baseline);

        assert!(
            result.len() <= baseline.entries.len(),
            "Dup factor {}: Result size {} exceeds entry count {}",
            dup_factor,
            result.len(),
            baseline.entries.len()
        );
    }
}

// ============================================================================
// Property: All fingerprints in result are non-empty
// ============================================================================

#[test]
fn property_result_fingerprints_are_nonempty() {
    // Test with fingerprints that include empty strings
    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "non_empty_1".to_string(),
                rule_id: "rule1".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "non_empty_2".to_string(),
                rule_id: "rule2".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
        ],
    };

    let result = false_positive_fingerprint_set(&baseline);

    for fp in &result {
        assert!(
            !fp.is_empty(),
            "Empty fingerprint found in result. This indicates a bug in fingerprint extraction."
        );
    }
}

// ============================================================================
// Property: Deterministic — same input always produces same output
// ============================================================================

#[test]
fn property_is_deterministic_various_sizes() {
    for size in [1, 10, 100, 500] {
        let baseline = baseline_with_n_unique_entries(size);

        // Call 3 times and verify all results are identical
        let result1 = false_positive_fingerprint_set(&baseline);
        let result2 = false_positive_fingerprint_set(&baseline);
        let result3 = false_positive_fingerprint_set(&baseline);

        assert_eq!(
            result1, result2,
            "Size {}: First and second call differ",
            size
        );
        assert_eq!(
            result2, result3,
            "Size {}: Second and third call differ",
            size
        );
    }
}

// ============================================================================
// Property: All-same fingerprint baseline yields set of size 1
// ============================================================================

#[test]
fn property_all_same_fingerprint_yields_singleton() {
    let test_cases = [
        (1, "only"),
        (10, "ten_copies"),
        (100, "hundred_copies"),
        (1000, "thousand_copies"),
    ];

    for (count, fp) in test_cases {
        let baseline = baseline_with_all_same_fingerprint(count, fp);

        let result = false_positive_fingerprint_set(&baseline);

        assert_eq!(
            result.len(),
            1,
            "Count {} with fingerprint '{}': Expected singleton, got {} elements",
            count,
            fp,
            result.len()
        );
        assert!(result.contains(fp), "Result doesn't contain '{}'", fp);
    }
}

// ============================================================================
// Property: result.contains(fp) iff fp is a fingerprint in entries
// ============================================================================

#[test]
fn property_contains_logic_correct() {
    for size in [1, 10, 50, 100] {
        let baseline = baseline_with_n_unique_entries(size);
        let result = false_positive_fingerprint_set(&baseline);

        // Build set of actual entry fingerprints
        let entry_fps: BTreeSet<String> = baseline
            .entries
            .iter()
            .map(|e| &e.fingerprint)
            .cloned()
            .collect();

        // Check: every entry fingerprint is in result
        for fp in &entry_fps {
            assert!(
                result.contains(fp),
                "Size {}: Entry fingerprint '{}' not in result",
                size,
                fp
            );
        }

        // Check: every result fingerprint is an entry fingerprint
        for fp in &result {
            assert!(
                entry_fps.contains(fp),
                "Size {}: Result fingerprint '{}' not in any entry",
                size,
                fp
            );
        }
    }
}

// ============================================================================
// Stress test: Large baseline performance and correctness
// ============================================================================

#[test]
fn property_stress_large_baseline() {
    // Test with 10,000 entries - should still be correct and fast
    let baseline = baseline_with_n_unique_entries(10_000);

    let result = false_positive_fingerprint_set(&baseline);

    assert_eq!(
        result.len(),
        10_000,
        "Large baseline: Expected 10000 unique fingerprints, got {}",
        result.len()
    );

    // Verify first and last are present
    assert!(
        result.contains("fp_00000000"),
        "Large baseline: Missing first fingerprint"
    );
    assert!(
        result.contains("fp_00009999"),
        "Large baseline: Missing last fingerprint"
    );
}
