//! Property-based tests for `normalize_false_positive_baseline` and related functions.
//!
//! These tests verify invariants that should hold for ALL inputs, not just specific examples.

use diffguard_analytics::{
    false_positive_fingerprint_set, merge_false_positive_baselines,
    normalize_false_positive_baseline, FalsePositiveBaseline, FALSE_POSITIVE_BASELINE_SCHEMA_V1,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Proptest strategy for generating arbitrary FalsePositiveEntry values
// ---------------------------------------------------------------------------

fn arb_fingerprint() -> impl Strategy<Value = String> {
    // Just use any string - normalization doesn't validate fingerprint content
    any::<String>()
}

fn arb_printable_string() -> impl Strategy<Value = String> {
    // Just use any non-empty string
    any::<String>().prop_filter("non-empty".to_string(), |s| !s.is_empty())
}

fn arb_entry() -> impl Strategy<Value = diffguard_analytics::FalsePositiveEntry> {
    (
        arb_fingerprint(),
        arb_printable_string(),
        arb_printable_string(),
        any::<u32>(),
        prop::option::of(arb_printable_string()),
    )
        .prop_map(|(fingerprint, rule_id, path, line, note)| {
            diffguard_analytics::FalsePositiveEntry {
                fingerprint,
                rule_id,
                path,
                line,
                note,
            }
        })
}

fn arb_baseline() -> impl Strategy<Value = FalsePositiveBaseline> {
    let empty_schema = (
        Just(String::new()),
        prop::collection::vec(arb_entry(), 0..20_usize),
    )
        .prop_map(|(schema, entries)| FalsePositiveBaseline { schema, entries });

    let with_schema = (
        arb_printable_string(),
        prop::collection::vec(arb_entry(), 0..20_usize),
    )
        .prop_map(|(schema, entries)| FalsePositiveBaseline { schema, entries });

    prop_oneof![empty_schema, with_schema]
}

// ---------------------------------------------------------------------------
// Property 1: Idempotent — normalizing twice is same as normalizing once
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn property_normalize_idempotent(baseline in arb_baseline()) {
        // Normalize once
        let mut normalized1 = baseline.clone();
        normalize_false_positive_baseline(&mut normalized1);

        // Normalize twice
        let mut normalized2 = baseline.clone();
        normalize_false_positive_baseline(&mut normalized2);
        normalize_false_positive_baseline(&mut normalized2);

        // They should be equal
        prop_assert_eq!(normalized1, normalized2,
            "Normalizing twice should yield same result as normalizing once");
    }
}

// ---------------------------------------------------------------------------
// Property 2: Schema is set to V1 when empty
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn property_schema_set_when_empty(baseline in arb_baseline()) {
        let mut baseline = baseline;
        baseline.schema = String::new(); // Force empty

        normalize_false_positive_baseline(&mut baseline);

        prop_assert_eq!(
            baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1,
            "Empty schema should be set to V1 constant"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 3: Entries are sorted by (fingerprint, rule_id, path, line)
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn property_entries_are_sorted(baseline in arb_baseline()) {
        let mut baseline = baseline;
        normalize_false_positive_baseline(&mut baseline);

        for window in baseline.entries.windows(2) {
            let a = &window[0];
            let b = &window[1];
            let cmp = a.fingerprint
                .cmp(&b.fingerprint)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.line.cmp(&b.line));

            prop_assert!(
                cmp == std::cmp::Ordering::Less || cmp == std::cmp::Ordering::Equal,
                "Entries must be sorted by (fingerprint, rule_id, path, line); \
                 found {:?} >= {:?} at sort boundary",
                a, b
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 4: No duplicate fingerprints after normalization
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn property_no_duplicate_fingerprints(baseline in arb_baseline()) {
        let mut baseline = baseline;
        normalize_false_positive_baseline(&mut baseline);

        let mut seen = std::collections::HashSet::new();
        for entry in &baseline.entries {
            let was_new = seen.insert(entry.fingerprint.clone());
            prop_assert!(was_new,
                "Duplicate fingerprint found after normalization: {}", entry.fingerprint);
        }
    }
}

// ---------------------------------------------------------------------------
// Property 5: Merge produces union of fingerprints
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn property_merge_contains_all_fingerprints(
        base in arb_baseline(),
        incoming in arb_baseline(),
    ) {
        let result = merge_false_positive_baselines(&base, &incoming);
        let result_fps = false_positive_fingerprint_set(&result);

        let base_fps = false_positive_fingerprint_set(&base);
        let incoming_fps = false_positive_fingerprint_set(&incoming);

        // Every fingerprint from base should be in result
        for fp in base_fps.iter() {
            prop_assert!(
                result_fps.contains(fp),
                "Base fingerprint {:?} missing from merge result", fp
            );
        }

        // Every fingerprint from incoming should be in result
        for fp in incoming_fps.iter() {
            prop_assert!(
                result_fps.contains(fp),
                "Incoming fingerprint {:?} missing from merge result", fp
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Property 6: Merge is fingerprint-commutative
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn property_merge_fingerprint_commutative(
        a in arb_baseline(),
        b in arb_baseline(),
    ) {
        let result_ab = merge_false_positive_baselines(&a, &b);
        let result_ba = merge_false_positive_baselines(&b, &a);

        let fps_ab = false_positive_fingerprint_set(&result_ab);
        let fps_ba = false_positive_fingerprint_set(&result_ba);

        prop_assert_eq!(
            fps_ab, fps_ba,
            "Merge should be commutative with respect to fingerprints; \
             merge(a,b) fingerprints != merge(b,a) fingerprints"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 7: Normalization does not change fingerprint set
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn property_normalize_preserves_fingerprints(baseline in arb_baseline()) {
        let fps_before: std::collections::BTreeSet<_> =
            baseline.entries.iter().map(|e| e.fingerprint.clone()).collect();

        let mut normalized = baseline;
        normalize_false_positive_baseline(&mut normalized);

        let fps_after: std::collections::BTreeSet<_> =
            normalized.entries.iter().map(|e| e.fingerprint.clone()).collect();

        prop_assert_eq!(
            fps_before, fps_after,
            "Normalization should not change which fingerprints are present"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 8: Empty baseline normalizes correctly
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn property_empty_baseline_normalizes(schema in prop::option::of(arb_printable_string())) {
        let mut baseline = FalsePositiveBaseline {
            schema: schema.unwrap_or_default(),
            entries: vec![],
        };

        normalize_false_positive_baseline(&mut baseline);

        // Schema should be set to V1 if it was empty
        if baseline.schema.is_empty() {
            prop_assert_eq!(baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
        }
        prop_assert!(baseline.entries.is_empty(), "Empty entries should remain empty");
    }
}

// ---------------------------------------------------------------------------
// Property 9: Single entry baseline normalizes correctly
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn property_single_entry_normalizes(
        entry in arb_entry(),
        schema in prop::option::of(arb_printable_string()),
    ) {
        let mut baseline = FalsePositiveBaseline {
            schema: schema.unwrap_or_default(),
            entries: vec![entry],
        };

        normalize_false_positive_baseline(&mut baseline);

        // Should have exactly one entry
        prop_assert_eq!(baseline.entries.len(), 1);

        // Schema should be set if it was empty
        if baseline.schema.is_empty() {
            prop_assert_eq!(baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
        }
    }
}

// ---------------------------------------------------------------------------
// Property 10: Duplicate fingerprints are reduced to one (first wins)
// ---------------------------------------------------------------------------
proptest! {
    #[test]
    fn property_duplicate_fingerprints_reduced(
        fingerprint in arb_fingerprint(),
        count in 1usize..20,
    ) {
        // Create entries with the same fingerprint but different other fields
        let entries: Vec<_> = (0..count)
            .map(|i| diffguard_analytics::FalsePositiveEntry {
                fingerprint: fingerprint.clone(),
                rule_id: format!("rule_{}", i),
                path: format!("/path/{}", i),
                line: i as u32,
                note: None,
            })
            .collect();

        let mut baseline = FalsePositiveBaseline {
            schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
            entries,
        };

        normalize_false_positive_baseline(&mut baseline);

        // After dedup, should have exactly 1 entry
        prop_assert_eq!(
            baseline.entries.len(), 1,
            "Expected 1 entry after dedup of {} duplicates, got {}",
            count, baseline.entries.len()
        );

        // The fingerprint set should have exactly 1 element
        let fps = false_positive_fingerprint_set(&baseline);
        prop_assert_eq!(fps.len(), 1, "Should have exactly 1 fingerprint after dedup");
    }
}
