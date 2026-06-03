//! Red tests for the `normalize_false_positive_baseline` refactor.
//!
//! ## What these tests verify
//!
//! These tests verify that `normalize_false_positive_baseline` has been refactored
//! to take `&mut FalsePositiveBaseline` (instead of owned `FalsePositiveBaseline`)
//! and return `()` (instead of identity-returning `FalsePositiveBaseline`).
//!
//! ## Expected behavior
//!
//! **BEFORE the refactor:** These tests FAIL TO COMPILE because the function
//! signature is `fn normalize_false_positive_baseline(mut baseline: FalsePositiveBaseline) -> FalsePositiveBaseline`.
//! The call `normalize_false_positive_baseline(&mut baseline)` produces a type mismatch error.
//!
//! **AFTER the refactor:** These tests COMPILE and PASS because the function
//! signature is `fn normalize_false_positive_baseline(baseline: &mut FalsePositiveBaseline)`.
//! The call `normalize_false_positive_baseline(&mut baseline)` is valid and
//! the normalization behavior (sort, dedup, schema set) is preserved.
//!
//! ## Acceptance criteria covered
//!
//! - **AC-2:** Function signature changed to `&mut` — verified by successful compilation
//! - **AC-3:** `#[must_use]` removed — the function returns `()` so no unused return value warning
//! - **AC-4:** Functional behavior unchanged — normalization (schema set, sort, dedup) verified

use diffguard_analytics::{
    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    normalize_false_positive_baseline,
};

/// Test that `normalize_false_positive_baseline` accepts `&mut FalsePositiveBaseline`.
///
/// This test will FAIL TO COMPILE before the refactor because the function takes
/// owned `FalsePositiveBaseline`, not `&mut FalsePositiveBaseline`.
#[test]
fn test_normalize_accepts_mut_reference() {
    let mut baseline = FalsePositiveBaseline::default();
    baseline.schema = String::new(); // empty schema
    baseline.entries.push(FalsePositiveEntry {
        fingerprint: "aaa".to_string(),
        rule_id: "rule.one".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    // Call with &mut — this is the new API after the refactor.
    // Before the refactor: type error — expected `FalsePositiveBaseline`, got `&mut FalsePositiveBaseline`
    // After the refactor: compiles correctly
    normalize_false_positive_baseline(&mut baseline);

    // If we get here, the function accepted &mut and returned () — refactor succeeded.
    // Verify normalization still worked (schema was set, entries were processed).
    assert_eq!(baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
}

/// Test that `normalize_false_positive_baseline` returns `()` (no return value).
///
/// This test verifies the `#[must_use]` attribute has been removed by checking
/// the function returns `()` after the refactor.
#[test]
fn test_normalize_returns_unit() {
    let mut baseline = FalsePositiveBaseline::default();
    baseline.entries.push(FalsePositiveEntry {
        fingerprint: "bbb".to_string(),
        rule_id: "rule.two".to_string(),
        path: "b.rs".to_string(),
        line: 2,
        note: None,
    });

    // The return value should be `()` — assignment to a variable of type `()` is valid.
    // Before refactor: `let result: FalsePositiveBaseline = normalize_false_positive_baseline(...)` would work
    // After refactor: `let result: () = normalize_false_positive_baseline(...)` is the correct type
    let result: () = normalize_false_positive_baseline(&mut baseline);
    // If this compiles, the return type is `()` — the `#[must_use]` attribute is gone.
    assert_eq!(result, ());
}

/// Test that normalization correctly sets empty schema to V1.
#[test]
fn test_normalize_sets_schema_when_empty() {
    let mut baseline = FalsePositiveBaseline {
        schema: String::new(), // empty
        entries: vec![],
    };

    normalize_false_positive_baseline(&mut baseline);

    assert_eq!(
        baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1,
        "empty schema should be set to V1"
    );
}

/// Test that normalization correctly sorts entries by fingerprint.
#[test]
fn test_normalize_sorts_entries_by_fingerprint() {
    let mut baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "ccc".to_string(),
                rule_id: "rule".to_string(),
                path: "c.rs".to_string(),
                line: 3,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "aaa".to_string(),
                rule_id: "rule".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "bbb".to_string(),
                rule_id: "rule".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
        ],
    };

    normalize_false_positive_baseline(&mut baseline);

    // After sorting by fingerprint: aaa < bbb < ccc
    assert_eq!(baseline.entries[0].fingerprint, "aaa");
    assert_eq!(baseline.entries[1].fingerprint, "bbb");
    assert_eq!(baseline.entries[2].fingerprint, "ccc");
}

/// Test that normalization correctly deduplicates entries by fingerprint.
#[test]
fn test_normalize_deduplicates_by_fingerprint() {
    let mut baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "aaa".to_string(),
                rule_id: "rule.one".to_string(),
                path: "a.rs".to_string(),
                line: 10,
                note: Some("first note".to_string()),
            },
            // Duplicate fingerprint — should be removed
            FalsePositiveEntry {
                fingerprint: "aaa".to_string(),
                rule_id: "rule.two".to_string(),
                path: "b.rs".to_string(),
                line: 20,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "bbb".to_string(),
                rule_id: "rule.three".to_string(),
                path: "c.rs".to_string(),
                line: 30,
                note: None,
            },
        ],
    };

    normalize_false_positive_baseline(&mut baseline);

    assert_eq!(
        baseline.entries.len(),
        2,
        "duplicate fingerprint 'aaa' should be deduplicated"
    );
    assert_eq!(baseline.entries[0].fingerprint, "aaa");
    assert_eq!(baseline.entries[1].fingerprint, "bbb");
}

/// Test that normalization handles already-normal baseline (no-op).
#[test]
fn test_normalize_idempotent() {
    let mut baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "aaa".to_string(),
            rule_id: "rule".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: None,
        }],
    };

    // Run normalization twice — should be idempotent
    normalize_false_positive_baseline(&mut baseline);
    let first_result = baseline.clone();
    normalize_false_positive_baseline(&mut baseline);

    assert_eq!(baseline, first_result, "normalization should be idempotent");
}
