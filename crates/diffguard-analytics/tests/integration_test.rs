//! Integration tests for `diffguard-analytics` — testing component handoffs and workflows.
//!
//! These tests verify that the analytics functions work correctly together,
//! simulating real-world usage patterns where multiple components interact.

use diffguard_analytics::{
    FalsePositiveBaseline, FalsePositiveEntry, baseline_from_receipt,
    false_positive_fingerprint_set, fingerprint_for_finding, merge_false_positive_baselines,
    normalize_false_positive_baseline,
};
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};

// ============================================================================
// Helper: Build realistic CheckReceipt
// ============================================================================

fn make_receipt(rule_id: &str, path: &str, line: u32) -> CheckReceipt {
    CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 10,
            lines_scanned: 500,
        },
        findings: vec![Finding {
            rule_id: rule_id.to_string(),
            severity: Severity::Error,
            message: "test finding".to_string(),
            path: path.to_string(),
            line,
            column: Some(1),
            match_text: "test".to_string(),
            snippet: "test snippet".to_string(),
        }],
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

// ============================================================================
// Test: Component handoff — receipt -> baseline -> fingerprint_set
// ============================================================================

/// Verifies the complete pipeline: receipt → baseline → fingerprint_set.
///
/// This is the primary workflow for false-positive tracking:
/// 1. Run a check and get a receipt with findings
/// 2. Build a baseline from those findings
/// 3. Extract fingerprints for fast lookup
#[test]
fn integration_receipt_to_baseline_to_fingerprint_set() {
    let receipt = make_receipt("rust.no_unwrap", "src/lib.rs", 42);

    // Step 1: Build baseline from receipt
    let baseline = baseline_from_receipt(&receipt);
    assert_eq!(baseline.schema, "diffguard.false_positive_baseline.v1");
    assert_eq!(baseline.entries.len(), 1);
    assert_eq!(baseline.entries[0].rule_id, "rust.no_unwrap");
    assert_eq!(baseline.entries[0].path, "src/lib.rs");
    assert_eq!(baseline.entries[0].line, 42);

    // Step 2: Extract fingerprint set for fast lookup
    let fps = false_positive_fingerprint_set(&baseline);
    assert_eq!(fps.len(), 1);

    // Verify fingerprint is a valid SHA-256 hex string (64 chars)
    let fp = fps.iter().next().unwrap();
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

/// Verifies that fingerprint_for_finding produces fingerprints compatible
/// with what baseline_from_receipt extracts.
#[test]
fn integration_fingerprint_for_finding_matches_baseline_extraction() {
    let finding = Finding {
        rule_id: "rust.no_unwrap".to_string(),
        severity: Severity::Error,
        message: "no unwrap".to_string(),
        path: "src/lib.rs".to_string(),
        line: 12,
        column: Some(4),
        match_text: ".unwrap()".to_string(),
        snippet: "let x = y.unwrap();".to_string(),
    };

    // Compute fingerprint directly
    let direct_fp = fingerprint_for_finding(&finding);

    // Compute via baseline pipeline
    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 2,
        },
        findings: vec![finding],
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
    };
    let baseline = baseline_from_receipt(&receipt);
    let fps = false_positive_fingerprint_set(&baseline);

    // The fingerprint computed directly should match what's in the set
    assert_eq!(fps.len(), 1);
    let baseline_fp = fps.iter().next().unwrap();
    assert_eq!(&direct_fp, baseline_fp);
}

// ============================================================================
// Test: Component handoff — merge -> fingerprint_set
// ============================================================================

/// Verifies the merge pipeline: baseline1 + baseline2 → merged → fingerprint_set.
///
/// This tests the workflow where:
/// 1. User has an existing baseline (e.g., from last run)
/// 2. User has a new baseline (e.g., from current run)
/// 3. Merge to get combined baseline
/// 4. Extract fingerprints for checking new findings
#[test]
fn integration_merge_baselines_then_extract_fingerprints() {
    // Existing baseline: one known false positive
    let existing = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "existing_fp_abc123".to_string(),
            rule_id: "rust.no_unwrap".to_string(),
            path: "src/lib.rs".to_string(),
            line: 10,
            note: Some("Intentional: test helper".to_string()),
        }],
    };

    // New baseline: different false positive
    let incoming = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "incoming_fp_def456".to_string(),
            rule_id: "rust.no_expect".to_string(),
            path: "src/main.rs".to_string(),
            line: 20,
            note: None,
        }],
    };

    // Merge: union of fingerprints, preserving existing metadata
    let merged = merge_false_positive_baselines(&existing, &incoming);
    assert_eq!(merged.entries.len(), 2);

    // Extract fingerprints for fast lookup
    let fps = false_positive_fingerprint_set(&merged);
    assert_eq!(fps.len(), 2);
    assert!(fps.contains("existing_fp_abc123"));
    assert!(fps.contains("incoming_fp_def456"));
}

/// Verifies that merging with duplicate fingerprints deduplicates correctly.
#[test]
fn integration_merge_deduplicates_fingerprints() {
    let existing = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "shared_fp".to_string(),
            rule_id: "rust.no_unwrap".to_string(),
            path: "src/lib.rs".to_string(),
            line: 10,
            note: Some("Original note".to_string()),
        }],
    };

    let incoming = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "shared_fp".to_string(),
            rule_id: "rust.no_unwrap".to_string(),
            path: "src/lib.rs".to_string(),
            line: 10,
            note: None, // No note — should preserve existing
        }],
    };

    let merged = merge_false_positive_baselines(&existing, &incoming);
    assert_eq!(merged.entries.len(), 1); // Deduplicated
    assert_eq!(merged.entries[0].note.as_deref(), Some("Original note")); // Preserved

    let fps = false_positive_fingerprint_set(&merged);
    assert_eq!(fps.len(), 1);
}

// ============================================================================
// Test: Component handoff — normalize -> fingerprint_set
// ============================================================================

/// Verifies that normalize_false_positive_baseline + fingerprint_set works correctly.
///
/// Some workflows may normalize before extracting fingerprints.
#[test]
fn integration_normalize_then_extract_fingerprints() {
    // Baseline with empty schema (should be set by normalize)
    let baseline = FalsePositiveBaseline {
        schema: String::new(), // Empty — normalize should fix this
        entries: vec![FalsePositiveEntry {
            fingerprint: "fp1".to_string(),
            rule_id: "rule1".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: None,
        }],
    };

    let normalized = normalize_false_positive_baseline(baseline);
    assert_eq!(normalized.schema, "diffguard.false_positive_baseline.v1");

    let fps = false_positive_fingerprint_set(&normalized);
    assert_eq!(fps.len(), 1);
    assert!(fps.contains("fp1"));
}

// ============================================================================
// Test: False-positive lookup workflow
// ============================================================================

/// Simulates the false-positive checking workflow:
/// 1. Load known false positives into a fingerprint set
/// 2. For each new finding, check if its fingerprint is in the set
/// 3. Suppress findings that are known false positives
#[test]
fn integration_false_positive_lookup_workflow() {
    // Step 1: Build baseline of known false positives from historical data
    let historical_receipts = vec![
        make_receipt("rust.no_unwrap", "src/helper.rs", 5),
        make_receipt("rust.no_unwrap", "src/util.rs", 100),
        make_receipt("rust.no_expect", "src/main.rs", 50),
    ];

    let baselines: Vec<_> = historical_receipts
        .iter()
        .map(baseline_from_receipt)
        .collect();

    // Merge all baselines into one
    let mut combined = baselines[0].clone();
    for baseline in &baselines[1..] {
        combined = merge_false_positive_baselines(&combined, baseline);
    }

    // Step 2: Build fingerprint set for O(log n) lookup
    let known_fps = false_positive_fingerprint_set(&combined);
    assert_eq!(known_fps.len(), 3);

    // Step 3: Simulate checking a new finding
    // IMPORTANT: Must match the exact fingerprint computed from the receipt
    // The match_text in make_receipt is "test", so we must use the same
    let new_finding = Finding {
        rule_id: "rust.no_unwrap".to_string(),
        severity: Severity::Error,
        message: "no unwrap".to_string(),
        path: "src/helper.rs".to_string(),
        line: 5,
        column: Some(4),
        match_text: "test".to_string(), // Must match what make_receipt used
        snippet: "let x = y.unwrap();".to_string(),
    };

    let new_fp = fingerprint_for_finding(&new_finding);

    // Step 4: Check if this is a known false positive
    let is_known_false_positive = known_fps.contains(&new_fp);
    assert!(
        is_known_false_positive,
        "This unwrap in helper.rs is a known false positive"
    );

    // Now test a NEW finding that's NOT in the baseline
    let genuinely_new_finding = Finding {
        rule_id: "rust.no_unwrap".to_string(),
        severity: Severity::Error,
        message: "no unwrap".to_string(),
        path: "src/new_code.rs".to_string(),
        line: 99,
        column: Some(4),
        match_text: ".unwrap()".to_string(),
        snippet: "let x = y.unwrap();".to_string(),
    };

    let genuinely_new_fp = fingerprint_for_finding(&genuinely_new_finding);
    let is_known_fp_for_new = known_fps.contains(&genuinely_new_fp);
    assert!(
        !is_known_fp_for_new,
        "This is genuinely new, not a false positive"
    );
}

// ============================================================================
// Test: BTreeSet ordering is deterministic and sorted
// ============================================================================

/// Verifies that the fingerprint set maintains sorted order,
/// which is important for deterministic output and debugging.
#[test]
fn integration_fingerprint_set_is_sorted() {
    // Create baseline with fingerprints that sort non-alphabetically
    let baseline = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "zzz".to_string(),
                rule_id: "rule1".to_string(),
                path: "c.rs".to_string(),
                line: 3,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "aaa".to_string(),
                rule_id: "rule2".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "mmm".to_string(),
                rule_id: "rule3".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
        ],
    };

    let fps = false_positive_fingerprint_set(&baseline);

    // BTreeSet should iterate in sorted order
    let items: Vec<&String> = fps.iter().collect();
    assert_eq!(items[0], "aaa");
    assert_eq!(items[1], "mmm");
    assert_eq!(items[2], "zzz");

    // Also verify the into_iter() ordering is sorted
    let items_owned: Vec<String> = fps.into_iter().collect();
    assert_eq!(items_owned[0], "aaa");
    assert_eq!(items_owned[1], "mmm");
    assert_eq!(items_owned[2], "zzz");
}

// ============================================================================
// Test: Schema preservation through the pipeline
// ============================================================================

/// Verifies that schema metadata is preserved correctly through transformations.
#[test]
fn integration_schema_preserved_through_pipeline() {
    let receipt = make_receipt("test.rule", "test.rs", 1);

    // baseline_from_receipt should set schema
    let baseline = baseline_from_receipt(&receipt);
    assert_eq!(baseline.schema, "diffguard.false_positive_baseline.v1");

    // normalize should preserve schema
    let normalized = normalize_false_positive_baseline(baseline.clone());
    assert_eq!(normalized.schema, "diffguard.false_positive_baseline.v1");

    // merge should preserve schema
    let merged = merge_false_positive_baselines(&baseline, &normalized);
    assert_eq!(merged.schema, "diffguard.false_positive_baseline.v1");

    // fingerprint_set doesn't use schema, but verify baseline still intact
    let fps = false_positive_fingerprint_set(&merged);
    assert_eq!(fps.len(), 1);
}

// ============================================================================
// Test: Multiple findings with same fingerprint are deduplicated
// ============================================================================

/// Verifies that findings with identical fingerprints are correctly deduplicated
/// when building fingerprint sets. This is crucial for baseline size management.
#[test]
fn integration_deduplicates_findings_with_same_fingerprint() {
    // Create a receipt with multiple findings that produce the same fingerprint
    // (same rule_id, path, line, match_text)
    let receipt = CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 2,
        },
        findings: vec![
            Finding {
                rule_id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "no unwrap".to_string(),
                path: "src/lib.rs".to_string(),
                line: 12,
                column: Some(4),
                match_text: ".unwrap()".to_string(),
                snippet: "let x = y.unwrap();".to_string(),
            },
            // Same finding repeated (e.g., from different context lines)
            Finding {
                rule_id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "no unwrap".to_string(),
                path: "src/lib.rs".to_string(),
                line: 12,
                column: Some(4),
                match_text: ".unwrap()".to_string(),
                snippet: "let x = y.unwrap();".to_string(),
            },
        ],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 2,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    };

    let baseline = baseline_from_receipt(&receipt);
    // Should deduplicate to 1 entry
    assert_eq!(baseline.entries.len(), 1);

    let fps = false_positive_fingerprint_set(&baseline);
    assert_eq!(fps.len(), 1);
}

// ============================================================================
// Test: Empty and edge case workflows
// ============================================================================

/// Verifies that empty baseline workflows work correctly.
#[test]
fn integration_empty_baseline_workflow() {
    let empty_baseline = FalsePositiveBaseline::default();
    let fps = false_positive_fingerprint_set(&empty_baseline);

    assert!(fps.is_empty());

    // Merging with empty should preserve the other side
    let non_empty = baseline_from_receipt(&make_receipt("rule", "file.rs", 1));
    let merged = merge_false_positive_baselines(&empty_baseline, &non_empty);
    assert_eq!(merged.entries.len(), 1);

    let merged_fps = false_positive_fingerprint_set(&merged);
    assert_eq!(merged_fps.len(), 1);
}

/// Verifies that fingerprint sets are efficiently queryable with BTreeSet.
#[test]
fn integration_btreeset_lookup_performance() {
    // Build a baseline with many entries
    let entries: Vec<FalsePositiveEntry> = (0..1000)
        .map(|i| FalsePositiveEntry {
            fingerprint: format!("fp_{:08}", i),
            rule_id: format!("rule_{}", i % 10),
            path: format!("src_{}.rs", i % 100),
            line: i,
            note: None,
        })
        .collect();

    let baseline = FalsePositiveBaseline {
        schema: "diffguard.false_positive_baseline.v1".to_string(),
        entries,
    };

    let fps = false_positive_fingerprint_set(&baseline);
    assert_eq!(fps.len(), 1000);

    // BTreeSet provides O(log n) lookup
    // We can't easily test exact timing, but we can verify the lookup succeeds
    assert!(fps.contains("fp_00000500"));
    assert!(fps.contains("fp_00000999"));
    assert!(!fps.contains("fp_00001000")); // Doesn't exist
    assert!(!fps.contains("fp_not_there"));
}
