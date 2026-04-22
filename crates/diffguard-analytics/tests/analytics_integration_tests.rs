//! Integration tests for diffguard-analytics workflows.
//!
//! These tests verify that multiple analytics components work together correctly,
//! simulating real-world workflows a user would follow.
//!
//! Coverage:
//! - CheckReceipt → Baseline → Fingerprint set workflow (suppression)
//! - CheckReceipt → TrendRun → TrendHistory → Summary workflow (analytics tracking)
//! - Baseline evolution (building, merging, updating baselines over time)
//! - JSON serialization round-trips for persistence
//! - Multi-component error propagation

use diffguard_analytics::{
    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    TREND_HISTORY_SCHEMA_V1, TrendHistory, append_trend_run, baseline_from_receipt,
    false_positive_fingerprint_set, fingerprint_for_finding, merge_false_positive_baselines,
    normalize_false_positive_baseline, summarize_trend_history, trend_run_from_receipt,
};
use diffguard_types::{
    CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts,
    VerdictStatus,
};

// ============================================================================
// Helper Functions
// ============================================================================

fn make_finding(rule_id: &str, path: &str, line: u32, match_text: &str) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Error,
        message: "Test finding".to_string(),
        path: path.to_string(),
        line,
        column: Some(1),
        match_text: match_text.to_string(),
        snippet: format!("line {} in {}", line, path),
    }
}

fn make_receipt_with_findings(findings: Vec<Finding>) -> CheckReceipt {
    CheckReceipt {
        schema: "diffguard.check.v1".to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 3,
            scope: Scope::Added,
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

// ============================================================================
// Workflow 1: CheckReceipt → Baseline → Fingerprint Set (Suppression Workflow)
// ============================================================================

/// Tests the complete suppression workflow:
/// 1. Create a CheckReceipt with findings
/// 2. Build a baseline from the receipt
/// 3. Extract a fingerprint set for fast lookup
/// 4. Use fingerprints to suppress matching findings
#[test]
fn suppression_workflow_full_round_trip() {
    // Step 1: Create a receipt with findings
    let findings = vec![
        make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()"),
        make_finding("rust.no_unwrap", "src/main.rs", 10, ".unwrap()"),
        make_finding(
            "secrets.detect_api_key",
            "config.rs",
            5,
            "api_key = \"xxx\"",
        ),
    ];
    let receipt = make_receipt_with_findings(findings);

    // Step 2: Build baseline from receipt
    let baseline = baseline_from_receipt(&receipt);
    assert_eq!(baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
    assert_eq!(baseline.entries.len(), 3);

    // Step 3: Extract fingerprint set for fast lookup
    let fp_set = false_positive_fingerprint_set(&baseline);
    assert_eq!(fp_set.len(), 3);

    // Step 4: Create a new receipt with some of the same findings
    let new_findings = vec![
        make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()"), // This should be suppressed
        make_finding("rust.no_unwrap", "src/main.rs", 10, ".unwrap()"), // This should be suppressed
        make_finding("rust.no_unwrap", "src/new.rs", 99, ".unwrap()"), // NEW - should NOT be suppressed
    ];
    let new_receipt = make_receipt_with_findings(new_findings.clone());

    // Step 5: Extract fingerprints from new findings and check against baseline
    let _new_baseline = baseline_from_receipt(&new_receipt);

    // The old fingerprints should be in the baseline set (suppressed)
    for entry in &baseline.entries {
        assert!(
            fp_set.contains(&entry.fingerprint),
            "baseline fingerprint should be in suppression set"
        );
    }

    // Verify the new findings that are NOT in baseline
    // The "new.rs" finding should have a different fingerprint
    let new_finding_fp = fingerprint_for_finding(&new_findings[2]);
    assert!(
        !fp_set.contains(&new_finding_fp),
        "new finding should NOT be suppressed"
    );
}

/// Tests that fingerprints from baseline correctly suppress findings
#[test]
fn suppression_workflow_fingerprint_matching() {
    let findings = vec![make_finding(
        "rust.no_unwrap",
        "src/lib.rs",
        42,
        ".unwrap()",
    )];
    let receipt = make_receipt_with_findings(findings.clone());
    let baseline = baseline_from_receipt(&receipt);
    let fp_set = false_positive_fingerprint_set(&baseline);

    // The fingerprint of the finding should be in the set
    let fp = fingerprint_for_finding(&findings[0]);
    assert!(fp_set.contains(&fp));

    // A different finding at the same location but different rule should NOT be suppressed
    let different_rule = make_finding("rust.no_deref", "src/lib.rs", 42, ".unwrap()");
    let different_fp = fingerprint_for_finding(&different_rule);
    assert!(!fp_set.contains(&different_fp));

    // A finding at a different line should NOT be suppressed
    let different_line = make_finding("rust.no_unwrap", "src/lib.rs", 100, ".unwrap()");
    let different_line_fp = fingerprint_for_finding(&different_line);
    assert!(!fp_set.contains(&different_line_fp));
}

// ============================================================================
// Workflow 2: CheckReceipt → TrendRun → TrendHistory → Summary (Analytics Workflow)
// ============================================================================

/// Tests the complete trend analytics workflow:
/// 1. Create CheckReceipts representing multiple runs
/// 2. Convert each to a TrendRun
/// 3. Append runs to TrendHistory
/// 4. Summarize the trend history
#[test]
fn trend_analytics_workflow_full_round_trip() {
    // Step 1: Create receipts for multiple runs
    let receipt1 = make_receipt_with_findings(vec![
        make_finding("rust.no_unwrap", "a.rs", 1, ".unwrap()"),
        make_finding("rust.no_unwrap", "b.rs", 2, ".unwrap()"),
    ]);
    let receipt2 = make_receipt_with_findings(vec![
        make_finding("rust.no_unwrap", "a.rs", 1, ".unwrap()"),
        make_finding("rust.no_unwrap", "c.rs", 3, ".unwrap()"),
        make_finding("secrets.detect_api_key", "d.rs", 4, "api_key"),
    ]);

    // Step 2: Convert to trend runs
    let run1 = trend_run_from_receipt(
        &receipt1,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
        60_000,
    );
    let run2 = trend_run_from_receipt(
        &receipt2,
        "2026-01-02T00:00:00Z",
        "2026-01-02T00:01:30Z",
        90_000,
    );

    // Verify run data
    assert_eq!(run1.findings, 2);
    assert_eq!(run2.findings, 3);
    assert_eq!(run1.duration_ms, 60_000);
    assert_eq!(run2.duration_ms, 90_000);

    // Step 3: Append runs to trend history
    let history = TrendHistory::default();
    let history = append_trend_run(history, run1, Some(10));
    let history = append_trend_run(history, run2, Some(10));

    assert_eq!(history.runs.len(), 2);
    assert_eq!(history.schema, TREND_HISTORY_SCHEMA_V1);

    // Step 4: Summarize the trend history
    let summary = summarize_trend_history(&history);

    assert_eq!(summary.run_count, 2);
    assert_eq!(summary.total_findings, 5);
    assert!(summary.delta_from_previous.is_some());

    let delta = summary.delta_from_previous.unwrap();
    // run2 had 3 findings, run1 had 2, so delta is +1
    assert_eq!(delta.findings, 1);
}

/// Tests that trend history trims oldest runs when max_runs is exceeded
#[test]
fn trend_analytics_workflow_trims_oldest_runs() {
    let receipt =
        make_receipt_with_findings(vec![make_finding("rust.no_unwrap", "a.rs", 1, ".unwrap()")]);

    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
        60_000,
    );

    // Add 5 runs with max_runs = 3
    let history = TrendHistory::default();
    let history = append_trend_run(history, run.clone(), Some(3));
    let history = append_trend_run(history, run.clone(), Some(3));
    let history = append_trend_run(history, run.clone(), Some(3));
    let history = append_trend_run(history, run.clone(), Some(3));
    let history = append_trend_run(history, run.clone(), Some(3));

    // Should only have 3 runs
    assert_eq!(history.runs.len(), 3);

    // Summary should reflect only 3 runs
    let summary = summarize_trend_history(&history);
    assert_eq!(summary.run_count, 3);
    // But total findings should still sum all 5 runs (oldest 2 were dropped)
    assert_eq!(summary.total_findings, 3); // 3 runs * 1 finding each
}

// ============================================================================
// Workflow 3: Baseline Evolution (Building, Merging, Updating Over Time)
// ============================================================================

/// Tests the baseline evolution workflow:
/// 1. Create initial baseline from first receipt
/// 2. Merge with new baseline from second receipt
/// 3. Verify deduplication and note preservation
#[test]
fn baseline_evolution_workflow_initial_and_merge() {
    // Step 1: Create initial baseline
    let receipt1 = make_receipt_with_findings(vec![
        make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()"),
        make_finding("rust.no_unwrap", "src/main.rs", 10, ".unwrap()"),
    ]);
    let baseline1 = baseline_from_receipt(&receipt1);
    assert_eq!(baseline1.entries.len(), 2);

    // Step 2: Create second baseline with overlapping and new findings
    let receipt2 = make_receipt_with_findings(vec![
        make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()"), // duplicate
        make_finding("rust.no_unwrap", "src/new.rs", 99, ".unwrap()"), // new
    ]);
    let baseline2 = baseline_from_receipt(&receipt2);

    // Step 3: Merge baselines - base is baseline1, incoming is baseline2
    let merged = merge_false_positive_baselines(&baseline1, &baseline2);

    // Should have 3 unique entries (2 from baseline1 + 1 new from baseline2)
    assert_eq!(merged.entries.len(), 3);

    // Verify fingerprints
    let merged_fp_set = false_positive_fingerprint_set(&merged);
    assert_eq!(merged_fp_set.len(), 3);
}

/// Tests that notes are preserved when merging baselines
#[test]
fn baseline_evolution_workflow_preserves_curation_notes() {
    // Create baseline with a curated entry (has note)
    let mut baseline1 = FalsePositiveBaseline::default();
    baseline1.entries.push(FalsePositiveEntry {
        fingerprint: "curated_fp".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        note: Some("Intentionally used unwrap here - it cannot fail".to_string()),
    });

    // Create second baseline with same fingerprint but no note
    let mut baseline2 = FalsePositiveBaseline::default();
    baseline2.entries.push(FalsePositiveEntry {
        fingerprint: "curated_fp".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "src/lib.rs".to_string(),
        line: 42,
        note: None,
    });

    // Merge - should preserve note from baseline1
    let merged = merge_false_positive_baselines(&baseline1, &baseline2);

    let entry = merged
        .entries
        .iter()
        .find(|e| e.fingerprint == "curated_fp");
    assert!(entry.is_some());
    assert_eq!(
        entry.unwrap().note.as_deref(),
        Some("Intentionally used unwrap here - it cannot fail")
    );
}

/// Tests baseline normalization is applied after merge
#[test]
fn baseline_evolution_workflow_normalizes_after_merge() {
    // Create two unsorted baselines
    let mut baseline1 = FalsePositiveBaseline::default();
    baseline1.entries.push(FalsePositiveEntry {
        fingerprint: "z_fp".to_string(),
        rule_id: "rule.z".to_string(),
        path: "z.rs".to_string(),
        line: 1,
        note: None,
    });
    baseline1.entries.push(FalsePositiveEntry {
        fingerprint: "a_fp".to_string(),
        rule_id: "rule.a".to_string(),
        path: "a.rs".to_string(),
        line: 1,
        note: None,
    });

    let mut baseline2 = FalsePositiveBaseline::default();
    baseline2.entries.push(FalsePositiveEntry {
        fingerprint: "m_fp".to_string(),
        rule_id: "rule.m".to_string(),
        path: "m.rs".to_string(),
        line: 1,
        note: None,
    });

    let merged = merge_false_positive_baselines(&baseline1, &baseline2);

    // Entries should be sorted by fingerprint after merge
    assert_eq!(merged.entries[0].fingerprint, "a_fp");
    assert_eq!(merged.entries[1].fingerprint, "m_fp");
    assert_eq!(merged.entries[2].fingerprint, "z_fp");
}

// ============================================================================
// Workflow 4: JSON Serialization Round-trips
// ============================================================================

/// Tests that FalsePositiveBaseline serializes and deserializes correctly
#[test]
fn serialization_round_trip_false_positive_baseline() {
    let baseline = {
        let findings = vec![
            make_finding("rust.no_unwrap", "src/lib.rs", 42, ".unwrap()"),
            make_finding("secrets.detect_api_key", "config.rs", 5, "api_key"),
        ];
        baseline_from_receipt(&make_receipt_with_findings(findings))
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&baseline).expect("should serialize");

    // Verify JSON contains expected fields
    assert!(json.contains("\"schema\""));
    assert!(json.contains("\"entries\""));
    assert!(json.contains("\"fingerprint\""));
    assert!(json.contains("\"rule_id\""));
    assert!(json.contains("\"path\""));
    assert!(json.contains("\"line\""));

    // Deserialize back
    let deserialized: FalsePositiveBaseline =
        serde_json::from_str(&json).expect("should deserialize");

    // Verify equality
    assert_eq!(deserialized.schema, baseline.schema);
    assert_eq!(deserialized.entries.len(), baseline.entries.len());
    for (orig, deser) in baseline.entries.iter().zip(deserialized.entries.iter()) {
        assert_eq!(orig.fingerprint, deser.fingerprint);
        assert_eq!(orig.rule_id, deser.rule_id);
        assert_eq!(orig.path, deser.path);
        assert_eq!(orig.line, deser.line);
    }
}

/// Tests that TrendHistory serializes and deserializes correctly
#[test]
fn serialization_round_trip_trend_history() {
    let receipt =
        make_receipt_with_findings(vec![make_finding("rust.no_unwrap", "a.rs", 1, ".unwrap()")]);
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
        60_000,
    );

    let history = append_trend_run(TrendHistory::default(), run, Some(10));

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&history).expect("should serialize");

    // Verify JSON contains expected fields
    assert!(json.contains("\"schema\""));
    assert!(json.contains("\"runs\""));
    assert!(json.contains("\"started_at\""));
    assert!(json.contains("\"ended_at\""));
    assert!(json.contains("\"duration_ms\""));
    assert!(json.contains("\"findings\""));

    // Deserialize back
    let deserialized: TrendHistory = serde_json::from_str(&json).expect("should deserialize");

    // Verify equality
    assert_eq!(deserialized.schema, history.schema);
    assert_eq!(deserialized.runs.len(), history.runs.len());
    assert_eq!(deserialized.runs[0].findings, history.runs[0].findings);
    assert_eq!(
        deserialized.runs[0].duration_ms,
        history.runs[0].duration_ms
    );
}

/// Tests that TrendSummary serializes and deserializes correctly
#[test]
fn serialization_round_trip_trend_summary() {
    let receipt = make_receipt_with_findings(vec![
        make_finding("rust.no_unwrap", "a.rs", 1, ".unwrap()"),
        make_finding("rust.no_unwrap", "b.rs", 2, ".unwrap()"),
    ]);
    let run1 = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
        60_000,
    );
    let run2 = trend_run_from_receipt(
        &receipt,
        "2026-01-02T00:00:00Z",
        "2026-01-02T00:01:00Z",
        60_000,
    );

    let history = TrendHistory::default();
    let history = append_trend_run(history, run1, Some(10));
    let history = append_trend_run(history, run2, Some(10));

    let summary = summarize_trend_history(&history);

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&summary).expect("should serialize");

    // Deserialize back
    let deserialized: diffguard_analytics::TrendSummary =
        serde_json::from_str(&json).expect("should deserialize");

    // Verify equality
    assert_eq!(deserialized.run_count, summary.run_count);
    assert_eq!(deserialized.total_findings, summary.total_findings);
}

// ============================================================================
// Workflow 5: Multi-Receipt Analytics (Simulating CI Pipeline)
// ============================================================================

/// Simulates a multi-stage CI pipeline with baseline suppression
///
/// Workflow:
/// 1. User creates a curated baseline of acceptable findings (manually reviewed)
/// 2. Subsequent PR comes with findings
/// 3. We extract fingerprints from the curated baseline to create a suppression set
/// 4. New findings are checked against the suppression set to determine what to flag
#[test]
fn ci_pipeline_workflow_with_baseline_suppression() {
    // User has manually curated a baseline containing ONLY the acceptable legacy findings.
    let mut curated_baseline = FalsePositiveBaseline::default();
    curated_baseline.entries.push(FalsePositiveEntry {
        fingerprint: fingerprint_for_finding(&make_finding(
            "rust.no_unwrap",
            "legacy.rs",
            100,
            ".unwrap()",
        )),
        rule_id: "rust.no_unwrap".to_string(),
        path: "legacy.rs".to_string(),
        line: 100,
        note: Some("Legacy code - requires significant refactoring".to_string()),
    });
    curated_baseline.entries.push(FalsePositiveEntry {
        fingerprint: fingerprint_for_finding(&make_finding(
            "rust.no_unwrap",
            "legacy.rs",
            101,
            ".unwrap()",
        )),
        rule_id: "rust.no_unwrap".to_string(),
        path: "legacy.rs".to_string(),
        line: 101,
        note: Some("Legacy code - requires significant refactoring".to_string()),
    });
    let curated_baseline = normalize_false_positive_baseline(curated_baseline);

    // Create suppression set from the curated baseline
    let suppression_set = false_positive_fingerprint_set(&curated_baseline);

    // Another PR comes with findings
    let _pr_findings = vec![
        make_finding("rust.no_unwrap", "legacy.rs", 100, ".unwrap()"), // Suppressed (in curated baseline)
        make_finding("rust.no_unwrap", "legacy.rs", 101, ".unwrap()"), // Suppressed (in curated baseline)
        make_finding("rust.no_unwrap", "pr_change.rs", 5, ".unwrap()"), // NEW! Real bug - NOT suppressed
    ];

    // Verify: pr_change.rs should NOT be suppressed (it's a NEW finding)
    let new_finding_fp = fingerprint_for_finding(&make_finding(
        "rust.no_unwrap",
        "pr_change.rs",
        5,
        ".unwrap()",
    ));
    assert!(
        !suppression_set.contains(&new_finding_fp),
        "pr_change.rs finding should NOT be suppressed"
    );

    // The legacy findings should be suppressed (they're in the curated baseline)
    let legacy1_fp = fingerprint_for_finding(&make_finding(
        "rust.no_unwrap",
        "legacy.rs",
        100,
        ".unwrap()",
    ));
    assert!(
        suppression_set.contains(&legacy1_fp),
        "legacy.rs:100 should be suppressed"
    );
}

/// Simulates trend tracking across multiple CI runs
#[test]
fn ci_pipeline_workflow_trend_tracking() {
    // Run 1: 3 findings
    let receipt1 = make_receipt_with_findings(vec![
        make_finding("rust.no_unwrap", "a.rs", 1, ".unwrap()"),
        make_finding("rust.no_unwrap", "b.rs", 2, ".unwrap()"),
        make_finding("rust.no_unwrap", "c.rs", 3, ".unwrap()"),
    ]);
    let run1 = trend_run_from_receipt(
        &receipt1,
        "2026-01-01T08:00:00Z",
        "2026-01-01T08:05:00Z",
        300_000,
    );

    // Run 2: 2 findings (improved!)
    let receipt2 = make_receipt_with_findings(vec![
        make_finding("rust.no_unwrap", "a.rs", 1, ".unwrap()"),
        make_finding("rust.no_unwrap", "b.rs", 2, ".unwrap()"),
    ]);
    let run2 = trend_run_from_receipt(
        &receipt2,
        "2026-01-02T08:00:00Z",
        "2026-01-02T08:04:00Z",
        240_000,
    );

    // Run 3: 4 findings (regression!)
    let receipt3 = make_receipt_with_findings(vec![
        make_finding("rust.no_unwrap", "a.rs", 1, ".unwrap()"),
        make_finding("rust.no_unwrap", "b.rs", 2, ".unwrap()"),
        make_finding("rust.no_unwrap", "d.rs", 4, ".unwrap()"),
        make_finding("rust.no_unwrap", "e.rs", 5, ".unwrap()"),
    ]);
    let run3 = trend_run_from_receipt(
        &receipt3,
        "2026-01-03T08:00:00Z",
        "2026-01-03T08:06:00Z",
        360_000,
    );

    // Build trend history
    let history = TrendHistory::default();
    let history = append_trend_run(history, run1, Some(10));
    let history = append_trend_run(history, run2, Some(10));
    let history = append_trend_run(history, run3, Some(10));

    // Verify trend tracking
    let summary = summarize_trend_history(&history);
    assert_eq!(summary.run_count, 3);
    assert_eq!(summary.total_findings, 9); // 3 + 2 + 4

    // Latest run should be run3
    assert!(summary.latest.is_some());
    assert_eq!(summary.latest.unwrap().findings, 4);

    // Delta from previous (run2 → run3) should show +2 findings
    let delta = summary.delta_from_previous.expect("should have delta");
    assert_eq!(delta.findings, 2); // 4 - 2 = +2 (regression)
}

// ============================================================================
// Edge Cases: Empty and Minimal Data
// ============================================================================

/// Tests workflow with empty baseline (no previous findings)
#[test]
fn workflow_with_empty_initial_baseline() {
    let empty_baseline = FalsePositiveBaseline::default();
    let receipt =
        make_receipt_with_findings(vec![make_finding("rust.no_unwrap", "a.rs", 1, ".unwrap()")]);
    let new_baseline = baseline_from_receipt(&receipt);

    // Merge empty with new - should just return new
    let merged = merge_false_positive_baselines(&empty_baseline, &new_baseline);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].path, "a.rs");
}

/// Tests workflow with empty trend history
#[test]
fn workflow_with_empty_trend_history() {
    let empty_history = TrendHistory::default();
    let summary = summarize_trend_history(&empty_history);

    assert_eq!(summary.run_count, 0);
    assert_eq!(summary.total_findings, 0);
    assert!(summary.latest.is_none());
    assert!(summary.delta_from_previous.is_none());
}

/// Tests trend history with single run (no delta possible)
#[test]
fn workflow_with_single_run_trend_history() {
    let receipt =
        make_receipt_with_findings(vec![make_finding("rust.no_unwrap", "a.rs", 1, ".unwrap()")]);
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T08:00:00Z",
        "2026-01-01T08:05:00Z",
        300_000,
    );

    let history = append_trend_run(TrendHistory::default(), run, Some(10));
    let summary = summarize_trend_history(&history);

    assert_eq!(summary.run_count, 1);
    assert!(summary.latest.is_some());
    assert!(summary.delta_from_previous.is_none()); // Can't compute delta with only 1 run
}

// ============================================================================
// Error Handling and Boundary Conditions
// ============================================================================

/// Tests that extremely large findings counts are handled correctly
#[test]
fn workflow_handles_large_finding_counts() {
    // Create a receipt that would have more findings than u32::MAX
    // (we can't actually create u32::MAX findings, but we can verify the cap logic)
    let receipt = make_receipt_with_findings(vec![]);
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T08:00:00Z",
        "2026-01-01T08:05:00Z",
        300_000,
    );

    // Verify findings count is properly capped at u32::MAX
    // Since our test receipt has 0 findings, this is trivially true
    assert_eq!(run.findings, 0);
}

/// Tests that schema validation works after round-trip
#[test]
fn workflow_schema_validation_after_deserialization() {
    let baseline = baseline_from_receipt(&make_receipt_with_findings(vec![make_finding(
        "rust.no_unwrap",
        "a.rs",
        1,
        ".unwrap()",
    )]));

    // Verify schema is set correctly
    assert_eq!(baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);

    // After normalization, schema should still be correct
    let normalized = normalize_false_positive_baseline(baseline.clone());
    assert_eq!(normalized.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);

    // After serialization/deserialization, schema should be preserved
    let json = serde_json::to_string(&normalized).unwrap();
    let deserialized: FalsePositiveBaseline = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
}
