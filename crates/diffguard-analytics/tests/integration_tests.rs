//! Integration tests for diffguard-analytics — verifies component handoffs and full workflows.
//!
//! These tests exercise the seams between public functions:
//! - CheckReceipt → Finding fingerprint → FalsePositiveBaseline
//! - CheckReceipt → TrendRun → TrendHistory → TrendSummary
//! - Baseline merge → fingerprint set → fast lookup

use diffguard_analytics::{
    FalsePositiveBaseline, FalsePositiveEntry, TREND_HISTORY_SCHEMA_V1, TrendHistory, TrendRun,
    TrendSummary, append_trend_run, baseline_from_receipt, false_positive_fingerprint_set,
    merge_false_positive_baselines, normalize_false_positive_baseline, normalize_trend_history,
    summarize_trend_history, trend_run_from_receipt,
};
use diffguard_types::{
    CheckReceipt, DiffMeta, Finding, Severity, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
};

/// Builds a CheckReceipt with the given findings for testing.
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
            files_scanned: 42,
            lines_scanned: 1337,
        },
        findings,
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 1,
                warn: 2,
                error: 3,
                suppressed: 4,
            },
            reasons: vec![],
        },
        timing: None,
    }
}

/// Builds a simple Finding for testing.
fn make_finding(rule_id: &str, path: &str, line: u32) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Error,
        message: "test finding".to_string(),
        path: path.to_string(),
        line,
        column: Some(1),
        match_text: "test".to_string(),
        snippet: "test line".to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Workflow: CheckReceipt → Baseline → Fingerprint Set
// ─────────────────────────────────────────────────────────────────────────────

/// Full false-positive tracking workflow:
/// 1. Create CheckReceipt with findings
/// 2. Convert to baseline via baseline_from_receipt
/// 3. Merge with an existing baseline
/// 4. Build fingerprint set for fast lookup
/// 5. Verify lookup succeeds
#[test]
fn test_full_baseline_workflow() {
    // Step 1: Create a receipt with findings
    let findings = vec![
        make_finding("rust.no_unwrap", "src/lib.rs", 10),
        make_finding("rust.no_unwrap", "src/main.rs", 20),
        make_finding("rust.no_vec_push", "src/utils.rs", 30),
    ];
    let receipt = make_receipt(findings);

    // Step 2: Convert receipt to baseline
    let baseline = baseline_from_receipt(&receipt);
    assert_eq!(baseline.entries.len(), 3);
    assert!(!baseline.schema.is_empty());

    // Step 3: Merge with an empty baseline (should preserve all entries)
    let empty_baseline = FalsePositiveBaseline::default();
    let merged = merge_false_positive_baselines(&empty_baseline, &baseline);
    assert_eq!(merged.entries.len(), 3);

    // Step 4: Build fingerprint set
    let fp_set = false_positive_fingerprint_set(&merged);
    assert_eq!(fp_set.len(), 3);

    // Step 5: Verify fingerprint lookup works (all fingerprints should be in set)
    for entry in &merged.entries {
        assert!(
            fp_set.contains(&entry.fingerprint),
            "fingerprint {} should be in set",
            entry.fingerprint
        );
    }
}

/// Tests that baseline_from_receipt normalizes entries deterministically.
/// Two identical receipts should produce identical baselines.
#[test]
fn test_baseline_determinism() {
    let findings = vec![
        make_finding("rust.no_unwrap", "src/lib.rs", 10),
        make_finding("rust.no_unwrap", "src/main.rs", 20),
    ];
    let receipt = make_receipt(findings);

    let baseline_a = baseline_from_receipt(&receipt);
    let baseline_b = baseline_from_receipt(&receipt);

    assert_eq!(baseline_a, baseline_b);
    assert_eq!(baseline_a.schema, baseline_b.schema);
    assert_eq!(baseline_a.entries.len(), baseline_b.entries.len());
}

/// Tests mergeFalsePositiveBaselines fills empty fields from base into incoming.
///
/// The merge starts with incoming as the base, then for each fingerprint in base:
/// - If the fingerprint is NEW in incoming: push the base entry
/// - If the fingerprint EXISTS in incoming: fill empty fields from base into incoming
///
/// Key insight: base only fills in EMPTY fields from incoming; it never overwrites
/// a non-empty value in incoming.
#[test]
fn test_merge_fills_empty_fields_from_incoming() {
    // Base has all fields populated
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp1".to_string(),
        rule_id: "rust.no_unwrap".to_string(),
        path: "base.rs".to_string(),
        line: 99,
        note: Some("base note".to_string()),
    });

    // Incoming has empty fields that should be filled from base
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp1".to_string(),
        rule_id: "".to_string(), // Empty — should be filled from base
        path: "".to_string(),    // Empty — should be filled from base
        line: 0,                 // Zero — should be filled from base
        note: None,              // None — should be filled from base's Some
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    // All empty/zero fields in incoming should be filled from base
    assert_eq!(merged.entries[0].rule_id, "rust.no_unwrap");
    assert_eq!(merged.entries[0].path, "base.rs");
    assert_eq!(merged.entries[0].line, 99);
    assert_eq!(merged.entries[0].note.as_deref(), Some("base note"));
}

/// Tests that when incoming has non-empty values, base's empty values do NOT overwrite them.
#[test]
fn test_merge_incoming_non_empty_takes_precedence() {
    // Base has empty rule_id
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp1".to_string(),
        rule_id: "".to_string(),
        path: "base.rs".to_string(),
        line: 99,
        note: Some("base note".to_string()),
    });

    // Incoming has non-empty rule_id — base's empty should NOT overwrite it
    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "fp1".to_string(),
        rule_id: "rust.no_vec_push".to_string(), // Non-empty
        path: "incoming.rs".to_string(),
        line: 42,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);

    assert_eq!(merged.entries.len(), 1);
    // incoming's non-empty rule_id should be preserved (base doesn't overwrite)
    assert_eq!(merged.entries[0].rule_id, "rust.no_vec_push");
    // incoming's path and line preserved since they're non-empty
    assert_eq!(merged.entries[0].path, "incoming.rs");
    assert_eq!(merged.entries[0].line, 42);
    // but note is None in incoming, so base's Some fills it
    assert_eq!(merged.entries[0].note.as_deref(), Some("base note"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Workflow: CheckReceipt → TrendRun → TrendHistory → TrendSummary
// ─────────────────────────────────────────────────────────────────────────────

/// Full trend tracking workflow:
/// 1. Create CheckReceipt
/// 2. Convert to TrendRun
/// 3. Append run to TrendHistory
/// 4. Summarize history with delta
#[test]
fn test_full_trend_workflow() {
    // Step 1: Create receipt
    let findings = vec![make_finding("rust.no_unwrap", "src/lib.rs", 10)];
    let receipt = make_receipt(findings);

    // Step 2: Convert to TrendRun
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );
    assert_eq!(run.base, "origin/main");
    assert_eq!(run.head, "HEAD");
    assert_eq!(run.findings, 1);
    assert_eq!(run.counts.error, 3);

    // Step 3: Append to history
    let history = append_trend_run(TrendHistory::default(), run, Some(10));
    assert_eq!(history.runs.len(), 1);

    // Step 4: Summarize
    let summary = summarize_trend_history(&history);
    assert_eq!(summary.run_count, 1);
    assert_eq!(summary.total_findings, 1);
    assert!(summary.delta_from_previous.is_none()); // Only one run, no delta
}

/// Tests that append_trend_run trims to max_runs correctly.
#[test]
fn test_trend_trim_workflow() {
    let findings = vec![make_finding("rust.no_unwrap", "src/lib.rs", 10)];
    let receipt = make_receipt(findings);

    let mut history = TrendHistory::default();
    for i in 0..5 {
        let run = trend_run_from_receipt(
            &receipt,
            &format!("2026-01-01T00:00:0{}Z", i),
            &format!("2026-01-01T00:00:1{}Z", i),
            1000,
        );
        history = append_trend_run(history, run, Some(3));
    }

    // Should keep only the 3 newest runs
    assert_eq!(history.runs.len(), 3);
    // Oldest runs should be dropped (first 2)
    assert_eq!(history.runs[0].started_at, "2026-01-01T00:00:02Z");
    assert_eq!(history.runs[1].started_at, "2026-01-01T00:00:03Z");
    assert_eq!(history.runs[2].started_at, "2026-01-01T00:00:04Z");
}

/// Tests trend delta computation between runs.
#[test]
fn test_trend_delta_computation() {
    let findings = vec![make_finding("rust.no_unwrap", "src/lib.rs", 10)];
    let receipt = make_receipt(findings);

    // First run: 3 errors, 2 warnings, 5 findings
    let mut run1 = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );
    run1.counts.error = 3;
    run1.counts.warn = 2;
    run1.findings = 5;

    // Second run: 1 error, 1 warning, 2 findings (improved)
    let mut run2 = trend_run_from_receipt(
        &receipt,
        "2026-01-01T01:00:00Z",
        "2026-01-01T01:00:01Z",
        1000,
    );
    run2.counts.error = 1;
    run2.counts.warn = 1;
    run2.findings = 2;

    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run1, run2],
    };

    let summary = summarize_trend_history(&history);

    assert_eq!(summary.run_count, 2);
    assert_eq!(summary.total_findings, 7); // 5 + 2
    assert!(summary.delta_from_previous.is_some());

    let delta = summary.delta_from_previous.unwrap();
    assert_eq!(delta.findings, -3); // 2 - 5
    assert_eq!(delta.error, -2); // 1 - 3
    assert_eq!(delta.warn, -1); // 1 - 2
}

// ─────────────────────────────────────────────────────────────────────────────
// Component Handoff Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Tests that normalize_false_positive_baseline preserves existing schema
/// and does NOT overwrite an already-set schema.
#[test]
fn test_baseline_normalize_preserves_schema() {
    // Default already sets schema to the correct value
    let baseline = FalsePositiveBaseline::default();
    assert!(!baseline.schema.is_empty());

    let normalized = normalize_false_positive_baseline(baseline.clone());
    assert_eq!(
        normalized.schema,
        diffguard_analytics::FALSE_POSITIVE_BASELINE_SCHEMA_V1
    );

    // Should NOT overwrite if already set
    let baseline_with_custom_schema = FalsePositiveBaseline {
        schema: "already_set".to_string(),
        ..Default::default()
    };
    let not_overwritten = normalize_false_positive_baseline(baseline_with_custom_schema);
    assert_eq!(not_overwritten.schema, "already_set");
}

/// Tests that normalize_trend_history preserves existing schema
/// and does NOT overwrite an already-set schema.
#[test]
fn test_trend_normalize_preserves_schema() {
    // Default already sets schema to the correct value
    let history = TrendHistory::default();
    assert!(!history.schema.is_empty());

    let normalized = normalize_trend_history(history.clone());
    assert_eq!(normalized.schema, TREND_HISTORY_SCHEMA_V1);

    // Should NOT overwrite if already set
    let history_with_custom_schema = TrendHistory {
        schema: "already_set".to_string(),
        ..Default::default()
    };
    let not_overwritten = normalize_trend_history(history_with_custom_schema);
    assert_eq!(not_overwritten.schema, "already_set");
}

/// Tests that false_positive_fingerprint_set produces correct BTreeSet.
#[test]
fn test_fingerprint_set_handoff() {
    let baseline = FalsePositiveBaseline {
        schema: diffguard_analytics::FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "aaa".to_string(),
                rule_id: "rule1".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "bbb".to_string(),
                rule_id: "rule2".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
        ],
    };

    let set = false_positive_fingerprint_set(&baseline);

    assert_eq!(set.len(), 2);
    assert!(set.contains("aaa"));
    assert!(set.contains("bbb"));
    assert!(!set.contains("ccc"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Serialization Round-Trip Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Tests JSON serialization round-trip for FalsePositiveBaseline.
#[test]
fn test_baseline_serde_roundtrip() {
    let baseline = FalsePositiveBaseline {
        schema: diffguard_analytics::FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "fp_hash_abc123".to_string(),
            rule_id: "rust.no_unwrap".to_string(),
            path: "src/lib.rs".to_string(),
            line: 42,
            note: Some("Intentionally allowed in test".to_string()),
        }],
    };

    let json = serde_json::to_string(&baseline).expect("serialize baseline");
    let deserialized: FalsePositiveBaseline =
        serde_json::from_str(&json).expect("deserialize baseline");

    assert_eq!(deserialized, baseline);
}

/// Tests JSON serialization round-trip for TrendHistory.
#[test]
fn test_trend_history_serde_roundtrip() {
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![
            TrendRun {
                started_at: "2026-01-01T00:00:00Z".to_string(),
                ended_at: "2026-01-01T00:00:01Z".to_string(),
                duration_ms: 1000,
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                scope: diffguard_types::Scope::Added,
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 2,
                    error: 3,
                    suppressed: 1,
                },
                files_scanned: 42,
                lines_scanned: 1337,
                findings: 5,
            },
            TrendRun {
                started_at: "2026-01-01T01:00:00Z".to_string(),
                ended_at: "2026-01-01T01:00:01Z".to_string(),
                duration_ms: 1000,
                base: "HEAD".to_string(),
                head: "HEAD~1".to_string(),
                scope: diffguard_types::Scope::Changed,
                status: VerdictStatus::Pass,
                counts: VerdictCounts {
                    info: 1,
                    warn: 0,
                    error: 0,
                    suppressed: 0,
                },
                files_scanned: 30,
                lines_scanned: 900,
                findings: 0,
            },
        ],
    };

    let json = serde_json::to_string(&history).expect("serialize history");
    let deserialized: TrendHistory = serde_json::from_str(&json).expect("deserialize history");

    assert_eq!(deserialized.schema, history.schema);
    assert_eq!(deserialized.runs.len(), 2);
    assert_eq!(deserialized.runs[0].findings, 5);
    assert_eq!(deserialized.runs[1].findings, 0);
}

/// Tests JSON serialization round-trip for TrendSummary.
#[test]
fn test_trend_summary_serde_roundtrip() {
    let summary = TrendSummary {
        run_count: 2,
        totals: VerdictCounts {
            info: 1,
            warn: 2,
            error: 3,
            suppressed: 1,
        },
        total_findings: 10,
        latest: Some(TrendRun {
            started_at: "2026-01-01T00:00:00Z".to_string(),
            ended_at: "2026-01-01T00:00:01Z".to_string(),
            duration_ms: 1000,
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            scope: diffguard_types::Scope::Added,
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 2,
                error: 3,
                suppressed: 1,
            },
            files_scanned: 42,
            lines_scanned: 1337,
            findings: 5,
        }),
        delta_from_previous: Some(diffguard_analytics::TrendDelta {
            findings: -2,
            info: 0,
            warn: -1,
            error: -1,
            suppressed: 0,
        }),
    };

    let json = serde_json::to_string(&summary).expect("serialize summary");
    let deserialized: TrendSummary = serde_json::from_str(&json).expect("deserialize summary");

    assert_eq!(deserialized.run_count, 2);
    assert_eq!(deserialized.total_findings, 10);
    assert!(deserialized.latest.is_some());
    assert!(deserialized.delta_from_previous.is_some());
    assert_eq!(deserialized.delta_from_previous.unwrap().findings, -2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Edge Cases
// ─────────────────────────────────────────────────────────────────────────────

/// Tests behavior with empty findings list.
#[test]
fn test_baseline_from_empty_receipt() {
    let receipt = make_receipt(vec![]);
    let baseline = baseline_from_receipt(&receipt);

    assert_eq!(baseline.entries.len(), 0);
    assert!(!baseline.schema.is_empty());
}

/// Tests trend summary with empty history.
#[test]
fn test_summarize_empty_history() {
    let history = TrendHistory::default();
    let summary = summarize_trend_history(&history);

    assert_eq!(summary.run_count, 0);
    assert_eq!(summary.total_findings, 0);
    assert!(summary.latest.is_none());
    assert!(summary.delta_from_previous.is_none());
}

/// Tests that append_trend_run handles max_runs = 0 (no trim).
#[test]
fn test_append_trend_run_no_trim_when_max_zero() {
    let findings = vec![make_finding("rust.no_unwrap", "src/lib.rs", 10)];
    let receipt = make_receipt(findings);

    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );

    let history = append_trend_run(TrendHistory::default(), run, Some(0));
    assert_eq!(history.runs.len(), 1);
}

/// Tests that append_trend_run handles max_runs = 1.
#[test]
fn test_append_trend_run_max_one() {
    let findings = vec![make_finding("rust.no_unwrap", "src/lib.rs", 10)];
    let receipt = make_receipt(findings);

    let run1 = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );
    let run2 = trend_run_from_receipt(
        &receipt,
        "2026-01-01T01:00:00Z",
        "2026-01-01T01:00:01Z",
        1000,
    );

    let history = append_trend_run(
        append_trend_run(TrendHistory::default(), run1, Some(1)),
        run2,
        Some(1),
    );

    // Should keep only the newest run
    assert_eq!(history.runs.len(), 1);
    assert_eq!(history.runs[0].started_at, "2026-01-01T01:00:00Z");
}
