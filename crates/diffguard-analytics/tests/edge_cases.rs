//! Edge case tests for diffguard-analytics public functions.
//!
//! These tests verify behavior under boundary conditions:
//! - Empty inputs, zero values, max values
//! - Duplicate handling
//! - Overflow/saturating arithmetic
//! - Schema preservation (should NOT overwrite existing valid schema)
//!
//! These complement the red tests (must_use_verification.rs) which verify
//! #[must_use] and # Panics docs are present.

use diffguard_analytics::{
    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    TREND_HISTORY_SCHEMA_V1, TrendHistory, TrendRun, append_trend_run, baseline_from_receipt,
    false_positive_fingerprint_set, fingerprint_for_finding, merge_false_positive_baselines,
    normalize_false_positive_baseline, normalize_trend_history, summarize_trend_history,
    trend_run_from_receipt,
};
use diffguard_types::{
    CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts,
    VerdictStatus,
};

/// Helper: minimal receipt with given findings count
fn receipt_with_n_findings(n: usize) -> CheckReceipt {
    CheckReceipt {
        schema: "diffguard.check.v1".to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "1.0.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 100,
        },
        findings: (0..n)
            .map(|i| Finding {
                rule_id: format!("rule{}", i),
                severity: Severity::Error,
                message: format!("finding {}", i),
                path: format!("src/file{}.rs", i),
                line: i as u32 + 1,
                column: Some(1),
                match_text: format!("match{}", i),
                snippet: format!("line {} with match{}", i, i),
            })
            .collect(),
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: n as u32,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// fingerprint_for_finding edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_fingerprint_for_finding_empty_strings() {
    // Empty strings should still produce a valid SHA-256 fingerprint (64 hex chars)
    let finding = Finding {
        rule_id: String::new(),
        severity: Severity::Error,
        message: String::new(),
        path: String::new(),
        line: 0,
        column: None,
        match_text: String::new(),
        snippet: String::new(),
    };

    let fp = fingerprint_for_finding(&finding);
    assert_eq!(fp.len(), 64, "SHA-256 hex encoding should be 64 characters");
    assert!(
        fp.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint should only contain hex characters"
    );
}

#[test]
fn test_fingerprint_for_finding_unicode() {
    // Unicode in match_text should be handled (UTF-8 encoded before hashing)
    let finding = Finding {
        rule_id: "rule-日本語".to_string(),
        severity: Severity::Error,
        message: "unicode finding".to_string(),
        path: "src/日本語.rs".to_string(),
        line: 1,
        column: Some(1),
        match_text: "日本語テキスト".to_string(),
        snippet: "let x = 日本語;".to_string(),
    };

    let fp = fingerprint_for_finding(&finding);
    assert_eq!(fp.len(), 64);
}

#[test]
fn test_fingerprint_for_finding_deterministic() {
    // Same finding must produce same fingerprint
    let finding = Finding {
        rule_id: "rust.no_debug".to_string(),
        severity: Severity::Warn,
        message: "debug output".to_string(),
        path: "src/main.rs".to_string(),
        line: 42,
        column: Some(8),
        match_text: "println!".to_string(),
        snippet: "    println!(\"{:?}\", x);".to_string(),
    };

    let fp1 = fingerprint_for_finding(&finding);
    let fp2 = fingerprint_for_finding(&finding);
    assert_eq!(fp1, fp2, "same finding must produce same fingerprint");
}

#[test]
fn test_fingerprint_for_finding_different_inputs_different_fingerprints() {
    // Different findings must produce different fingerprints
    let finding1 = Finding {
        rule_id: "rust.no_debug".to_string(),
        severity: Severity::Warn,
        message: "debug output".to_string(),
        path: "src/main.rs".to_string(),
        line: 42,
        column: Some(8),
        match_text: "println!".to_string(),
        snippet: "println!".to_string(),
    };

    let mut finding2 = finding1.clone();
    finding2.line = 43; // Only line differs

    let fp1 = fingerprint_for_finding(&finding1);
    let fp2 = fingerprint_for_finding(&finding2);
    assert_ne!(
        fp1, fp2,
        "different findings must produce different fingerprints"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// normalize_false_positive_baseline edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_normalize_false_positive_baseline_empty_entries() {
    let baseline = FalsePositiveBaseline {
        schema: String::new(),
        entries: vec![],
    };

    let normalized = normalize_false_positive_baseline(baseline);
    assert_eq!(normalized.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
    assert!(normalized.entries.is_empty());
}

#[test]
fn test_normalize_false_positive_baseline_deduplicates() {
    // Two entries with same fingerprint - should be deduplicated
    let baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "dup_fp".to_string(),
                rule_id: "rule1".to_string(),
                path: "a.rs".to_string(),
                line: 10,
                note: Some("first".to_string()),
            },
            FalsePositiveEntry {
                fingerprint: "dup_fp".to_string(), // Same fingerprint
                rule_id: "rule2".to_string(),
                path: "b.rs".to_string(),
                line: 20,
                note: Some("second".to_string()),
            },
        ],
    };

    let normalized = normalize_false_positive_baseline(baseline);
    assert_eq!(
        normalized.entries.len(),
        1,
        "duplicate fingerprints should be removed"
    );
}

#[test]
fn test_normalize_false_positive_baseline_does_not_overwrite_schema() {
    // If schema is already set, it should NOT be overwritten
    let original_schema = "my.custom.schema.v1";
    let baseline = FalsePositiveBaseline {
        schema: original_schema.to_string(),
        entries: vec![],
    };

    let normalized = normalize_false_positive_baseline(baseline);
    assert_eq!(
        normalized.schema, original_schema,
        "existing schema should not be overwritten"
    );
}

#[test]
fn test_normalize_false_positive_baseline_sorts_by_fingerprint() {
    // Entries should be sorted by fingerprint, then rule_id, path, line
    let baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "z_fp".to_string(),
                rule_id: "rule_z".to_string(),
                path: "z.rs".to_string(),
                line: 30,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "a_fp".to_string(),
                rule_id: "rule_a".to_string(),
                path: "a.rs".to_string(),
                line: 10,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "m_fp".to_string(),
                rule_id: "rule_m".to_string(),
                path: "m.rs".to_string(),
                line: 20,
                note: None,
            },
        ],
    };

    let normalized = normalize_false_positive_baseline(baseline);
    assert_eq!(normalized.entries[0].fingerprint, "a_fp");
    assert_eq!(normalized.entries[1].fingerprint, "m_fp");
    assert_eq!(normalized.entries[2].fingerprint, "z_fp");
}

// ─────────────────────────────────────────────────────────────────────────────
// baseline_from_receipt edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_baseline_from_receipt_empty_findings() {
    let receipt = receipt_with_n_findings(0);
    let baseline = baseline_from_receipt(&receipt);

    assert_eq!(baseline.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
    assert!(baseline.entries.is_empty());
}

#[test]
fn test_baseline_from_receipt_many_findings() {
    // 1000 findings should all be converted to baseline entries
    let receipt = receipt_with_n_findings(1000);
    let baseline = baseline_from_receipt(&receipt);

    assert_eq!(baseline.entries.len(), 1000);
}

// ─────────────────────────────────────────────────────────────────────────────
// merge_false_positive_baselines edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_merge_both_empty() {
    let base = FalsePositiveBaseline::default();
    let incoming = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert!(merged.entries.is_empty());
}

#[test]
fn test_merge_incoming_empty() {
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "fp1".to_string(),
        rule_id: "rule1".to_string(),
        path: "a.rs".to_string(),
        line: 10,
        note: None,
    });

    let incoming = FalsePositiveBaseline::default();

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(merged.entries.len(), 1);
    assert_eq!(merged.entries[0].fingerprint, "fp1");
}

#[test]
fn test_merge_fills_empty_fields_from_base() {
    // Incoming has fingerprint match but empty optional fields
    // Base has the same fingerprint with non-empty fields
    // Incoming's empty fields should be filled from base
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "shared_fp".to_string(),
        rule_id: "rule1".to_string(),
        path: "a.rs".to_string(),
        line: 10,
        note: Some("base note".to_string()),
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "shared_fp".to_string(),
        rule_id: String::new(), // empty - should be filled from base
        path: String::new(),    // empty - should be filled from base
        line: 0,                // zero - should be filled from base
        note: None, // None - base has Some, but note merge only if incoming.note is None AND base.note is Some
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    let entry = merged
        .entries
        .iter()
        .find(|e| e.fingerprint == "shared_fp")
        .expect("shared_fp should exist");

    // Per the merge logic: rule_id only filled if existing.rule_id.is_empty()
    assert_eq!(entry.rule_id, "rule1");
    assert_eq!(entry.path, "a.rs");
    assert_eq!(entry.line, 10);
}

#[test]
fn test_merge_deduplicates_after_merge() {
    // Both have same fingerprint - should result in single entry
    let mut base = FalsePositiveBaseline::default();
    base.entries.push(FalsePositiveEntry {
        fingerprint: "dup".to_string(),
        rule_id: "rule1".to_string(),
        path: "a.rs".to_string(),
        line: 10,
        note: None,
    });

    let mut incoming = FalsePositiveBaseline::default();
    incoming.entries.push(FalsePositiveEntry {
        fingerprint: "dup".to_string(),
        rule_id: "rule1".to_string(),
        path: "a.rs".to_string(),
        line: 10,
        note: None,
    });

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_eq!(
        merged.entries.len(),
        1,
        "duplicate fingerprints should be deduped"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// false_positive_fingerprint_set edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_false_positive_fingerprint_set_empty_baseline() {
    let baseline = FalsePositiveBaseline::default();
    let set = false_positive_fingerprint_set(&baseline);
    assert!(set.is_empty());
}

#[test]
fn test_false_positive_fingerprint_set_single_entry() {
    let baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "only_fp".to_string(),
            rule_id: "rule1".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: None,
        }],
    };

    let set = false_positive_fingerprint_set(&baseline);
    assert_eq!(set.len(), 1);
    assert!(set.contains("only_fp"));
}

// ─────────────────────────────────────────────────────────────────────────────
// normalize_trend_history edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_normalize_trend_history_does_not_overwrite_schema() {
    let original_schema = "my.custom.trend.v1";
    let history = TrendHistory {
        schema: original_schema.to_string(),
        runs: vec![],
    };

    let normalized = normalize_trend_history(history);
    assert_eq!(
        normalized.schema, original_schema,
        "existing schema should not be overwritten"
    );
}

#[test]
fn test_normalize_trend_history_empty_schema_gets_default() {
    let history = TrendHistory {
        schema: String::new(),
        runs: vec![],
    };

    let normalized = normalize_trend_history(history);
    assert_eq!(normalized.schema, TREND_HISTORY_SCHEMA_V1);
}

// ─────────────────────────────────────────────────────────────────────────────
// trend_run_from_receipt edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_trend_run_from_receipt_empty_findings() {
    let receipt = receipt_with_n_findings(0);
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
        60000,
    );

    assert_eq!(run.findings, 0);
}

#[test]
fn test_trend_run_from_receipt_finds_count_matches() {
    // 42 findings
    let receipt = receipt_with_n_findings(42);
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
        60000,
    );

    assert_eq!(run.findings, 42);
}

#[test]
fn test_trend_run_from_receipt_preserves_timing_fields() {
    let receipt = receipt_with_n_findings(1);
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:02:30Z",
        150000,
    );

    assert_eq!(run.started_at, "2026-01-01T00:00:00Z");
    assert_eq!(run.ended_at, "2026-01-01T00:02:30Z");
    assert_eq!(run.duration_ms, 150000);
}

// ─────────────────────────────────────────────────────────────────────────────
// append_trend_run edge cases
// ─────────────────────────────────────────────────────────────────────────────

fn make_trend_run(id: u32) -> TrendRun {
    TrendRun {
        started_at: format!("2026-01-{:02}T00:00:00Z", id),
        ended_at: format!("2026-01-{:02}T00:01:00Z", id),
        duration_ms: 60000,
        base: "origin/main".to_string(),
        head: "HEAD".to_string(),
        scope: Scope::Added,
        status: VerdictStatus::Pass,
        counts: VerdictCounts::default(),
        files_scanned: 10,
        lines_scanned: 500,
        findings: id,
    }
}

#[test]
fn test_append_trend_run_max_runs_zero_does_not_trim() {
    // max_runs = 0 should NOT trim (per implementation: limit > 0 check)
    let history = TrendHistory::default();
    let run = make_trend_run(1);

    let updated = append_trend_run(history, run, Some(0));

    // With limit=0, the condition `limit > 0` is false, so no trimming occurs
    assert_eq!(updated.runs.len(), 1);
}

#[test]
fn test_append_trend_run_max_runs_one() {
    let history = TrendHistory::default();
    let run1 = make_trend_run(1);
    let run2 = make_trend_run(2);

    let updated = append_trend_run(history, run1, Some(1));
    assert_eq!(updated.runs.len(), 1);

    let updated = append_trend_run(updated, run2, Some(1));
    assert_eq!(updated.runs.len(), 1, "should trim to 1");
    assert_eq!(updated.runs[0].findings, 2, "newest run should be kept");
}

#[test]
fn test_append_trend_run_keeps_newest_runs() {
    // When trimming, newest runs (at end) should be kept, oldest (at start) removed
    let history = TrendHistory::default();

    let updated = append_trend_run(history, make_trend_run(1), Some(3));
    let updated = append_trend_run(updated, make_trend_run(2), Some(3));
    let updated = append_trend_run(updated, make_trend_run(3), Some(3));
    let updated = append_trend_run(updated, make_trend_run(4), Some(3));
    let updated = append_trend_run(updated, make_trend_run(5), Some(3));

    assert_eq!(updated.runs.len(), 3);
    // Should be runs 3, 4, 5 (newest 3)
    assert_eq!(updated.runs[0].findings, 3);
    assert_eq!(updated.runs[1].findings, 4);
    assert_eq!(updated.runs[2].findings, 5);
}

#[test]
fn test_append_trend_run_no_max_runs_keeps_all() {
    let history = TrendHistory::default();

    let updated = append_trend_run(history, make_trend_run(1), None);
    let updated = append_trend_run(updated, make_trend_run(2), None);
    let updated = append_trend_run(updated, make_trend_run(3), None);

    assert_eq!(updated.runs.len(), 3);
}

#[test]
fn test_append_trend_run_normalizes_history() {
    // Even if history has empty schema, it should be normalized after append
    let history = TrendHistory {
        schema: String::new(),
        runs: vec![],
    };
    let run = make_trend_run(1);

    let updated = append_trend_run(history, run, None);

    assert_eq!(updated.schema, TREND_HISTORY_SCHEMA_V1);
}

// ─────────────────────────────────────────────────────────────────────────────
// summarize_trend_history edge cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_summarize_empty_history() {
    let history = TrendHistory::default();
    let summary = summarize_trend_history(&history);

    assert_eq!(summary.run_count, 0);
    assert_eq!(summary.total_findings, 0);
    assert!(summary.latest.is_none());
    assert!(
        summary.delta_from_previous.is_none(),
        "no delta when no runs"
    );
}

#[test]
fn test_summarize_single_run_no_delta() {
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![make_trend_run(1)],
    };

    let summary = summarize_trend_history(&history);

    assert_eq!(summary.run_count, 1);
    assert!(summary.latest.is_some());
    assert!(
        summary.delta_from_previous.is_none(),
        "no delta with only one run"
    );
}

#[test]
fn test_summarize_saturating_arithmetic() {
    // Very large counts - saturating_add should prevent overflow
    let mut run = make_trend_run(1);
    run.counts.info = u32::MAX;
    run.counts.warn = u32::MAX;
    run.counts.error = u32::MAX;
    run.counts.suppressed = u32::MAX;

    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run.clone(), run.clone()],
    };

    let summary = summarize_trend_history(&history);

    // Each run has u32::MAX, two runs should saturate at u32::MAX (not overflow)
    assert_eq!(summary.totals.info, u32::MAX);
    assert_eq!(summary.totals.warn, u32::MAX);
    assert_eq!(summary.totals.error, u32::MAX);
    assert_eq!(summary.totals.suppressed, u32::MAX);
}

#[test]
fn test_summarize_negative_delta() {
    // Second run has fewer findings than first - delta should be negative
    let run1 = make_trend_run(1);
    let mut run2 = make_trend_run(2);
    run2.findings = 0;
    run2.counts.warn = 0;
    run2.counts.error = 0;

    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run1, run2],
    };

    let summary = summarize_trend_history(&history);

    let delta = summary.delta_from_previous.expect("should have delta");
    assert!(
        delta.findings < 0,
        "delta should be negative when findings decreased"
    );
}

#[test]
fn test_summarize_positive_delta() {
    // Second run has more findings than first - delta should be positive
    let mut run1 = make_trend_run(1);
    run1.findings = 1;
    run1.counts.warn = 1;

    let mut run2 = make_trend_run(2);
    run2.findings = 10;
    run2.counts.warn = 10;

    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run1, run2],
    };

    let summary = summarize_trend_history(&history);

    let delta = summary.delta_from_previous.expect("should have delta");
    assert!(
        delta.findings > 0,
        "delta should be positive when findings increased"
    );
    assert_eq!(delta.findings, 9); // 10 - 1
}

#[test]
fn test_summarize_total_findings_matches_sum() {
    let run1 = make_trend_run(1);
    let mut run2 = make_trend_run(2);
    run2.findings = 5;

    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run1, run2],
    };

    let summary = summarize_trend_history(&history);

    assert_eq!(
        summary.total_findings,
        1 + 5,
        "total findings should be sum of all runs"
    );
}

#[test]
fn test_summarize_latest_is_last_run() {
    let run1 = make_trend_run(1);
    let run2 = make_trend_run(2);
    let run3 = make_trend_run(3);

    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run1, run2, run3],
    };

    let summary = summarize_trend_history(&history);

    let latest = summary.latest.expect("should have latest");
    assert_eq!(latest.findings, 3, "latest should be the last (newest) run");
}
