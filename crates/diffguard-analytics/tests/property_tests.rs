//! Property-based tests for diffguard-analytics public functions.
//!
//! These tests verify invariants that hold across all inputs using
//! property-based testing with proptest.
//!
//! Properties tested:
//! 1. Idempotency: normalizing twice gives same result as once
//! 2. Determinism: same inputs produce same outputs
//! 3. Preservation: information isn't lost or corrupted
//! 4. Bounded outputs: values within expected ranges
//! 5. Serialization round-trip: no data loss

use diffguard_analytics::{
    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    TREND_HISTORY_SCHEMA_V1, TrendHistory, TrendRun, append_trend_run, baseline_from_receipt,
    false_positive_fingerprint_set, fingerprint_for_finding, merge_false_positive_baselines,
    normalize_false_positive_baseline, normalize_trend_history, summarize_trend_history,
    trend_run_from_receipt,
};
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};
use proptest::prelude::*;

// ============================================================================
// Proptest Strategies for generating random instances
// ============================================================================

/// Strategy for generating valid Severity values.
fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Warn),
        Just(Severity::Error),
    ]
}

/// Strategy for generating valid Scope values.
fn arb_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![
        Just(Scope::Added),
        Just(Scope::Changed),
        Just(Scope::Modified),
        Just(Scope::Deleted),
    ]
}

/// Strategy for generating valid VerdictStatus values.
fn arb_verdict_status() -> impl Strategy<Value = VerdictStatus> {
    prop_oneof![
        Just(VerdictStatus::Pass),
        Just(VerdictStatus::Warn),
        Just(VerdictStatus::Fail),
    ]
}

/// Strategy for generating non-empty strings (for required fields).
fn arb_non_empty_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_.-]{1,50}".prop_map(|s| s)
}

/// Strategy for generating arbitrary strings (including empty).
fn arb_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_.-]*".prop_map(|s| s)
}

/// Strategy for generating valid ToolMeta.
fn arb_tool_meta() -> impl Strategy<Value = ToolMeta> {
    (arb_non_empty_string(), arb_non_empty_string())
        .prop_map(|(name, version)| ToolMeta { name, version })
}

/// Strategy for generating valid DiffMeta.
fn arb_diff_meta() -> impl Strategy<Value = DiffMeta> {
    (
        arb_non_empty_string(), // base
        arb_non_empty_string(), // head
        0u32..100,              // context_lines
        arb_scope(),            // scope
        0u64..1000,             // files_scanned
        0u32..10000,            // lines_scanned
    )
        .prop_map(
            |(base, head, context_lines, scope, files_scanned, lines_scanned)| DiffMeta {
                base,
                head,
                context_lines,
                scope,
                files_scanned,
                lines_scanned,
            },
        )
}

/// Strategy for generating valid Finding.
fn arb_finding() -> impl Strategy<Value = Finding> {
    (
        arb_non_empty_string(),      // rule_id
        arb_severity(),              // severity
        arb_non_empty_string(),      // message
        arb_non_empty_string(),      // path
        1u32..10000,                 // line
        prop::option::of(1u32..500), // column
        arb_string(),                // match_text (can be empty)
        arb_string(),                // snippet (can be empty)
    )
        .prop_map(
            |(rule_id, severity, message, path, line, column, match_text, snippet)| Finding {
                rule_id,
                severity,
                message,
                path,
                line,
                column,
                match_text,
                snippet,
            },
        )
}

/// Strategy for generating valid VerdictCounts.
fn arb_verdict_counts() -> impl Strategy<Value = VerdictCounts> {
    (0u32..100, 0u32..100, 0u32..100, 0u32..50).prop_map(|(info, warn, error, suppressed)| {
        VerdictCounts {
            info,
            warn,
            error,
            suppressed,
        }
    })
}

/// Strategy for generating valid Verdict.
fn arb_verdict() -> impl Strategy<Value = Verdict> {
    (
        arb_verdict_status(),
        arb_verdict_counts(),
        prop::collection::vec(arb_non_empty_string(), 0..5),
    )
        .prop_map(|(status, counts, reasons)| Verdict {
            status,
            counts,
            reasons,
        })
}

/// Strategy for generating valid CheckReceipt.
fn arb_check_receipt() -> impl Strategy<Value = CheckReceipt> {
    (
        arb_tool_meta(),
        arb_diff_meta(),
        prop::collection::vec(arb_finding(), 0..10),
        arb_verdict(),
    )
        .prop_map(|(tool, diff, findings, verdict)| CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool,
            diff,
            findings,
            verdict,
            timing: None,
        })
}

/// Strategy for generating valid FalsePositiveEntry.
fn arb_false_positive_entry() -> impl Strategy<Value = FalsePositiveEntry> {
    (
        arb_string(),                   // fingerprint
        arb_string(),                   // rule_id (can be empty per merge logic)
        arb_string(),                   // path (can be empty per merge logic)
        0u32..1000,                     // line (0 allowed per merge logic)
        prop::option::of(arb_string()), // note
    )
        .prop_map(
            |(fingerprint, rule_id, path, line, note)| FalsePositiveEntry {
                fingerprint,
                rule_id,
                path,
                line,
                note,
            },
        )
}

/// Strategy for generating valid FalsePositiveBaseline.
fn arb_false_positive_baseline() -> impl Strategy<Value = FalsePositiveBaseline> {
    prop::collection::vec(arb_false_positive_entry(), 0..10).prop_map(|entries| {
        FalsePositiveBaseline {
            schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
            entries,
        }
    })
}

/// Strategy for generating valid TrendRun.
fn arb_trend_run() -> impl Strategy<Value = TrendRun> {
    (
        arb_string(),         // started_at
        arb_string(),         // ended_at
        0u64..1_000_000,      // duration_ms
        arb_string(),         // base
        arb_string(),         // head
        arb_scope(),          // scope
        arb_verdict_status(), // status
        arb_verdict_counts(), // counts
        0u64..1000,           // files_scanned
        0u32..10000,          // lines_scanned
        0u32..1000,           // findings
    )
        .prop_map(
            |(
                started_at,
                ended_at,
                duration_ms,
                base,
                head,
                scope,
                status,
                counts,
                files_scanned,
                lines_scanned,
                findings,
            )| {
                TrendRun {
                    started_at,
                    ended_at,
                    duration_ms,
                    base,
                    head,
                    scope,
                    status,
                    counts,
                    files_scanned,
                    lines_scanned,
                    findings,
                }
            },
        )
}

/// Strategy for generating valid TrendHistory.
fn arb_trend_history() -> impl Strategy<Value = TrendHistory> {
    prop::collection::vec(arb_trend_run(), 0..20).prop_map(|runs| TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs,
    })
}

// ============================================================================
// Property Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    // ========================================================================
    // Property 1: normalize_false_positive_baseline is IDEMPOTENT
    // ========================================================================

    /// **Property 1: normalize_false_positive_baseline Idempotency**
    ///
    /// For any FalsePositiveBaseline, normalizing it twice SHALL produce
    /// the same result as normalizing it once.
    ///
    /// Invariant: Idempotent (f(f(x)) = f(x))
    #[test]
    fn normalize_baseline_is_idempotent(baseline in arb_false_positive_baseline()) {
        let normalized_once = normalize_false_positive_baseline(baseline.clone());
        let normalized_twice = normalize_false_positive_baseline(normalized_once.clone());
        prop_assert_eq!(
            normalized_once, normalized_twice,
            "Normalizing twice should produce same result as normalizing once"
        );
    }

    // ========================================================================
    // Property 2: normalize_trend_history is IDEMPOTENT
    // ========================================================================

    /// **Property 2: normalize_trend_history Idempotency**
    ///
    /// For any TrendHistory, normalizing it twice SHALL produce
    /// the same result as normalizing it once.
    ///
    /// Invariant: Idempotent (f(f(x)) = f(x))
    #[test]
    fn normalize_trend_history_is_idempotent(history in arb_trend_history()) {
        let normalized_once = normalize_trend_history(history.clone());
        let normalized_twice = normalize_trend_history(normalized_once.clone());
        prop_assert_eq!(
            normalized_once, normalized_twice,
            "Normalizing trend history twice should produce same result as normalizing once"
        );
    }

    // ========================================================================
    // Property 3: fingerprint_for_finding is DETERMINISTIC
    // ========================================================================

    /// **Property 3: fingerprint_for_finding Determinism**
    ///
    /// For any Finding, calling fingerprint_for_finding twice SHALL produce
    /// the same 64-character hex string.
    ///
    /// Invariant: Deterministic (same input => same output)
    #[test]
    fn fingerprint_for_finding_is_deterministic(finding in arb_finding()) {
        let fp1 = fingerprint_for_finding(&finding);
        let fp2 = fingerprint_for_finding(&finding);
        let fp_len = fp1.len();
        prop_assert_eq!(
            fp1, fp2.clone(),
            "Same finding should produce same fingerprint"
        );
        prop_assert_eq!(
            fp_len, 64,
            "SHA-256 hex encoding should be exactly 64 characters"
        );
        prop_assert!(
            fp2.chars().all(|c| c.is_ascii_hexdigit()),
            "Fingerprint should only contain hex characters"
        );
    }

    // ========================================================================
    // Property 4: baseline_from_receipt is DETERMINISTIC
    // ========================================================================

    /// **Property 4: baseline_from_receipt Determinism**
    ///
    /// For any CheckReceipt, building a baseline twice SHALL produce
    /// identical baselines with same schema and entries.
    ///
    /// Invariant: Deterministic (same input => same output)
    #[test]
    fn baseline_from_receipt_is_deterministic(receipt in arb_check_receipt()) {
        let baseline1 = baseline_from_receipt(&receipt);
        let baseline2 = baseline_from_receipt(&receipt);
        let schema1 = baseline1.schema.clone();
        prop_assert_eq!(
            baseline1, baseline2,
            "Same receipt should produce identical baselines"
        );
        prop_assert_eq!(
            schema1, FALSE_POSITIVE_BASELINE_SCHEMA_V1,
            "Baseline schema should always be set to V1"
        );
    }

    // ========================================================================
    // Property 5: merge_false_positive_baselines produces valid UNION
    // ========================================================================

    /// **Property 5: merge_false_positive_baselines Union Property**
    ///
    /// The merged baseline SHALL contain all unique fingerprints from both
    /// base and incoming. No fingerprint from either input SHALL be lost.
    ///
    /// Invariant: Preservation (union of fingerprints)
    #[test]
    fn merge_preserves_all_fingerprints(
        mut base in arb_false_positive_baseline(),
        mut incoming in arb_false_positive_baseline()
    ) {
        // Deduplicate entries within each baseline to ensure clean test
        base = normalize_false_positive_baseline(base);
        incoming = normalize_false_positive_baseline(incoming);

        let base_fps: Vec<_> = base.entries.iter().map(|e| e.fingerprint.clone()).collect();
        let incoming_fps: Vec<_> = incoming.entries.iter().map(|e| e.fingerprint.clone()).collect();

        let merged = merge_false_positive_baselines(&base, &incoming);
        let merged_fps: std::collections::BTreeSet<_> = merged
            .entries
            .iter()
            .map(|e| e.fingerprint.clone())
            .collect();

        // All base fingerprints should be in merged
        for fp in &base_fps {
            prop_assert!(
                merged_fps.contains(fp),
                "Base fingerprint {:?} should be in merged result", fp
            );
        }

        // All incoming fingerprints should be in merged
        for fp in &incoming_fps {
            prop_assert!(
                merged_fps.contains(fp),
                "Incoming fingerprint {:?} should be in merged result", fp
            );
        }

        // Schema should be set
        prop_assert_eq!(
            merged.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1,
            "Merged baseline schema should be set to V1"
        );
    }

    // ========================================================================
    // Property 6: merge is IDEMPOTENT when base is subset of incoming
    // ========================================================================

    /// **Property 6: merge_false_positive_baselines Idempotency**
    ///
    /// When incoming already contains all entries from base, merging again
    /// SHOULD produce the same result.
    ///
    /// Invariant: Idempotent when base entries are subset of incoming
    #[test]
    fn merge_idempotent_when_incoming_contains_base(
        mut base in arb_false_positive_baseline(),
        mut incoming in arb_false_positive_baseline()
    ) {
        // Deduplicate and normalize both
        base = normalize_false_positive_baseline(base);
        incoming = normalize_false_positive_baseline(incoming);

        // First merge
        let merged1 = merge_false_positive_baselines(&base, &incoming);

        // Second merge (using result as new incoming)
        let merged2 = merge_false_positive_baselines(&base, &merged1);

        prop_assert_eq!(
            merged1.entries.len(), merged2.entries.len(),
            "Second merge should not change entry count"
        );
    }

    // ========================================================================
    // Property 7: append_trend_run respects max_runs BOUND
    // ========================================================================

    /// **Property 7: append_trend_run respects max_runs bound**
    ///
    /// When max_runs is Some(n) with n > 0, the resulting history SHALL have
    /// at most n runs, keeping the newest entries.
    ///
    /// Invariant: Bounded output (len <= max_runs)
    #[test]
    fn append_trend_run_respects_max_runs(
        history in arb_trend_history(),
        max_runs in 1usize..50,
        run in arb_trend_run()
    ) {
        let result = append_trend_run(history, run, Some(max_runs));

        if result.runs.len() > max_runs {
            prop_assert!(
                false,
                "append_trend_run result has {} runs but max_runs was {}",
                result.runs.len(),
                max_runs
            );
        }

        prop_assert!(
            result.runs.len() <= max_runs,
            "Result runs count ({}) should not exceed max_runs ({})",
            result.runs.len(),
            max_runs
        );
    }

    /// **Property 7b: append_trend_run with max_runs=0 does not trim**
    ///
    /// When max_runs is Some(0), no trimming should occur.
    ///
    /// Invariant: max_runs=0 means unlimited
    #[test]
    fn append_trend_run_max_runs_zero_unlimited(
        history in arb_trend_history(),
        run in arb_trend_run()
    ) {
        let result = append_trend_run(history.clone(), run, Some(0));
        prop_assert_eq!(
            result.runs.len(),
            history.runs.len() + 1,
            "max_runs=0 should not trim any entries"
        );
    }

    /// **Property 7c: append_trend_run with None does not trim**
    ///
    /// When max_runs is None, no trimming should occur.
    ///
    /// Invariant: max_runs=None means unlimited
    #[test]
    fn append_trend_run_max_runs_none_unlimited(
        history in arb_trend_history(),
        run in arb_trend_run()
    ) {
        let result = append_trend_run(history.clone(), run, None);
        prop_assert_eq!(
            result.runs.len(),
            history.runs.len() + 1,
            "max_runs=None should not trim any entries"
        );
    }

    // ========================================================================
    // Property 8: summarize_trend_history TOTALS are correct
    // ========================================================================

    /// **Property 8: summarize_trend_history totals accuracy**
    ///
    /// The totals in the summary SHALL equal the sum of corresponding
    /// counts across all runs.
    ///
    /// Invariant: totals.info = sum(run.counts.info for all runs), etc.
    #[test]
    fn summarize_totals_match_sum(history in arb_trend_history()) {
        let summary = summarize_trend_history(&history);

        let _expected_totals = VerdictCounts {
            info: history.runs.iter().map(|r| r.counts.info).sum(),
            warn: history.runs.iter().map(|r| r.counts.warn).sum(),
            error: history.runs.iter().map(|r| r.counts.error).sum(),
            suppressed: history.runs.iter().map(|r| r.counts.suppressed).sum(),
        };

        // Use saturating_add to match implementation behavior
        let mut actual_totals = VerdictCounts::default();
        for run in &history.runs {
            actual_totals.info = actual_totals.info.saturating_add(run.counts.info);
            actual_totals.warn = actual_totals.warn.saturating_add(run.counts.warn);
            actual_totals.error = actual_totals.error.saturating_add(run.counts.error);
            actual_totals.suppressed = actual_totals.suppressed.saturating_add(run.counts.suppressed);
        }

        prop_assert_eq!(
            summary.totals.info, actual_totals.info,
            "info total mismatch"
        );
        prop_assert_eq!(
            summary.totals.warn, actual_totals.warn,
            "warn total mismatch"
        );
        prop_assert_eq!(
            summary.totals.error, actual_totals.error,
            "error total mismatch"
        );
        prop_assert_eq!(
            summary.totals.suppressed, actual_totals.suppressed,
            "suppressed total mismatch"
        );
    }

    /// **Property 8b: summarize_trend_history total_findings accuracy**
    ///
    /// The total_findings SHALL equal the sum of findings across all runs.
    ///
    /// Invariant: total_findings = sum(run.findings for all runs)
    #[test]
    fn summarize_total_findings_matches_sum(history in arb_trend_history()) {
        let summary = summarize_trend_history(&history);

        let _expected_total_findings: u32 = history.runs.iter().map(|r| r.findings).sum();

        // Use saturating_add to match implementation behavior
        let actual_total_findings: u32 = history.runs.iter()
            .fold(0u32, |acc, r| acc.saturating_add(r.findings));

        prop_assert_eq!(
            summary.total_findings, actual_total_findings,
            "total_findings mismatch: expected {}, got {}",
            actual_total_findings, summary.total_findings
        );
    }

    // ========================================================================
    // Property 9: summarize_trend_history run_count is correct
    // ========================================================================

    /// **Property 9: summarize_trend_history run_count accuracy**
    ///
    /// The run_count in the summary SHALL equal the number of runs in history.
    ///
    /// Invariant: run_count = history.runs.len()
    #[test]
    fn summarize_run_count_matches_history(history in arb_trend_history()) {
        let summary = summarize_trend_history(&history);
        prop_assert_eq!(
            summary.run_count as usize, history.runs.len(),
            "run_count should match history.runs.len()"
        );
    }

    // ========================================================================
    // Property 10: summarize_trend_history latest is LAST run
    // ========================================================================

    /// **Property 10: summarize_trend_history latest is most recent run**
    ///
    /// When history is non-empty, summary.latest SHALL be the last run
    /// in chronological order (last element of runs vector).
    ///
    /// Invariant: latest = runs.last()
    #[test]
    fn summarize_latest_is_last_run(history in arb_trend_history()) {
        let summary = summarize_trend_history(&history);

        if history.runs.is_empty() {
            prop_assert!(
                summary.latest.is_none(),
                "Empty history should have no latest run"
            );
        } else {
            let expected_latest = &history.runs[history.runs.len() - 1];
            prop_assert_eq!(
                summary.latest.as_ref(),
                Some(expected_latest),
                "latest should be the last run in history"
            );
        }
    }

    // ========================================================================
    // Property 11: false_positive_fingerprint_set preserves all fingerprints
    // ========================================================================

    /// **Property 11: false_positive_fingerprint_set preserves all fingerprints**
    ///
    /// The fingerprint set SHALL contain exactly one entry for each unique
    /// fingerprint in the baseline, with no additions or omissions.
    ///
    /// Invariant: set.len() = unique fingerprints in baseline
    #[test]
    fn fingerprint_set_preserves_all_fingerprints(baseline in arb_false_positive_baseline()) {
        let set = false_positive_fingerprint_set(&baseline);

        // Collect unique fingerprints from baseline entries
        let mut unique_fps: Vec<_> = baseline.entries.iter().map(|e| e.fingerprint.clone()).collect();
        unique_fps.sort();
        unique_fps.dedup();

        prop_assert_eq!(
            set.len(), unique_fps.len(),
            "Fingerprint set should contain exactly one entry per unique fingerprint"
        );

        // Every entry's fingerprint should be in the set
        for entry in &baseline.entries {
            prop_assert!(
                set.contains(&entry.fingerprint),
                "Entry fingerprint {:?} should be in set", entry.fingerprint
            );
        }
    }

    // ========================================================================
    // Property 12: Serialization round-trip for FalsePositiveBaseline
    // ========================================================================

    /// **Property 12: FalsePositiveBaseline JSON round-trip**
    ///
    /// Serializing a baseline to JSON and deserializing it back SHALL produce
    /// an equivalent value.
    ///
    /// Invariant: Round-trip (serialize then deserialize = identity)
    #[test]
    fn baseline_json_roundtrip(baseline in arb_false_positive_baseline()) {
        let json = serde_json::to_string(&baseline)
            .expect("Baseline should serialize to JSON");
        let deserialized: FalsePositiveBaseline = serde_json::from_str(&json)
            .expect("JSON should deserialize to Baseline");

        prop_assert_eq!(
            baseline, deserialized,
            "FalsePositiveBaseline round-trip should preserve all data"
        );
    }

    // ========================================================================
    // Property 13: Serialization round-trip for TrendHistory
    // ========================================================================

    /// **Property 13: TrendHistory JSON round-trip**
    ///
    /// Serializing trend history to JSON and deserializing it back SHALL produce
    /// an equivalent value.
    ///
    /// Invariant: Round-trip (serialize then deserialize = identity)
    #[test]
    fn trend_history_json_roundtrip(history in arb_trend_history()) {
        let json = serde_json::to_string(&history)
            .expect("TrendHistory should serialize to JSON");
        let deserialized: TrendHistory = serde_json::from_str(&json)
            .expect("JSON should deserialize to TrendHistory");

        prop_assert_eq!(
            history, deserialized,
            "TrendHistory round-trip should preserve all data"
        );
    }

    // ========================================================================
    // Property 14: Serialization round-trip for TrendRun
    // ========================================================================

    /// **Property 14: TrendRun JSON round-trip**
    ///
    /// Serializing a trend run to JSON and deserializing it back SHALL produce
    /// an equivalent value.
    ///
    /// Invariant: Round-trip (serialize then deserialize = identity)
    #[test]
    fn trend_run_json_roundtrip(run in arb_trend_run()) {
        let json = serde_json::to_string(&run)
            .expect("TrendRun should serialize to JSON");
        let deserialized: TrendRun = serde_json::from_str(&json)
            .expect("JSON should deserialize to TrendRun");

        prop_assert_eq!(
            run, deserialized,
            "TrendRun round-trip should preserve all data"
        );
    }

    // ========================================================================
    // Property 15: normalize does not lose entries
    // ========================================================================

    /// **Property 15: normalize_false_positive_baseline preserves entries**
    ///
    /// After normalization, all non-duplicate entries SHALL still be present.
    ///
    /// Invariant: entries are sorted/deduped but not lost
    #[test]
    fn normalize_baseline_preserves_unique_entries(baseline in arb_false_positive_baseline()) {
        // Count unique fingerprints before
        let unique_fps: std::collections::BTreeSet<_> = baseline
            .entries
            .iter()
            .map(|e| e.fingerprint.clone())
            .collect();

        let unique_count = unique_fps.len();
        let normalized = normalize_false_positive_baseline(baseline);

        prop_assert_eq!(
            normalized.entries.len(), unique_count,
            "Normalized baseline should have exactly one entry per unique fingerprint"
        );
    }

    // ========================================================================
    // Property 16: trend_run_from_receipt preserves counts
    // ========================================================================

    /// **Property 16: trend_run_from_receipt preserves verdict counts**
    ///
    /// The TrendRun created from a receipt SHALL have the same counts
    /// as the receipt's verdict.
    ///
    /// Invariant: counts preserved from receipt to trend run
    #[test]
    fn trend_run_preserves_counts(receipt in arb_check_receipt()) {
        let run = trend_run_from_receipt(
            &receipt,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:01:00Z",
            60000,
        );

        prop_assert_eq!(
            run.counts.info, receipt.verdict.counts.info,
            "info count should be preserved"
        );
        prop_assert_eq!(
            run.counts.warn, receipt.verdict.counts.warn,
            "warn count should be preserved"
        );
        prop_assert_eq!(
            run.counts.error, receipt.verdict.counts.error,
            "error count should be preserved"
        );
        prop_assert_eq!(
            run.counts.suppressed, receipt.verdict.counts.suppressed,
            "suppressed count should be preserved"
        );
    }

    // ========================================================================
    // Property 17: trend_run_from_receipt findings count matches
    // ========================================================================

    /// **Property 17: trend_run_from_receipt findings count matches receipt**
    ///
    /// The findings count in the TrendRun SHALL equal the number of findings
    /// in the receipt.
    ///
    /// Invariant: findings.len() in receipt = findings in trend run
    #[test]
    fn trend_run_findings_count_matches(receipt in arb_check_receipt()) {
        let run = trend_run_from_receipt(
            &receipt,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:01:00Z",
            60000,
        );

        let expected_findings = receipt.findings.len() as u32;
        prop_assert_eq!(
            run.findings, expected_findings,
            "TrendRun findings should match receipt findings count"
        );
    }
}

// ============================================================================
// Additional Classical (non-proptest) Tests for Edge Cases
// ============================================================================

#[test]
fn test_fingerprint_produces_valid_sha256_hex() {
    // Very long strings should still produce valid 64-char hex
    let finding = Finding {
        rule_id: "x".repeat(1000),
        severity: Severity::Error,
        message: "y".repeat(1000),
        path: "z".repeat(1000),
        line: 9999,
        column: Some(999),
        match_text: "w".repeat(1000),
        snippet: "v".repeat(1000),
    };

    let fp = fingerprint_for_finding(&finding);
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_normalize_with_empty_schema_sets_v1() {
    let baseline = FalsePositiveBaseline {
        schema: String::new(),
        entries: vec![],
    };

    let normalized = normalize_false_positive_baseline(baseline);
    assert_eq!(normalized.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
}

#[test]
fn test_normalize_trend_history_with_empty_schema_sets_v1() {
    let history = TrendHistory {
        schema: String::new(),
        runs: vec![],
    };

    let normalized = normalize_trend_history(history);
    assert_eq!(normalized.schema, TREND_HISTORY_SCHEMA_V1);
}

#[test]
fn test_summarize_empty_history_has_no_delta() {
    let history = TrendHistory::default();
    let summary = summarize_trend_history(&history);

    assert_eq!(summary.run_count, 0);
    assert!(summary.delta_from_previous.is_none());
    assert!(summary.latest.is_none());
}

#[test]
fn test_summarize_single_run_has_no_delta() {
    let run = TrendRun {
        started_at: "2026-01-01T00:00:00Z".to_string(),
        ended_at: "2026-01-01T00:01:00Z".to_string(),
        duration_ms: 60000,
        base: "origin/main".to_string(),
        head: "HEAD".to_string(),
        scope: Scope::Added,
        status: VerdictStatus::Pass,
        counts: VerdictCounts {
            info: 1,
            warn: 2,
            error: 3,
            suppressed: 4,
        },
        files_scanned: 10,
        lines_scanned: 500,
        findings: 5,
    };

    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run],
    };

    let summary = summarize_trend_history(&history);
    assert_eq!(summary.run_count, 1);
    assert!(summary.delta_from_previous.is_none());
}

#[test]
fn test_summarize_two_runs_has_delta() {
    let run1 = TrendRun {
        started_at: "2026-01-01T00:00:00Z".to_string(),
        ended_at: "2026-01-01T00:01:00Z".to_string(),
        duration_ms: 60000,
        base: "origin/main".to_string(),
        head: "HEAD~1".to_string(),
        scope: Scope::Added,
        status: VerdictStatus::Pass,
        counts: VerdictCounts {
            info: 1,
            warn: 2,
            error: 3,
            suppressed: 4,
        },
        files_scanned: 10,
        lines_scanned: 500,
        findings: 5,
    };

    let run2 = TrendRun {
        started_at: "2026-01-02T00:00:00Z".to_string(),
        ended_at: "2026-01-02T00:01:00Z".to_string(),
        duration_ms: 60000,
        base: "origin/main".to_string(),
        head: "HEAD".to_string(),
        scope: Scope::Added,
        status: VerdictStatus::Fail,
        counts: VerdictCounts {
            info: 2,
            warn: 3,
            error: 5,
            suppressed: 6,
        },
        files_scanned: 12,
        lines_scanned: 600,
        findings: 10,
    };

    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run1, run2],
    };

    let summary = summarize_trend_history(&history);
    assert_eq!(summary.run_count, 2);

    let delta = summary.delta_from_previous.expect("Should have delta");
    assert_eq!(delta.findings, 5); // 10 - 5
    assert_eq!(delta.info, 1); // 2 - 1
    assert_eq!(delta.warn, 1); // 3 - 2
    assert_eq!(delta.error, 2); // 5 - 3
    assert_eq!(delta.suppressed, 2); // 6 - 4
}
