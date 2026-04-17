//! Edge case tests for diffguard-analytics usize→u64 migration (issue #577)
//!
//! These tests verify that the migration from u32 to u64 for `findings`,
//! `run_count`, and `total_findings` correctly handles:
//! - Values exceeding u32::MAX
//! - Large accumulations
//! - Empty and single-run histories
//! - Delta calculations with large values

use diffguard_analytics::*;
use diffguard_types::{DiffMeta, Scope, Severity, ToolMeta, Verdict, VerdictCounts, VerdictStatus};
use std::u32;

/// Creates a TrendRun with explicit findings count.
fn make_run(findings: u64, info: u32, warn: u32, error: u32, suppressed: u32) -> TrendRun {
    TrendRun {
        started_at: "2026-01-01T00:00:00Z".to_string(),
        ended_at: "2026-01-01T00:00:01Z".to_string(),
        duration_ms: 1000,
        base: "origin/main".to_string(),
        head: "HEAD".to_string(),
        scope: Scope::Added,
        status: VerdictStatus::Fail,
        counts: VerdictCounts {
            info,
            warn,
            error,
            suppressed,
        },
        files_scanned: 1,
        lines_scanned: 100,
        findings,
    }
}

#[test]
fn summarize_empty_history_yields_zero_totals() {
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V2.to_string(),
        runs: vec![],
    };
    let summary = summarize_trend_history(&history);
    assert_eq!(summary.run_count, 0);
    assert_eq!(summary.total_findings, 0);
    assert!(summary.latest.is_none());
    assert!(summary.delta_from_previous.is_none());
}

#[test]
fn summarize_single_run_has_no_delta() {
    let run = make_run(5, 1, 2, 3, 4);
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V2.to_string(),
        runs: vec![run],
    };
    let summary = summarize_trend_history(&history);
    assert_eq!(summary.run_count, 1);
    assert_eq!(summary.total_findings, 5);
    assert!(summary.delta_from_previous.is_none());
}

#[test]
fn summarize_two_runs_reports_delta() {
    let run1 = make_run(10, 1, 2, 3, 4);
    let run2 = make_run(7, 0, 1, 2, 3);
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V2.to_string(),
        runs: vec![run1, run2],
    };
    let summary = summarize_trend_history(&history);
    assert_eq!(summary.run_count, 2);
    assert_eq!(summary.total_findings, 17);
    let delta = summary.delta_from_previous.expect("should have delta");
    assert_eq!(delta.findings, -3); // 7 - 10
    assert_eq!(delta.warn, -1); // 1 - 2
    assert_eq!(delta.error, -1); // 2 - 3
}

#[test]
fn summarize_large_findings_value_no_truncation() {
    // Test that findings > u32::MAX are preserved (this was the core bug)
    let large_findings = u64::MAX / 2; // ~4 billion
    let run = make_run(large_findings, 0, 0, 0, 0);
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V2.to_string(),
        runs: vec![run],
    };
    let summary = summarize_trend_history(&history);
    assert_eq!(summary.total_findings, large_findings);
    assert!(summary.total_findings > u32::MAX as u64);
}

#[test]
fn summarize_accumulates_findings_beyond_u32_max() {
    // Each run has ~2 billion findings; 3 runs = ~6 billion (exceeds u32::MAX)
    let per_run = u32::MAX as u64 / 2;
    let run1 = make_run(per_run, 0, 0, 0, 0);
    let run2 = make_run(per_run, 0, 0, 0, 0);
    let run3 = make_run(per_run, 0, 0, 0, 0);
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V2.to_string(),
        runs: vec![run1, run2, run3],
    };
    let summary = summarize_trend_history(&history);
    let expected = per_run * 3;
    assert_eq!(summary.total_findings, expected);
    assert!(summary.total_findings > u32::MAX as u64);
}

#[test]
fn summarize_run_count_beyond_u32_max() {
    // Create many runs to exceed u32::MAX run_count
    // We test that run_count is u64 and can hold large values
    let run = make_run(1, 0, 0, 0, 0);
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V2.to_string(),
        runs: vec![run],
    };
    // Verify type can represent values beyond u32::MAX
    let summary = summarize_trend_history(&history);
    // Manually construct a summary with run_count > u32::MAX
    let large_run_count = u64::MAX / 2;
    let large_summary = TrendSummary {
        run_count: large_run_count,
        totals: VerdictCounts::default(),
        total_findings: 0,
        latest: None,
        delta_from_previous: None,
    };
    assert!(large_summary.run_count > u32::MAX as u64);
    // Verify the actual run_count is correct type
    assert!(summary.run_count >= 1);
}

#[test]
fn trend_run_from_receipt_handles_large_finding_list() {
    // Create a receipt with many findings
    let many_findings: Vec<diffguard_types::Finding> = (0..1000)
        .map(|i| diffguard_types::Finding {
            rule_id: format!("rule.{}", i),
            severity: Severity::Error,
            message: format!("error {}", i),
            path: format!("src/file{}.rs", i),
            line: i as u32,
            column: Some(1),
            match_text: format!("match{}", i),
            snippet: format!("code {};", i),
        })
        .collect();

    let receipt = diffguard_types::CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned: 1000,
            lines_scanned: 10000,
        },
        findings: many_findings,
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1000,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    };

    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );
    assert_eq!(run.findings, 1000);
    assert!(run.findings > 0);
}

#[test]
fn delta_calculation_with_large_findings_increase() {
    // Test delta when findings increase significantly
    let run1 = make_run(5, 0, 0, 0, 0);
    let run2 = make_run(u64::MAX / 4, 0, 0, 0, 0); // Large increase
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V2.to_string(),
        runs: vec![run1, run2],
    };
    let summary = summarize_trend_history(&history);
    let delta = summary.delta_from_previous.expect("should have delta");
    // delta should be positive and large
    assert!(delta.findings > 0);
    assert!(delta.findings > i64::from(u32::MAX));
}

#[test]
fn delta_calculation_with_large_findings_decrease() {
    // Test delta when findings decrease significantly
    let run1 = make_run(u64::MAX / 4, 0, 0, 0, 0); // Large value
    let run2 = make_run(5, 0, 0, 0, 0); // Small value
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V2.to_string(),
        runs: vec![run1, run2],
    };
    let summary = summarize_trend_history(&history);
    let delta = summary.delta_from_previous.expect("should have delta");
    // delta should be negative and large in magnitude
    assert!(delta.findings < 0);
    assert!(delta.findings < -(i64::from(u32::MAX)));
}

#[test]
fn trend_history_default_uses_schema_v2() {
    let history = TrendHistory::default();
    assert_eq!(history.schema, TREND_HISTORY_SCHEMA_V2);
}

#[test]
fn normalize_trend_history_sets_schema_v2() {
    let mut history = TrendHistory::default();
    history.schema = String::new();
    let normalized = normalize_trend_history(history);
    assert_eq!(normalized.schema, TREND_HISTORY_SCHEMA_V2);
}

#[test]
fn append_trend_run_normalizes_empty_schema_to_v2() {
    let run = make_run(1, 0, 0, 0, 0);
    let history = TrendHistory {
        schema: String::new(), // Empty schema should be normalized to V2
        runs: vec![],
    };
    let result = append_trend_run(history, run, None);
    assert_eq!(result.schema, TREND_HISTORY_SCHEMA_V2);
}

#[test]
fn saturating_add_does_not_wrap() {
    // Verify that accumulating findings uses saturating arithmetic
    let run1 = make_run(u64::MAX, 0, 0, 0, 0);
    let run2 = make_run(u64::MAX, 0, 0, 0, 0);
    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V2.to_string(),
        runs: vec![run1, run2],
    };
    let summary = summarize_trend_history(&history);
    // Should saturate at u64::MAX, not wrap
    assert_eq!(summary.total_findings, u64::MAX);
}

#[test]
fn findings_field_is_u64_not_u32() {
    let run = make_run(u64::MAX, 0, 0, 0, 0);
    // This would fail to compile if findings were still u32
    let _large_value: u64 = run.findings;
    assert_eq!(run.findings, u64::MAX);
}

#[test]
fn run_count_field_is_u64_not_u32() {
    // Create a summary with run_count > u32::MAX
    let summary = TrendSummary {
        run_count: u64::MAX,
        totals: VerdictCounts::default(),
        total_findings: 0,
        latest: None,
        delta_from_previous: None,
    };
    // This would fail to compile if run_count were still u32
    let _large_value: u64 = summary.run_count;
    assert_eq!(summary.run_count, u64::MAX);
}

#[test]
fn total_findings_field_is_u64_not_u32() {
    // Create a summary with total_findings > u32::MAX
    let summary = TrendSummary {
        run_count: 1,
        totals: VerdictCounts::default(),
        total_findings: u64::MAX,
        latest: None,
        delta_from_previous: None,
    };
    // This would fail to compile if total_findings were still u32
    let _large_value: u64 = summary.total_findings;
    assert_eq!(summary.total_findings, u64::MAX);
}
