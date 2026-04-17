//! Snapshot tests for diffguard-analytics public API outputs.
//!
//! These tests capture the structured output (JSON-serializable) of the crate's
//! public API functions for representative inputs. Any change to output format
//! or normalization behavior will be detected immediately by snapshot failures.
//!
//! Snapshot tests are NOT regression tests — a failure means the output changed,
//! not that it's wrong. The reviewer must decide if the change is intentional.

use diffguard_analytics::{
    append_trend_run, baseline_from_receipt, false_positive_fingerprint_set,
    fingerprint_for_finding, merge_false_positive_baselines, normalize_false_positive_baseline,
    summarize_trend_history, trend_run_from_receipt, FalsePositiveBaseline, FalsePositiveEntry,
    TrendHistory, FALSE_POSITIVE_BASELINE_SCHEMA_V1, TREND_HISTORY_SCHEMA_V1,
};
use diffguard_types::{CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
                       VerdictCounts, VerdictStatus};
use insta::{assert_json_snapshot, assert_snapshot};

// ---------------------------------------------------------------------------
// Deterministic test fixtures
// ---------------------------------------------------------------------------

/// A minimal receipt with one finding — used across most snapshot tests.
fn receipt_with_one_finding() -> CheckReceipt {
    CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "abc123".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 12,
            lines_scanned: 500,
        },
        findings: vec![Finding {
            rule_id: "rust.no_unwrap".to_string(),
            severity: Severity::Error,
            message: "avoid unwrap".to_string(),
            path: "src/lib.rs".to_string(),
            line: 42,
            column: Some(8),
            match_text: ".unwrap()".to_string(),
            snippet: "let x = y.unwrap();".to_string(),
        }],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 1,
                error: 1,
                suppressed: 5,
            },
            reasons: vec!["has_error".to_string()],
        },
        timing: None,
    }
}

/// A receipt with multiple findings at different paths/lines.
fn receipt_with_multiple_findings() -> CheckReceipt {
    CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "def456".to_string(),
            context_lines: 3,
            scope: Scope::Changed,
            files_scanned: 8,
            lines_scanned: 300,
        },
        findings: vec![
            Finding {
                rule_id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "avoid unwrap".to_string(),
                path: "src/lib.rs".to_string(),
                line: 10,
                column: Some(4),
                match_text: ".unwrap()".to_string(),
                snippet: "let x = y.unwrap();".to_string(),
            },
            Finding {
                rule_id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "avoid unwrap".to_string(),
                path: "src/main.rs".to_string(),
                line: 99,
                column: Some(12),
                match_text: ".unwrap()".to_string(),
                snippet: "result.unwrap()".to_string(),
            },
            Finding {
                rule_id: "go.no_error_panic".to_string(),
                severity: Severity::Warn,
                message: "consider handling error".to_string(),
                path: "handler.go".to_string(),
                line: 55,
                column: Some(20),
                match_text: "panic(".to_string(),
                snippet: "panic(\"unrecoverable\")".to_string(),
            },
        ],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 1,
                error: 2,
                suppressed: 0,
            },
            reasons: vec!["has_error".to_string(), "has_warning".to_string()],
        },
        timing: None,
    }
}

// ---------------------------------------------------------------------------
// Snapshot tests — fingerprint_for_finding
// ---------------------------------------------------------------------------

/// Snapshot: SHA-256 hex fingerprint for a single Finding.
/// Format is deterministic: SHA-256 of `rule_id:path:line:match_text`.
#[test]
fn snapshot_fingerprint_for_finding_one_finding() {
    let receipt = receipt_with_one_finding();
    let fp = fingerprint_for_finding(&receipt.findings[0]);
    assert_snapshot!("fingerprint_one_finding", fp);
}

/// Snapshot: SHA-256 hex fingerprint for a Finding with special characters in path.
/// Tests that path with spaces, dots, dashes is handled correctly.
#[test]
fn snapshot_fingerprint_for_finding_special_path() {
    let finding = Finding {
        rule_id: "py.bare-except".to_string(),
        severity: Severity::Warn,
        message: "bare except".to_string(),
        path: "src/mymodule.test.py".to_string(),
        line: 7,
        column: Some(1),
        match_text: "except:".to_string(),
        snippet: "except: pass".to_string(),
    };
    let fp = fingerprint_for_finding(&finding);
    assert_snapshot!("fingerprint_special_path", fp);
}

/// Snapshot: two findings produce different fingerprints.
#[test]
fn snapshot_fingerprints_are_unique() {
    let receipt = receipt_with_multiple_findings();
    let fps: Vec<_> = receipt
        .findings
        .iter()
        .map(fingerprint_for_finding)
        .collect();
    assert_json_snapshot!("fingerprints_unique", fps);
}

// ---------------------------------------------------------------------------
// Snapshot tests — baseline_from_receipt
// ---------------------------------------------------------------------------

/// Snapshot: baseline JSON for receipt with one finding.
/// Captures: schema, entries[].fingerprint, rule_id, path, line, note (None).
#[test]
fn snapshot_baseline_from_receipt_one_finding() {
    let receipt = receipt_with_one_finding();
    let baseline = baseline_from_receipt(&receipt);
    assert_json_snapshot!("baseline_one_finding", baseline);
}

/// Snapshot: baseline JSON for receipt with multiple findings.
/// Captures: schema, all entries sorted by fingerprint.
#[test]
fn snapshot_baseline_from_receipt_multiple_findings() {
    let receipt = receipt_with_multiple_findings();
    let baseline = baseline_from_receipt(&receipt);
    assert_json_snapshot!("baseline_multiple_findings", baseline);
}

// ---------------------------------------------------------------------------
// Snapshot tests — merge_false_positive_baselines
// ---------------------------------------------------------------------------

/// Snapshot: merge two baselines — incoming has new fingerprints, base has existing.
#[test]
fn snapshot_merge_incoming_new_and_existing() {
    let mut base = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "existing_fp".to_string(),
            rule_id: "rust.no_unwrap".to_string(),
            path: "src/lib.rs".to_string(),
            line: 1,
            note: Some("intentional: allowed here".to_string()),
        }],
    };
    normalize_false_positive_baseline(&mut base);

    let mut incoming = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "incoming_only".to_string(),
            rule_id: "go.no_error_panic".to_string(),
            path: "handler.go".to_string(),
            line: 20,
            note: None,
        }],
    };
    normalize_false_positive_baseline(&mut incoming);

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_json_snapshot!("merge_new_and_existing", merged);
}

/// Snapshot: merge where base fills empty fields in incoming's duplicate entry.
#[test]
fn snapshot_merge_base_fills_empty_fields() {
    let mut base = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "dup_fp".to_string(),
            rule_id: "".to_string(), // empty — should be filled
            path: "".to_string(),    // empty — should be filled
            line: 0,                 // zero — should be filled
            note: Some("base note".to_string()), // base note preserved
        }],
    };
    normalize_false_positive_baseline(&mut base);

    let mut incoming = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "dup_fp".to_string(),
            rule_id: "rust.no_unwrap".to_string(),
            path: "src/lib.rs".to_string(),
            line: 42,
            note: None, // empty — should be filled from base
        }],
    };
    normalize_false_positive_baseline(&mut incoming);

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_json_snapshot!("merge_base_fills_empty", merged);
}

/// Snapshot: merge with empty base (incoming only).
#[test]
fn snapshot_merge_empty_base() {
    let base = FalsePositiveBaseline::default();
    let mut incoming = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "aaa_fp".to_string(),
                rule_id: "py.bare-except".to_string(),
                path: "main.py".to_string(),
                line: 5,
                note: Some("intentional".to_string()),
            },
            FalsePositiveEntry {
                fingerprint: "bbb_fp".to_string(),
                rule_id: "go.no_error_panic".to_string(),
                path: "util.go".to_string(),
                line: 11,
                note: None,
            },
        ],
    };
    normalize_false_positive_baseline(&mut incoming);

    let merged = merge_false_positive_baselines(&base, &incoming);
    assert_json_snapshot!("merge_empty_base", merged);
}

// ---------------------------------------------------------------------------
// Snapshot tests — false_positive_fingerprint_set
// ---------------------------------------------------------------------------

/// Snapshot: fingerprint set from baseline (sorted BTreeSet as JSON array).
#[test]
fn snapshot_fingerprint_set() {
    let receipt = receipt_with_multiple_findings();
    let baseline = baseline_from_receipt(&receipt);
    let fps = false_positive_fingerprint_set(&baseline);
    // Serialize BTreeSet as JSON array for readability
    let fps_vec: Vec<_> = fps.into_iter().collect();
    assert_json_snapshot!("fingerprint_set", fps_vec);
}

// ---------------------------------------------------------------------------
// Snapshot tests — trend_run_from_receipt
// ---------------------------------------------------------------------------

/// Snapshot: TrendRun JSON for a receipt.
#[test]
fn snapshot_trend_run_from_receipt() {
    let receipt = receipt_with_one_finding();
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-15T10:00:00Z",
        "2026-01-15T10:00:05Z",
        5000,
    );
    assert_json_snapshot!("trend_run_one", run);
}

// ---------------------------------------------------------------------------
// Snapshot tests — append_trend_run
// ---------------------------------------------------------------------------

/// Snapshot: append_trend_run trims to max_runs and returns new history.
#[test]
fn snapshot_append_trend_run_trims() {
    let receipt = receipt_with_one_finding();
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-15T10:00:00Z",
        "2026-01-15T10:00:01Z",
        1000,
    );

    let mut history = TrendHistory::default();
    // Append 3 runs with max_runs=2 — should trim to newest 2
    history = append_trend_run(history, run.clone(), Some(2));
    history = append_trend_run(history, run.clone(), Some(2));
    history = append_trend_run(history, run, Some(2));

    assert_json_snapshot!("append_trend_run_trims_to_2", history);
}

/// Snapshot: append_trend_run with no trim limit.
#[test]
fn snapshot_append_trend_run_no_trim() {
    let receipt = receipt_with_multiple_findings();
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-15T12:00:00Z",
        "2026-01-15T12:00:02Z",
        2000,
    );

    let history = append_trend_run(TrendHistory::default(), run, None);
    assert_json_snapshot!("append_trend_run_no_trim", history);
}

// ---------------------------------------------------------------------------
// Snapshot tests — summarize_trend_history
// ---------------------------------------------------------------------------

/// Snapshot: summarize_trend_history with 2 runs (produces delta).
#[test]
fn snapshot_summarize_trend_history_with_delta() {
    let receipt = receipt_with_one_finding();

    let mut run1 = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );
    run1.findings = 5;
    run1.counts.warn = 2;
    run1.counts.error = 3;

    let mut run2 = run1.clone();
    run2.findings = 2;
    run2.counts.warn = 1;
    run2.counts.error = 1;

    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run1, run2],
    };

    let summary = summarize_trend_history(&history);
    assert_json_snapshot!("summarize_with_delta", summary);
}

/// Snapshot: summarize_trend_history with 1 run (no delta).
#[test]
fn snapshot_summarize_trend_history_no_delta() {
    let receipt = receipt_with_one_finding();
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );

    let history = TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run],
    };

    let summary = summarize_trend_history(&history);
    assert_json_snapshot!("summarize_no_delta", summary);
}

/// Snapshot: summarize_trend_history with empty history.
#[test]
fn snapshot_summarize_empty_history() {
    let history = TrendHistory::default();
    let summary = summarize_trend_history(&history);
    assert_json_snapshot!("summarize_empty", summary);
}

// ---------------------------------------------------------------------------
// Snapshot tests — normalize_false_positive_baseline side-effects
// ---------------------------------------------------------------------------

/// Snapshot: normalize_false_positive_baseline sets schema when empty.
/// Since it now returns (), we snapshot the mutated baseline as JSON.
#[test]
fn snapshot_normalize_sets_schema_when_empty() {
    let mut baseline = FalsePositiveBaseline {
        schema: String::new(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "fp1".to_string(),
            rule_id: "rust.no_unwrap".to_string(),
            path: "x.rs".to_string(),
            line: 1,
            note: None,
        }],
    };
    normalize_false_positive_baseline(&mut baseline);
    assert_json_snapshot!("normalize_sets_schema", baseline);
}

/// Snapshot: normalize_false_positive_baseline is idempotent (call twice = same result).
#[test]
fn snapshot_normalize_idempotent() {
    let mut baseline = FalsePositiveBaseline {
        schema: String::new(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "z_fp".to_string(),
                rule_id: "rust.no_unwrap".to_string(),
                path: "z.rs".to_string(),
                line: 10,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "a_fp".to_string(),
                rule_id: "py.bare-except".to_string(),
                path: "a.py".to_string(),
                line: 5,
                note: None,
            },
        ],
    };
    normalize_false_positive_baseline(&mut baseline);
    let after_first = baseline.clone();
    normalize_false_positive_baseline(&mut baseline);
    assert_eq!(baseline, after_first, "normalization must be idempotent");
    assert_json_snapshot!("normalize_idempotent", baseline);
}
