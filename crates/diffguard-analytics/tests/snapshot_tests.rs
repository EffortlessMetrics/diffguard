//! Snapshot tests for diffguard-analytics output formats.
//!
//! These tests capture the current output of analytics functions for various scenarios.
//! The snapshots document what the output looks like NOW - any change to the output
//! will be detected by these tests.
//!
//! Coverage:
//! 1. Fingerprint computation (deterministic SHA-256 hex output)
//! 2. Baseline creation (FalsePositiveBaseline JSON)
//! 3. Baseline normalization (idempotent, sorted, deduplicated)
//! 4. Baseline merging (union with preference for existing entries)
//! 5. Fingerprint set extraction
//! 6. Trend run from receipt
//! 7. Trend history append and summarize

use diffguard_analytics::{
    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    TREND_HISTORY_SCHEMA_V1, append_trend_run, baseline_from_receipt,
    false_positive_fingerprint_set, fingerprint_for_finding, merge_false_positive_baselines,
    normalize_false_positive_baseline, summarize_trend_history, trend_run_from_receipt,
};
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};

// ============================================================================
// Helper Functions
// ============================================================================

fn make_finding(rule_id: &str, path: &str, line: u32, match_text: &str) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity: Severity::Error,
        message: "Test message".to_string(),
        path: path.to_string(),
        line,
        column: Some(1),
        match_text: match_text.to_string(),
        snippet: format!("line {} {}", line, match_text),
    }
}

fn make_receipt(findings: Vec<Finding>) -> CheckReceipt {
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
// Fingerprint Snapshot Tests
// ============================================================================

/// Snapshot test for fingerprint computation.
/// The fingerprint is a deterministic SHA-256 hash of rule_id:path:line:match_text.
#[test]
fn snapshot_fingerprint_single_finding() {
    let finding = make_finding("rust.no_unwrap", "src/lib.rs", 42, "unwrap()");
    let fp = fingerprint_for_finding(&finding);
    insta::assert_snapshot!("snapshot_fingerprint_single_finding", fp);
}

/// Snapshot test for fingerprint format validation.
/// Fingerprints should be exactly 64 hex characters.
#[test]
fn snapshot_fingerprint_format() {
    let finding = make_finding("test.rule", "src/main.rs", 1, "test");
    let fp = fingerprint_for_finding(&finding);
    // The fingerprint should be 64 chars (SHA-256 hex)
    let json = serde_json::json!({
        "fingerprint": fp,
        "length": fp.len(),
        "is_valid_hex": fp.chars().all(|c| c.is_ascii_hexdigit())
    });
    insta::assert_snapshot!("snapshot_fingerprint_format", json);
}

/// Snapshot test for fingerprint determinism.
/// Same finding should always produce same fingerprint.
#[test]
fn snapshot_fingerprint_determinism() {
    let finding = make_finding("rust.no_unwrap", "src/lib.rs", 100, "Some(1).unwrap()");
    let fp1 = fingerprint_for_finding(&finding);
    let fp2 = fingerprint_for_finding(&finding);
    let json = serde_json::json!({
        "fp1": fp1,
        "fp2": fp2,
        "are_equal": fp1 == fp2
    });
    insta::assert_snapshot!("snapshot_fingerprint_determinism", json);
}

/// Snapshot test for fingerprint sensitivity.
/// Different fields should produce different fingerprints.
#[test]
fn snapshot_fingerprint_sensitivity() {
    let base = make_finding("rust.no_unwrap", "src/lib.rs", 42, "unwrap()");
    let fp_base = fingerprint_for_finding(&base);

    let different_rule = make_finding("rust.no_debug", "src/lib.rs", 42, "unwrap()");
    let fp_rule = fingerprint_for_finding(&different_rule);

    let different_path = make_finding("rust.no_unwrap", "src/main.rs", 42, "unwrap()");
    let fp_path = fingerprint_for_finding(&different_path);

    let different_line = make_finding("rust.no_unwrap", "src/lib.rs", 100, "unwrap()");
    let fp_line = fingerprint_for_finding(&different_line);

    let different_match = make_finding("rust.no_unwrap", "src/lib.rs", 42, "expect()");
    let fp_match = fingerprint_for_finding(&different_match);

    let json = serde_json::json!({
        "base": fp_base,
        "different_rule": fp_rule,
        "different_path": fp_path,
        "different_line": fp_line,
        "different_match": fp_match,
        "all_different": fp_base != fp_rule && fp_base != fp_path && fp_base != fp_line && fp_base != fp_match
    });
    insta::assert_snapshot!("snapshot_fingerprint_sensitivity", json);
}

// ============================================================================
// Baseline Creation Snapshot Tests
// ============================================================================

/// Snapshot test for baseline creation from receipt with no findings.
#[test]
fn snapshot_baseline_empty_findings() {
    let receipt = make_receipt(vec![]);
    let baseline = baseline_from_receipt(&receipt);
    let json = serde_json::to_string_pretty(&baseline).expect("serialize baseline");
    insta::assert_snapshot!("snapshot_baseline_empty_findings", json);
}

/// Snapshot test for baseline creation from receipt with single finding.
#[test]
fn snapshot_baseline_single_finding() {
    let finding = make_finding("rust.no_unwrap", "src/lib.rs", 42, "unwrap()");
    let receipt = make_receipt(vec![finding]);
    let baseline = baseline_from_receipt(&receipt);
    let json = serde_json::to_string_pretty(&baseline).expect("serialize baseline");
    insta::assert_snapshot!("snapshot_baseline_single_finding", json);
}

/// Snapshot test for baseline creation from receipt with multiple findings.
#[test]
fn snapshot_baseline_multiple_findings() {
    let findings = vec![
        make_finding("rust.no_unwrap", "src/lib.rs", 42, "unwrap()"),
        make_finding("rust.no_debug", "src/main.rs", 10, "dbg!()"),
    ];
    let receipt = make_receipt(findings);
    let baseline = baseline_from_receipt(&receipt);
    let json = serde_json::to_string_pretty(&baseline).expect("serialize baseline");
    insta::assert_snapshot!("snapshot_baseline_multiple_findings", json);
}

/// Snapshot test for baseline deduplication.
/// Duplicate findings should result in single entry.
#[test]
fn snapshot_baseline_deduplication() {
    let finding = make_finding("rust.no_unwrap", "src/lib.rs", 42, "unwrap()");
    let receipt = make_receipt(vec![finding.clone(), finding.clone(), finding]);
    let baseline = baseline_from_receipt(&receipt);
    let json = serde_json::to_string_pretty(&baseline).expect("serialize baseline");
    insta::assert_snapshot!("snapshot_baseline_deduplication", json);
}

// ============================================================================
// Baseline Normalization Snapshot Tests
// ============================================================================

/// Snapshot test for baseline normalization - sets schema if empty.
#[test]
fn snapshot_normalize_sets_schema() {
    let baseline = FalsePositiveBaseline {
        schema: String::new(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "abc123".to_string(),
            rule_id: "test.rule".to_string(),
            path: "test.rs".to_string(),
            line: 1,
            note: None,
        }],
    };
    let normalized = normalize_false_positive_baseline(baseline);
    insta::assert_snapshot!("snapshot_normalize_sets_schema", normalized.schema);
}

/// Snapshot test for baseline normalization - sorts entries.
#[test]
fn snapshot_normalize_sorts_entries() {
    let baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "zzz".to_string(),
                rule_id: "z.rule".to_string(),
                path: "z.rs".to_string(),
                line: 3,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "aaa".to_string(),
                rule_id: "a.rule".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "mmm".to_string(),
                rule_id: "m.rule".to_string(),
                path: "m.rs".to_string(),
                line: 2,
                note: None,
            },
        ],
    };
    let normalized = normalize_false_positive_baseline(baseline);
    let json = serde_json::to_string_pretty(&normalized).expect("serialize baseline");
    insta::assert_snapshot!("snapshot_normalize_sorts_entries", json);
}

/// Snapshot test for baseline normalization - idempotent.
#[test]
fn snapshot_normalize_idempotent() {
    let baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "abc123".to_string(),
            rule_id: "test.rule".to_string(),
            path: "test.rs".to_string(),
            line: 1,
            note: Some("note".to_string()),
        }],
    };
    let normalized1 = normalize_false_positive_baseline(baseline.clone());
    let normalized2 = normalize_false_positive_baseline(normalized1.clone());
    insta::assert_snapshot!("snapshot_normalize_idempotent", normalized1 == normalized2);
}

// ============================================================================
// Baseline Merge Snapshot Tests
// ============================================================================

/// Snapshot test for baseline merge - union of fingerprints.
#[test]
fn snapshot_merge_union() {
    let base = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "aaa".to_string(),
            rule_id: "a.rule".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: None,
        }],
    };
    let incoming = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "bbb".to_string(),
            rule_id: "b.rule".to_string(),
            path: "b.rs".to_string(),
            line: 2,
            note: None,
        }],
    };
    let merged = merge_false_positive_baselines(&base, &incoming);
    let json = serde_json::to_string_pretty(&merged).expect("serialize baseline");
    insta::assert_snapshot!("snapshot_merge_union", json);
}

/// Snapshot test for baseline merge - prefers existing entries.
#[test]
fn snapshot_merge_prefers_existing() {
    let base = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "aaa".to_string(),
            rule_id: "a.rule".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: Some("existing note".to_string()),
        }],
    };
    let incoming = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "aaa".to_string(),
            rule_id: "a.rule".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: None, // No note - existing should be preserved
        }],
    };
    let merged = merge_false_positive_baselines(&base, &incoming);
    let note_value = format!("{:?}", merged.entries[0].note.as_deref());
    insta::assert_snapshot!("snapshot_merge_prefers_existing", note_value);
}

/// Snapshot test for baseline merge - deduplicates by fingerprint.
#[test]
fn snapshot_merge_deduplication() {
    let base = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "aaa".to_string(),
            rule_id: "a.rule".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: None,
        }],
    };
    let incoming = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "aaa".to_string(),
                rule_id: "a.rule".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "bbb".to_string(),
                rule_id: "b.rule".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
        ],
    };
    let merged = merge_false_positive_baselines(&base, &incoming);
    insta::assert_snapshot!("snapshot_merge_deduplication", merged.entries.len());
}

// ============================================================================
// Fingerprint Set Snapshot Tests
// ============================================================================

/// Snapshot test for fingerprint set extraction.
#[test]
fn snapshot_fingerprint_set() {
    let baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "aaa111".to_string(),
                rule_id: "a.rule".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "bbb222".to_string(),
                rule_id: "b.rule".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
        ],
    };
    let set = false_positive_fingerprint_set(&baseline);
    let json = serde_json::json!({
        "fingerprints": set.iter().collect::<Vec<_>>(),
        "count": set.len()
    });
    insta::assert_snapshot!("snapshot_fingerprint_set", json);
}

// ============================================================================
// Trend Snapshot Tests
// ============================================================================

/// Snapshot test for trend run creation from receipt.
#[test]
fn snapshot_trend_run_from_receipt() {
    let findings = vec![make_finding("rust.no_unwrap", "src/lib.rs", 42, "unwrap()")];
    let receipt = make_receipt(findings);
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );
    let json = serde_json::to_string_pretty(&run).expect("serialize run");
    insta::assert_snapshot!("snapshot_trend_run_from_receipt", json);
}

/// Snapshot test for appending trend run to history.
#[test]
fn snapshot_append_trend_run() {
    let findings = vec![make_finding("rust.no_unwrap", "src/lib.rs", 42, "unwrap()")];
    let receipt = make_receipt(findings);
    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );

    let history = diffguard_analytics::TrendHistory::default();
    let history = append_trend_run(history, run, None);
    let json = serde_json::to_string_pretty(&history).expect("serialize history");
    insta::assert_snapshot!("snapshot_append_trend_run", json);
}

/// Snapshot test for appending trend run with max limit.
#[test]
fn snapshot_append_trend_run_with_limit() {
    let findings = vec![make_finding("rust.no_unwrap", "src/lib.rs", 42, "unwrap()")];
    let receipt = make_receipt(findings);

    let history = diffguard_analytics::TrendHistory::default();
    let history = append_trend_run(
        history,
        trend_run_from_receipt(
            &receipt,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:01Z",
            1000,
        ),
        Some(2),
    );
    let history = append_trend_run(
        history,
        trend_run_from_receipt(
            &receipt,
            "2026-01-01T00:00:02Z",
            "2026-01-01T00:00:03Z",
            1000,
        ),
        Some(2),
    );
    let history = append_trend_run(
        history,
        trend_run_from_receipt(
            &receipt,
            "2026-01-01T00:00:04Z",
            "2026-01-01T00:00:05Z",
            1000,
        ),
        Some(2),
    );

    insta::assert_snapshot!("snapshot_append_trend_run_with_limit", history.runs.len());
}

/// Snapshot test for trend history summarization.
#[test]
fn snapshot_summarize_trend_history() {
    let findings = vec![make_finding("rust.no_unwrap", "src/lib.rs", 42, "unwrap()")];
    let receipt = make_receipt(findings);

    let run1 = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );
    let mut run2 = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:02Z",
        "2026-01-01T00:00:03Z",
        1000,
    );
    run2.counts.error = 2;
    run2.findings = 2;

    let history = diffguard_analytics::TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run1, run2],
    };
    let summary = summarize_trend_history(&history);
    let json = serde_json::to_string_pretty(&summary).expect("serialize summary");
    insta::assert_snapshot!("snapshot_summarize_trend_history", json);
}

/// Snapshot test for trend summary with no previous run (no delta).
#[test]
fn snapshot_summarize_single_run() {
    let findings = vec![make_finding("rust.no_unwrap", "src/lib.rs", 42, "unwrap()")];
    let receipt = make_receipt(findings);

    let run = trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:01Z",
        1000,
    );

    let history = diffguard_analytics::TrendHistory {
        schema: TREND_HISTORY_SCHEMA_V1.to_string(),
        runs: vec![run],
    };
    let summary = summarize_trend_history(&history);
    let json = serde_json::to_string_pretty(&summary).expect("serialize summary");
    insta::assert_snapshot!("snapshot_summarize_single_run", json);
}
