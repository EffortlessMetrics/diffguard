//! Analytics helpers for diffguard.
//!
//! This crate is intentionally pure (no filesystem/process/env I/O).

use std::collections::BTreeSet;

use diffguard_types::{CheckReceipt, Finding, Scope, VerdictCounts, VerdictStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema identifier for version 1 false-positive baseline files.
///
/// Persisted in the `schema` field of [`FalsePositiveBaseline`] to support
/// forward compatibility when the format evolves.
pub const FALSE_POSITIVE_BASELINE_SCHEMA_V1: &str = "diffguard.false_positive_baseline.v1";

/// Schema identifier for version 1 trend history files.
///
/// Persisted in the `schema` field of [`TrendHistory`] to support forward
/// compatibility when the format evolves.
pub const TREND_HISTORY_SCHEMA_V1: &str = "diffguard.trend_history.v1";

/// A set of known false-positive findings used to suppress repeated alerts.
///
/// Each entry represents a single finding that has been reviewed and deemed
/// intentional or acceptable. Baselines are compared by fingerprint so that
/// entries survive edits to rule metadata (e.g., renaming a rule ID).
///
/// Use [`normalize_false_positive_baseline`] before persisting or comparing
/// baselines to guarantee a canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FalsePositiveBaseline {
    /// Schema identifier. Set by [`normalize_false_positive_baseline`] when missing.
    pub schema: String,
    /// Individual false-positive entries. Sorted and deduplicated by
    /// [`normalize_false_positive_baseline`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<FalsePositiveEntry>,
}

impl Default for FalsePositiveBaseline {
    fn default() -> Self {
        Self {
            schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
            entries: vec![],
        }
    }
}

/// A single false-positive finding record.
///
/// The [`fingerprint`] is the primary key. All other fields are supplementary
/// metadata used for human readability and auditability.
///
/// Created manually by a reviewer or generated automatically by
/// [`baseline_from_receipt`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FalsePositiveEntry {
    /// SHA-256 fingerprint of the finding, computed by [`fingerprint_for_finding`].
    pub fingerprint: String,
    /// Rule that triggered this finding (e.g. `"rust.no_unwrap"`).
    pub rule_id: String,
    /// Path to the file containing the finding (relative or absolute).
    pub path: String,
    /// Line number in `path` where the finding occurs (1-indexed).
    pub line: u32,
    /// Optional human-readable note explaining why this is a known false positive.
    /// `base.note` wins when both `base` and `incoming` have `Some` during merge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Deterministically normalizes a false-positive baseline:
/// - ensures schema id is set
/// - sorts entries
/// - deduplicates by fingerprint
#[must_use]
pub fn normalize_false_positive_baseline(
    mut baseline: FalsePositiveBaseline,
) -> FalsePositiveBaseline {
    if baseline.schema.is_empty() {
        baseline.schema = FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string();
    }
    baseline.entries.sort_by(|a, b| {
        a.fingerprint
            .cmp(&b.fingerprint)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
    });
    baseline
        .entries
        .dedup_by(|a, b| a.fingerprint == b.fingerprint);
    baseline
}

/// Computes the stable finding fingerprint used for baseline tracking.
///
/// Format: SHA-256 of `rule_id:path:line:match_text`.
#[must_use]
pub fn fingerprint_for_finding(finding: &Finding) -> String {
    let input = format!(
        "{}:{}:{}:{}",
        finding.rule_id, finding.path, finding.line, finding.match_text
    );
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

/// Builds a baseline from receipt findings.
#[must_use]
pub fn baseline_from_receipt(receipt: &CheckReceipt) -> FalsePositiveBaseline {
    let mut baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: receipt
            .findings
            .iter()
            .map(|f| FalsePositiveEntry {
                fingerprint: fingerprint_for_finding(f),
                rule_id: f.rule_id.clone(),
                path: f.path.clone(),
                line: f.line,
                note: None,
            })
            .collect(),
    };
    baseline = normalize_false_positive_baseline(baseline);
    baseline
}

/// Merges two baselines (union by fingerprint), preferring existing entries in `base`.
pub fn merge_false_positive_baselines(
    base: &FalsePositiveBaseline,
    incoming: &FalsePositiveBaseline,
) -> FalsePositiveBaseline {
    let mut merged = normalize_false_positive_baseline(incoming.clone());
    let mut seen = merged
        .entries
        .iter()
        .map(|e| e.fingerprint.clone())
        .collect::<BTreeSet<_>>();

    for entry in &base.entries {
        if seen.insert(entry.fingerprint.clone()) {
            merged.entries.push(entry.clone());
        } else if let Some(existing) = merged
            .entries
            .iter_mut()
            .find(|e| e.fingerprint == entry.fingerprint)
        {
            // Preserve manually curated metadata from the existing baseline.
            if existing.note.is_none() && entry.note.is_some() {
                existing.note = entry.note.clone();
            }
            if existing.rule_id.is_empty() {
                existing.rule_id = entry.rule_id.clone();
            }
            if existing.path.is_empty() {
                existing.path = entry.path.clone();
            }
            if existing.line == 0 {
                existing.line = entry.line;
            }
        }
    }

    normalize_false_positive_baseline(merged)
}

/// Returns the baseline as a fingerprint set for fast lookup.
///
/// Use this when you need to test whether a given fingerprint is present
/// without iterating the full baseline. The returned set is always empty when
/// the baseline has no entries.
pub fn false_positive_fingerprint_set(baseline: &FalsePositiveBaseline) -> BTreeSet<String> {
    baseline
        .entries
        .iter()
        .map(|e| e.fingerprint.clone())
        .collect()
}

/// A time-series of individual diffguard check runs.
///
/// Each [`TrendRun`] represents a single invocation of diffguard. History is
/// stored in oldest-first order (the first entry is the earliest run).
///
/// Use [`append_trend_run`] to add new entries, and [`summarize_trend_history`]
/// to produce aggregate statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendHistory {
    /// Schema identifier. Set by [`normalize_trend_history`] when missing.
    pub schema: String,
    /// Ordered list of runs, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runs: Vec<TrendRun>,
}

impl Default for TrendHistory {
    fn default() -> Self {
        Self {
            schema: TREND_HISTORY_SCHEMA_V1.to_string(),
            runs: vec![],
        }
    }
}

/// A single diffguard check run, suitable for trend analysis.
///
/// Produced by [`trend_run_from_receipt`] and appended to [`TrendHistory`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendRun {
    /// ISO 8601 timestamp when the run started.
    pub started_at: String,
    /// ISO 8601 timestamp when the run ended.
    pub ended_at: String,
    /// Wall-clock duration of the run in milliseconds.
    pub duration_ms: u64,
    /// Git ref (branch name, tag, or commit) at the base of the diff.
    pub base: String,
    /// Git ref at the head of the diff.
    pub head: String,
    /// Which lines were considered (`Added`, `Removed`, or `All`).
    pub scope: Scope,
    /// Overall pass/fail status of the check.
    pub status: VerdictStatus,
    /// Breakdown of findings by severity.
    pub counts: VerdictCounts,
    /// Number of distinct files that were scanned.
    ///
    /// Stored as `u64` to avoid silent truncation for very large repositories
    /// (those with more than 2^32 - 1 unique files).
    pub files_scanned: u64,
    /// Total lines examined (context + added + removed).
    pub lines_scanned: u32,
    /// Total findings reported (before suppression).
    pub findings: u32,
}

/// Aggregated summary of a [`TrendHistory`].
///
/// Use [`summarize_trend_history`] to produce this from raw history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendSummary {
    /// Total number of runs in the history.
    pub run_count: u32,
    /// Sum of all verdict counts across all runs.
    pub totals: VerdictCounts,
    /// Sum of all findings across all runs.
    pub total_findings: u32,
    /// The most recent run, if the history is non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest: Option<TrendRun>,
    /// Change in counts between the most recent two runs, if at least two exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_from_previous: Option<TrendDelta>,
}

/// Change in counts between two consecutive [`TrendRun`]s.
///
/// All fields are `current - previous`, so a negative value means the current
/// run had fewer findings than the previous one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendDelta {
    /// Change in total findings count.
    pub findings: i64,
    /// Change in info-level findings count.
    pub info: i64,
    /// Change in warn-level findings count.
    pub warn: i64,
    /// Change in error-level findings count.
    pub error: i64,
    /// Change in suppressed findings count.
    pub suppressed: i64,
}

/// Normalizes a trend history by setting the schema id when missing.
///
/// Call this before persisting a history or before performing equality checks
/// to ensure a consistent canonical form. Does not modify the `runs` vector.
pub fn normalize_trend_history(mut history: TrendHistory) -> TrendHistory {
    if history.schema.is_empty() {
        history.schema = TREND_HISTORY_SCHEMA_V1.to_string();
    }
    history
}

/// Converts a check receipt into a trend run sample.
///
/// `started_at` and `ended_at` are passed in as strings to allow the caller to
/// use any timestamp format (typically ISO 8601). The `duration_ms` should
/// reflect wall-clock time, not CPU time.
///
/// The `findings` count is capped at `u32::MAX` to prevent truncation for
/// extremely large scans.
pub fn trend_run_from_receipt(
    receipt: &CheckReceipt,
    started_at: &str,
    ended_at: &str,
    duration_ms: u64,
) -> TrendRun {
    TrendRun {
        started_at: started_at.to_string(),
        ended_at: ended_at.to_string(),
        duration_ms,
        base: receipt.diff.base.clone(),
        head: receipt.diff.head.clone(),
        scope: receipt.diff.scope,
        status: receipt.verdict.status,
        counts: receipt.verdict.counts.clone(),
        files_scanned: receipt.diff.files_scanned,
        lines_scanned: receipt.diff.lines_scanned,
        findings: receipt.findings.len().min(u32::MAX as usize) as u32,
    }
}

/// Appends a run to history and optionally trims to `max_runs` newest entries.
///
/// When `max_runs` is `Some(n)` with `n > 0`, the oldest runs are evicted once
/// the history exceeds `n` entries. This keeps memory bounded for long-running
/// pipelines. When `max_runs` is `None`, runs are never evicted.
pub fn append_trend_run(
    mut history: TrendHistory,
    run: TrendRun,
    max_runs: Option<usize>,
) -> TrendHistory {
    history = normalize_trend_history(history);
    history.runs.push(run);

    if let Some(limit) = max_runs
        && limit > 0
        && history.runs.len() > limit
    {
        let drop_count = history.runs.len().saturating_sub(limit);
        history.runs.drain(0..drop_count);
    }

    history
}

/// Summarizes trend history totals and latest delta.
pub fn summarize_trend_history(history: &TrendHistory) -> TrendSummary {
    let mut totals = VerdictCounts::default();
    let mut total_findings = 0u32;

    for run in &history.runs {
        totals.info = totals.info.saturating_add(run.counts.info);
        totals.warn = totals.warn.saturating_add(run.counts.warn);
        totals.error = totals.error.saturating_add(run.counts.error);
        totals.suppressed = totals.suppressed.saturating_add(run.counts.suppressed);
        total_findings = total_findings.saturating_add(run.findings);
    }

    let latest = history.runs.last().cloned();
    // Delta is always (second-last - last) → (previous - current), so a negative
    // value means findings decreased since the previous run.
    let delta_from_previous = if history.runs.len() >= 2 {
        let prev = &history.runs[history.runs.len() - 2];
        let curr = &history.runs[history.runs.len() - 1];
        Some(TrendDelta {
            findings: i64::from(curr.findings) - i64::from(prev.findings),
            info: i64::from(curr.counts.info) - i64::from(prev.counts.info),
            warn: i64::from(curr.counts.warn) - i64::from(prev.counts.warn),
            error: i64::from(curr.counts.error) - i64::from(prev.counts.error),
            suppressed: i64::from(curr.counts.suppressed) - i64::from(prev.counts.suppressed),
        })
    } else {
        None
    };

    TrendSummary {
        run_count: history.runs.len().min(u32::MAX as usize) as u32,
        totals,
        total_findings,
        latest,
        delta_from_previous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::{DiffMeta, Severity, ToolMeta, Verdict};

    fn receipt_with_findings() -> CheckReceipt {
        CheckReceipt {
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
                files_scanned: 1,
                lines_scanned: 2,
            },
            findings: vec![Finding {
                rule_id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "no unwrap".to_string(),
                path: "src/lib.rs".to_string(),
                line: 12,
                column: Some(4),
                match_text: ".unwrap(".to_string(),
                snippet: "let x = y.unwrap();".to_string(),
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

    #[test]
    fn baseline_from_receipt_is_deterministic() {
        let receipt = receipt_with_findings();
        let a = baseline_from_receipt(&receipt);
        let b = baseline_from_receipt(&receipt);
        assert_eq!(a, b);
        assert_eq!(a.schema, FALSE_POSITIVE_BASELINE_SCHEMA_V1);
        assert_eq!(a.entries.len(), 1);
        assert_eq!(a.entries[0].fingerprint.len(), 64);
    }

    #[test]
    fn merge_baseline_preserves_existing_note() {
        let mut existing = FalsePositiveBaseline::default();
        existing.entries.push(FalsePositiveEntry {
            fingerprint: "abc".to_string(),
            rule_id: "rule.one".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: Some("intentional".to_string()),
        });

        let mut incoming = FalsePositiveBaseline::default();
        incoming.entries.push(FalsePositiveEntry {
            fingerprint: "abc".to_string(),
            rule_id: "rule.one".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: None,
        });

        let merged = merge_false_positive_baselines(&existing, &incoming);
        assert_eq!(merged.entries.len(), 1);
        assert_eq!(merged.entries[0].note.as_deref(), Some("intentional"));
    }

    #[test]
    fn append_trend_run_trims_to_max() {
        let receipt = receipt_with_findings();
        let run = trend_run_from_receipt(
            &receipt,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:01Z",
            1000,
        );
        let mut history = TrendHistory::default();
        history = append_trend_run(history, run.clone(), Some(2));
        history = append_trend_run(history, run.clone(), Some(2));
        history = append_trend_run(history, run, Some(2));
        assert_eq!(history.runs.len(), 2);
    }

    #[test]
    fn summarize_history_reports_delta() {
        let receipt = receipt_with_findings();
        let mut run1 = trend_run_from_receipt(
            &receipt,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:01Z",
            1000,
        );
        run1.findings = 3;
        run1.counts.warn = 2;

        let mut run2 = run1.clone();
        run2.findings = 1;
        run2.counts.warn = 1;

        let history = TrendHistory {
            schema: TREND_HISTORY_SCHEMA_V1.to_string(),
            runs: vec![run1, run2],
        };
        let summary = summarize_trend_history(&history);
        assert_eq!(summary.run_count, 2);
        assert_eq!(summary.total_findings, 4);
        let delta = summary.delta_from_previous.expect("delta");
        assert_eq!(delta.findings, -2);
        assert_eq!(delta.warn, -1);
    }
}
