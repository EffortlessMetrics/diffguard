//! Analytics helpers for diffguard.
//!
//! This crate is intentionally pure (no filesystem/process/env I/O).

use std::collections::BTreeSet;

use diffguard_types::{CheckReceipt, Finding, Scope, VerdictCounts, VerdictStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FALSE_POSITIVE_BASELINE_SCHEMA_V1: &str = "diffguard.false_positive_baseline.v1";
pub const TREND_HISTORY_SCHEMA_V1: &str = "diffguard.trend_history.v1";

/// A collection of false-positive entries used to suppress known/acceptable findings.
///
/// The baseline tracks findings across multiple CI runs, allowing diffguard to
/// distinguish between new findings and pre-existing false positives that were
/// manually reviewed and accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FalsePositiveBaseline {
    /// Schema version identifier for forward compatibility.
    pub schema: String,
    /// Individual false-positive entries, deduplicated by fingerprint.
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

/// A single false-positive finding entry within a baseline.
///
/// Each entry represents a finding that was manually reviewed and determined to be
/// a false positive. The `fingerprint` uniquely identifies the finding; other fields
/// store the original finding metadata and any notes added during review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FalsePositiveEntry {
    /// SHA-256 fingerprint of the finding, computed from rule_id:path:line:match_text.
    pub fingerprint: String,
    /// The rule that triggered this finding (e.g., "rust.no_unwrap").
    pub rule_id: String,
    /// Path to the file containing the finding.
    pub path: String,
    /// Line number where the finding was detected.
    pub line: u32,
    /// Optional human-written note explaining why this is a false positive.
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

/// Merges two baselines using a union-by-fingerprint strategy.
///
/// The `incoming` baseline provides all entries; entries from `base` are added only
/// if their fingerprint does not already exist in `incoming`. When a fingerprint
/// collision occurs (same finding in both baselines), fields from `base` fill in
/// only if the corresponding field in `incoming` is empty/missing — preserving
/// manually curated data like reviewer notes while accepting new metadata like
/// rule_id or path if the incoming entry lacks it.
///
/// This is the inverse of a typical "prefer incoming" merge: the base baseline's
/// manually reviewed metadata survives even when newer scan data would otherwise
/// overwrite it.
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
            // Fingerprint is new to incoming — add the entire entry.
            merged.entries.push(entry.clone());
        } else if let Some(existing) = merged
            .entries
            .iter_mut()
            .find(|e| e.fingerprint == entry.fingerprint)
        {
            // Fingerprint collision: inherit from base only when incoming field is empty.
            // This preserves manually curated notes and fills in missing metadata.
            if existing.note.is_none() && entry.note.is_some() {
                existing.note.clone_from(&entry.note);
            }
            if existing.rule_id.is_empty() {
                existing.rule_id.clone_from(&entry.rule_id);
            }
            if existing.path.is_empty() {
                existing.path.clone_from(&entry.path);
            }
            if existing.line == 0 {
                existing.line = entry.line;
            }
        }
    }

    normalize_false_positive_baseline(merged)
}

/// Returns the baseline as a fingerprint set for fast lookup.
pub fn false_positive_fingerprint_set(baseline: &FalsePositiveBaseline) -> BTreeSet<String> {
    baseline
        .entries
        .iter()
        .map(|e| e.fingerprint.clone())
        .collect()
}

/// A chronological sequence of CI check runs, used for trend analysis.
///
/// Each `TrendRun` represents a single diffguard execution. The runs are stored
/// in chronological order (oldest first) and are normalized to include a schema
/// version identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendHistory {
    /// Schema version for forward compatibility.
    pub schema: String,
    /// Ordered list of trend runs (oldest first).
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

/// A single diffguard CI check run, capturing inputs and outcome.
///
/// `TrendRun` is a snapshot of one diffguard execution: what was scanned,
/// what the verdict was, and how many findings were observed. Multiple runs
/// form a `TrendHistory` for longitudinal analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendRun {
    /// RFC 3339 timestamp when the run started.
    pub started_at: String,
    /// RFC 3339 timestamp when the run finished.
    pub ended_at: String,
    /// Elapsed time in milliseconds.
    pub duration_ms: u64,
    /// Git ref of the base commit (e.g., "origin/main").
    pub base: String,
    /// Git ref of the head commit (e.g., "HEAD").
    pub head: String,
    /// Which files were considered (Added, Removed, or All).
    pub scope: Scope,
    /// Overall pass/fail verdict.
    pub status: VerdictStatus,
    /// Breakdown of findings by severity.
    pub counts: VerdictCounts,
    /// Number of distinct files that were scanned.
    ///
    /// Stored as `u64` to avoid silent truncation for very large repositories
    /// (those with more than 2^32 - 1 unique files).
    pub files_scanned: u64,
    /// Total lines scanned across all files.
    pub lines_scanned: u32,
    /// Total findings reported (before suppression).
    pub findings: u32,
}

/// Aggregated summary of a `TrendHistory` — totals, latest run, and period-over-period delta.
///
/// `TrendSummary` condenses a full run history into a single view: how many runs
/// were executed, cumulative findings across all runs, the most recent run, and
/// the change in findings between the last two runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendSummary {
    /// Total number of runs in the history.
    pub run_count: u32,
    /// Cumulative counts across all runs.
    pub totals: VerdictCounts,
    /// Total findings across all runs (before suppression).
    pub total_findings: u32,
    /// The most recent run, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest: Option<TrendRun>,
    /// Change in counts between the second-most-recent and most-recent run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_from_previous: Option<TrendDelta>,
}

/// Period-over-period change in finding counts between two consecutive `TrendRun`s.
///
/// Each field is the difference (`current - previous`) for that severity level.
/// Positive values indicate an increase in findings; negative values indicate a decrease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendDelta {
    /// Change in total findings (all severities combined).
    pub findings: i64,
    /// Change in info-level findings.
    pub info: i64,
    /// Change in warning-level findings.
    pub warn: i64,
    /// Change in error-level findings.
    pub error: i64,
    /// Change in suppressed findings.
    pub suppressed: i64,
}

/// Deterministically normalizes trend history by setting schema id when missing.
pub fn normalize_trend_history(mut history: TrendHistory) -> TrendHistory {
    if history.schema.is_empty() {
        history.schema = TREND_HISTORY_SCHEMA_V1.to_string();
    }
    history
}

/// Converts a check receipt into a trend run sample.
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
