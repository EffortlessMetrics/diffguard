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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FalsePositiveBaseline {
    pub schema: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FalsePositiveEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub path: String,
    pub line: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Deterministically normalizes a false-positive baseline:
/// - ensures schema id is set
/// - sorts entries
/// - deduplicates by fingerprint
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
pub fn fingerprint_for_finding(finding: &Finding) -> String {
    let input = format!(
        "{}:{}:{}:{}",
        finding.rule_id, finding.path, finding.line, finding.match_text
    );
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

/// Builds a baseline from receipt findings.
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
pub fn false_positive_fingerprint_set(baseline: &FalsePositiveBaseline) -> BTreeSet<String> {
    baseline
        .entries
        .iter()
        .map(|e| e.fingerprint.clone())
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendHistory {
    pub schema: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendRun {
    pub started_at: String,
    pub ended_at: String,
    pub duration_ms: u64,
    pub base: String,
    pub head: String,
    pub scope: Scope,
    pub status: VerdictStatus,
    pub counts: VerdictCounts,
    pub files_scanned: u32,
    pub lines_scanned: u32,
    pub findings: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendSummary {
    pub run_count: u32,
    pub totals: VerdictCounts,
    pub total_findings: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest: Option<TrendRun>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_from_previous: Option<TrendDelta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TrendDelta {
    pub findings: i64,
    pub info: i64,
    pub warn: i64,
    pub error: i64,
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
