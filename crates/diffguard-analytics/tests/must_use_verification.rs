//! Integration tests verifying #[must_use] is present on all public functions.
//!
//! These tests serve as RED-BUILD verification: they define what correct behavior
//! looks like and will PASS when the implementation correctly adds #[must_use].
//!
//! ## Test Strategy
//!
//! The `#[must_use]` attribute is a compile-time construct. To verify its presence
//! at test time, we use source code inspection (regex matching) rather than runtime tests.
//!
//! Functional tests verify the functions work correctly when return values ARE used.

use std::fs;
use std::path::PathBuf;

// ─────────────────────────────────────────────────────────────────────────────
// MUST_USE ATTRIBUTE VERIFICATION (Source Inspection)
// ─────────────────────────────────────────────────────────────────────────────
//
// The #[must_use] attribute generates a compile-time warning (unused_must_use)
// when a caller discards the return value without using it.
//
// We verify presence by inspecting the source: the attribute must appear on the
// line immediately above each pub fn declaration.
//
// Pattern: r"#\[must_use\]\s+pub fn FUNCTION_NAME" or r"#\[must_use\]\s+\n\s+pub fn FUNCTION_NAME"

/// Path to the diffguard-analytics source file.
fn source_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")
}

/// Reads the library source as a string.
fn read_source() -> String {
    fs::read_to_string(source_path()).expect("failed to read lib.rs")
}

/// Check that #[must_use] is present for a function by inspecting source code.
fn assert_must_use(function_name: &str) {
    let source = read_source();
    // Regex to find #[must_use] followed by (optional whitespace+newline and) pub fn function_name
    let pattern = format!(
        r"#\[must_use\]\s+(?:\n\s+)?pub fn {0}",
        regex::escape(function_name)
    );
    let re = regex::Regex::new(&pattern).expect("invalid regex");
    let found = re.is_match(&source);
    assert!(
        found,
        "Missing #[must_use] on function: {function_name}\n\
         Expected pattern: #[must_use] pub fn {function_name}\n\
         Add `#[must_use]` directly above the function declaration."
    );
}

/// Check that the function has BOTH #[must_use] AND `# Panics: Does not panic.` in docs.
fn assert_must_use_and_panics_doc(function_name: &str) {
    let source = read_source();
    let must_use_pattern = format!(
        r"#\[must_use\]\s+(?:\n\s+)?pub fn {0}",
        regex::escape(function_name)
    );
    let must_use_re = regex::Regex::new(&must_use_pattern).expect("invalid regex");

    // The doc comment with # Panics should be before the #[must_use] or the pub fn
    // Pattern: /// # Panics: Does not panic. followed by #[must_use] and pub fn
    let doc_and_attr_pattern = format!(
        r"///\s*#\s*Panics:\s*Does not panic\.\s*(?:\n\s*///.*)*\n\s*(?:#\[must_use\]\s*)?pub fn {0}",
        regex::escape(function_name)
    );
    let doc_re = regex::Regex::new(&doc_and_attr_pattern).expect("invalid regex");

    let has_must_use = must_use_re.is_match(&source);
    let has_panics_doc = doc_re.is_match(&source);

    assert!(
        has_must_use,
        "Missing #[must_use] on function: {function_name}"
    );
    assert!(
        has_panics_doc,
        "Missing `# Panics: Does not panic.` documentation on function: {function_name}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS: #[must_use] attribute presence on all 6 functions
// ─────────────────────────────────────────────────────────────────────────────
//
// These functions are MISSING #[must_use] per issue #580:
// 1. merge_false_positive_baselines (line 100)
// 2. false_positive_fingerprint_set (line 139)
// 3. normalize_trend_history (line 203)
// 4. trend_run_from_receipt (line 211)
// 5. append_trend_run (line 233)
// 6. summarize_trend_history (line 253)
//
// These tests will FAIL initially (RED state) because #[must_use] is missing.
// Once code-builder adds #[must_use] to these functions, tests will PASS.

#[test]
fn test_merge_false_positive_baselines_has_must_use() {
    assert_must_use("merge_false_positive_baselines");
}

#[test]
fn test_false_positive_fingerprint_set_has_must_use() {
    assert_must_use("false_positive_fingerprint_set");
}

#[test]
fn test_normalize_trend_history_has_must_use() {
    assert_must_use("normalize_trend_history");
}

#[test]
fn test_trend_run_from_receipt_has_must_use() {
    assert_must_use("trend_run_from_receipt");
}

#[test]
fn test_append_trend_run_has_must_use() {
    assert_must_use("append_trend_run");
}

#[test]
fn test_summarize_trend_history_has_must_use() {
    assert_must_use("summarize_trend_history");
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS: # Panics documentation on all 9 public functions
// ─────────────────────────────────────────────────────────────────────────────
//
// Per Rust API Guidelines C409, all public functions should document panic behavior.
// Since all 9 functions in this crate are pure/deterministic and cannot panic,
// each should have: `# Panics: Does not panic.`
//
// These tests verify BOTH #[must_use] AND # Panics docs are present.

#[test]
fn test_normalize_false_positive_baseline_has_must_use_and_panics_doc() {
    assert_must_use_and_panics_doc("normalize_false_positive_baseline");
}

#[test]
fn test_fingerprint_for_finding_has_must_use_and_panics_doc() {
    assert_must_use_and_panics_doc("fingerprint_for_finding");
}

#[test]
fn test_baseline_from_receipt_has_must_use_and_panics_doc() {
    assert_must_use_and_panics_doc("baseline_from_receipt");
}

#[test]
fn test_merge_false_positive_baselines_has_panics_doc() {
    assert_must_use_and_panics_doc("merge_false_positive_baselines");
}

#[test]
fn test_false_positive_fingerprint_set_has_panics_doc() {
    assert_must_use_and_panics_doc("false_positive_fingerprint_set");
}

#[test]
fn test_normalize_trend_history_has_panics_doc() {
    assert_must_use_and_panics_doc("normalize_trend_history");
}

#[test]
fn test_trend_run_from_receipt_has_panics_doc() {
    assert_must_use_and_panics_doc("trend_run_from_receipt");
}

#[test]
fn test_append_trend_run_has_panics_doc() {
    assert_must_use_and_panics_doc("append_trend_run");
}

#[test]
fn test_summarize_trend_history_has_panics_doc() {
    assert_must_use_and_panics_doc("summarize_trend_history");
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS: Functional verification (these test correct BEHAVIOR, not attributes)
// ─────────────────────────────────────────────────────────────────────────────
//
// These tests verify the functions work correctly when return values ARE used.
// These should PASS both before and after the #[must_use] change (no regression).

#[test]
fn test_merge_false_positive_baselines_merges_correctly() {
    use diffguard_analytics::{
        FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    };

    let base = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "fp1".to_string(),
            rule_id: "rule1".to_string(),
            path: "a.rs".to_string(),
            line: 10,
            note: Some("existing note".to_string()),
        }],
    };

    let incoming = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "fp2".to_string(),
            rule_id: "rule2".to_string(),
            path: "b.rs".to_string(),
            line: 20,
            note: None,
        }],
    };

    let merged = diffguard_analytics::merge_false_positive_baselines(&base, &incoming);

    // Should have 2 entries (union by fingerprint)
    assert_eq!(merged.entries.len(), 2);

    // Verify the first entry preserved its note (merging logic)
    let fp1 = merged
        .entries
        .iter()
        .find(|e| e.fingerprint == "fp1")
        .expect("fp1 should exist");
    assert_eq!(fp1.note.as_deref(), Some("existing note"));
}

#[test]
fn test_false_positive_fingerprint_set_creates_set() {
    use diffguard_analytics::{
        FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    };

    let baseline = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "abc123".to_string(),
                rule_id: "rule1".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "def456".to_string(),
                rule_id: "rule2".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
        ],
    };

    let set = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert_eq!(set.len(), 2);
    assert!(set.contains("abc123"));
    assert!(set.contains("def456"));
}

#[test]
fn test_normalize_trend_history_preserves_schema() {
    use diffguard_analytics::{TREND_HISTORY_SCHEMA_V1, TrendHistory};

    // TrendHistory::default() already sets the schema, so create one with empty schema
    let history = TrendHistory {
        schema: String::new(),
        runs: vec![],
    };
    assert!(history.schema.is_empty());

    let normalized = diffguard_analytics::normalize_trend_history(history);

    // After normalization, schema should be set to TREND_HISTORY_SCHEMA_V1
    assert_eq!(normalized.schema, TREND_HISTORY_SCHEMA_V1);
}

#[test]
fn test_trend_run_from_receipt_creates_trend_run() {
    use diffguard_types::{
        CheckReceipt, DiffMeta, Scope, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
    };

    let receipt = CheckReceipt {
        schema: "diffguard.check.v1".to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "1.0.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 10,
            lines_scanned: 500,
        },
        findings: vec![],
        verdict: Verdict {
            status: VerdictStatus::Pass,
            counts: VerdictCounts {
                info: 0,
                warn: 1,
                error: 0,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    };

    let run = diffguard_analytics::trend_run_from_receipt(
        &receipt,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
        60000,
    );

    assert_eq!(run.started_at, "2026-01-01T00:00:00Z");
    assert_eq!(run.ended_at, "2026-01-01T00:01:00Z");
    assert_eq!(run.duration_ms, 60000);
    assert_eq!(run.base, "origin/main");
    assert_eq!(run.head, "HEAD");
    assert_eq!(run.scope, Scope::Added);
    assert_eq!(run.status, VerdictStatus::Pass);
    assert_eq!(run.counts.warn, 1);
    assert_eq!(run.files_scanned, 10);
}

#[test]
fn test_append_trend_run_adds_run() {
    use diffguard_analytics::{TrendHistory, TrendRun};
    use diffguard_types::{Scope, VerdictCounts, VerdictStatus};

    let history = TrendHistory::default();
    let run = TrendRun {
        started_at: "2026-01-01T00:00:00Z".to_string(),
        ended_at: "2026-01-01T00:01:00Z".to_string(),
        duration_ms: 60000,
        base: "origin/main".to_string(),
        head: "HEAD".to_string(),
        scope: Scope::Added,
        status: VerdictStatus::Pass,
        counts: VerdictCounts::default(),
        files_scanned: 10,
        lines_scanned: 500,
        findings: 0,
    };

    let updated = diffguard_analytics::append_trend_run(history, run, None);

    assert_eq!(updated.runs.len(), 1);
}

#[test]
fn test_append_trend_run_trims_to_max() {
    use diffguard_analytics::{TrendHistory, TrendRun};
    use diffguard_types::{Scope, VerdictCounts, VerdictStatus};

    let run = TrendRun {
        started_at: "2026-01-01T00:00:00Z".to_string(),
        ended_at: "2026-01-01T00:01:00Z".to_string(),
        duration_ms: 60000,
        base: "origin/main".to_string(),
        head: "HEAD".to_string(),
        scope: Scope::Added,
        status: VerdictStatus::Pass,
        counts: VerdictCounts::default(),
        files_scanned: 10,
        lines_scanned: 500,
        findings: 0,
    };

    // Add 3 runs with max_runs = 2
    let mut history =
        diffguard_analytics::append_trend_run(TrendHistory::default(), run.clone(), Some(2));
    history = diffguard_analytics::append_trend_run(history, run.clone(), Some(2));
    history = diffguard_analytics::append_trend_run(history, run, Some(2));

    // Should be trimmed to 2
    assert_eq!(history.runs.len(), 2);
}

#[test]
fn test_summarize_trend_history_computes_totals() {
    use diffguard_analytics::{TrendHistory, TrendRun};
    use diffguard_types::{Scope, VerdictCounts, VerdictStatus};

    let run1 = TrendRun {
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
            suppressed: 0,
        },
        files_scanned: 10,
        lines_scanned: 500,
        findings: 6,
    };

    let run2 = TrendRun {
        started_at: "2026-01-02T00:00:00Z".to_string(),
        ended_at: "2026-01-02T00:01:00Z".to_string(),
        duration_ms: 60000,
        base: "origin/main".to_string(),
        head: "HEAD".to_string(),
        scope: Scope::Added,
        status: VerdictStatus::Pass,
        counts: VerdictCounts {
            info: 1,
            warn: 1,
            error: 0,
            suppressed: 0,
        },
        files_scanned: 12,
        lines_scanned: 600,
        findings: 2,
    };

    let history = TrendHistory {
        schema: "diffguard.trend_history.v1".to_string(),
        runs: vec![run1, run2],
    };

    let summary = diffguard_analytics::summarize_trend_history(&history);

    assert_eq!(summary.run_count, 2);
    assert_eq!(summary.total_findings, 8); // 6 + 2
    assert_eq!(summary.totals.info, 2);
    assert_eq!(summary.totals.warn, 3);
    assert_eq!(summary.totals.error, 3);
}
