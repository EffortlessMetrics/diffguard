//! Check orchestration.
//!
//! `run_check` ties together the pipeline: diff prep → rule filtering → evaluation →
//! false-positive filtering → verdict → receipt assembly → output rendering.
//!
//! Sub-modules each own one step of that pipeline.

mod annotations;
mod diff_prep;
mod false_positive;
mod path_filter;
mod rule_filter;
mod rule_hits;
mod verdict;

use std::collections::BTreeSet;

use diffguard_domain::{
    DirectoryRuleOverride, InputLine, RuleOverrideMatcher, compile_rules,
    evaluate_lines_with_overrides_and_language,
};
use diffguard_types::{CheckReceipt, DiffMeta, FailOn, REASON_TRUNCATED, ToolMeta, Verdict};

pub use path_filter::PathFilterError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckPlan {
    pub base: String,
    pub head: String,
    pub scope: diffguard_types::Scope,
    pub diff_context: u32,
    pub fail_on: FailOn,
    pub max_findings: usize,
    pub path_filters: Vec<String>,
    /// Only include rules that have at least one of these tags.
    /// Empty means no filtering by this criterion.
    pub only_tags: Vec<String>,
    /// Include rules that have at least one of these tags (additive).
    /// Empty means no filtering by this criterion.
    pub enable_tags: Vec<String>,
    /// Exclude rules that have any of these tags.
    /// Empty means no filtering by this criterion.
    pub disable_tags: Vec<String>,
    /// Per-directory rule overrides loaded from `.diffguard.toml` files.
    pub directory_overrides: Vec<DirectoryRuleOverride>,
    /// Force all files to be treated as this language for preprocessing/rule filtering.
    pub force_language: Option<String>,
    /// Optional line-level allowlist `(path, line)` for secondary filtering.
    /// When set, only these diff lines are evaluated.
    pub allowed_lines: Option<BTreeSet<(String, u32)>>,
    /// Finding fingerprints to treat as acknowledged false positives.
    pub false_positive_fingerprints: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRun {
    pub receipt: CheckReceipt,
    pub markdown: String,
    pub annotations: Vec<String>,
    pub exit_code: i32,
    /// Number of findings dropped due to max_findings truncation.
    pub truncated_findings: u32,
    /// Number of rules that were evaluated (after tag filtering).
    pub rules_evaluated: usize,
    /// Per-rule hit aggregation for analytics.
    pub rule_hits: Vec<RuleHitStat>,
    /// Number of findings filtered as acknowledged false positives.
    pub false_positive_findings: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHitStat {
    pub rule_id: String,
    pub total: u32,
    pub emitted: u32,
    pub suppressed: u32,
    pub info: u32,
    pub warn: u32,
    pub error: u32,
    pub false_positive: u32,
}

/// Run a policy check over a unified diff text.
///
/// # Errors
///
/// Returns an error if:
/// - The diff text cannot be parsed ([`diffguard_diff::DiffParseError`])
/// - Path filter globs are invalid ([`PathFilterError`])
/// - Rule compilation fails ([`diffguard_domain::RuleCompileError`])
/// - Override compilation fails ([`diffguard_domain::OverrideCompileError`])
pub fn run_check(
    plan: &CheckPlan,
    config: &diffguard_types::ConfigFile,
    diff_text: &str,
) -> Result<CheckRun, anyhow::Error> {
    let diff_lines = diff_prep::prepare_diff_lines(plan, diff_text)?;

    let filtered_rules: Vec<_> = config
        .rule
        .iter()
        .filter(|r| rule_filter::filter_rule_by_tags(r, plan))
        .cloned()
        .collect();

    let rules = compile_rules(&filtered_rules)?;
    let rules_evaluated = filtered_rules.len();
    let override_matcher = RuleOverrideMatcher::compile(&plan.directory_overrides)?;

    let lines = diff_lines.into_iter().map(|l| InputLine {
        path: l.path,
        line: l.line,
        content: l.content,
    });

    let evaluation = evaluate_lines_with_overrides_and_language(
        lines,
        &rules,
        plan.max_findings,
        if plan.directory_overrides.is_empty() {
            None
        } else {
            Some(&override_matcher)
        },
        plan.force_language.as_deref(),
    );

    let fp_outcome = false_positive::apply_false_positive_filter(
        evaluation.findings,
        &evaluation.counts,
        &plan.false_positive_fingerprints,
    );

    let mut reasons: Vec<String> = Vec::new();
    if evaluation.truncated_findings > 0 {
        reasons.push(REASON_TRUNCATED.to_string());
    }

    let receipt = CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        diff: DiffMeta {
            base: plan.base.clone(),
            head: plan.head.clone(),
            context_lines: plan.diff_context,
            scope: plan.scope,
            files_scanned: evaluation.files_scanned,
            lines_scanned: evaluation.lines_scanned,
        },
        findings: fp_outcome.kept_findings,
        verdict: Verdict {
            status: verdict::compute_verdict_status(&fp_outcome.adjusted_counts),
            counts: fp_outcome.adjusted_counts,
            reasons,
        },
        timing: None,
    };

    let markdown = crate::render::render_markdown_for_receipt(&receipt);
    let annotations = annotations::render_annotations(&receipt.findings);
    let exit_code = verdict::compute_exit_code(plan.fail_on, &receipt.verdict.counts);
    let rule_hits = rule_hits::build_rule_hits(evaluation.rule_hits, &fp_outcome.per_rule);

    Ok(CheckRun {
        receipt,
        markdown,
        annotations,
        exit_code,
        truncated_findings: evaluation.truncated_findings,
        rules_evaluated,
        rule_hits,
        false_positive_findings: fp_outcome.false_positive_findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::{Finding, VerdictCounts, VerdictStatus};

    fn test_finding(severity: diffguard_types::Severity) -> Finding {
        Finding {
            rule_id: "test.rule".to_string(),
            severity,
            message: "Test message".to_string(),
            path: "src/lib.rs".to_string(),
            line: 42,
            column: Some(3),
            match_text: "match".to_string(),
            snippet: "let x = match;".to_string(),
        }
    }

    fn test_rule_config(
        severity: diffguard_types::Severity,
        pattern: &str,
    ) -> diffguard_types::ConfigFile {
        diffguard_types::ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults::default(),
            rule: vec![diffguard_types::RuleConfig {
                id: "test.rule".to_string(),
                description: String::new(),
                severity,
                message: "Test message".to_string(),
                languages: vec!["rust".to_string()],
                patterns: vec![pattern.to_string()],
                paths: vec!["**/*.rs".to_string()],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                match_mode: Default::default(),
                multiline: false,
                multiline_window: None,
                context_patterns: vec![],
                context_window: None,
                escalate_patterns: vec![],
                escalate_window: None,
                escalate_to: None,
                depends_on: vec![],
                help: None,
                url: None,
                tags: vec![],
                test_cases: vec![],
            }],
        }
    }

    fn test_plan(max_findings: usize, fail_on: FailOn, path_filters: Vec<&str>) -> CheckPlan {
        CheckPlan {
            base: "base".to_string(),
            head: "head".to_string(),
            scope: diffguard_types::Scope::Added,
            diff_context: 0,
            fail_on,
            max_findings,
            path_filters: path_filters.into_iter().map(|s| s.to_string()).collect(),
            only_tags: vec![],
            enable_tags: vec![],
            disable_tags: vec![],
            directory_overrides: vec![],
            force_language: None,
            allowed_lines: None,
            false_positive_fingerprints: BTreeSet::new(),
        }
    }

    #[test]
    fn run_check_without_path_filters_keeps_findings() {
        let plan = test_plan(100, FailOn::Error, vec![]);
        let config = test_rule_config(diffguard_types::Severity::Warn, "warn_me");
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+let x = warn_me();
"#;

        let run = run_check(&plan, &config, diff).expect("run_check");
        assert_eq!(run.receipt.findings.len(), 1);
    }

    #[test]
    fn run_check_with_path_filters_filters_findings() {
        let plan = test_plan(100, FailOn::Error, vec!["src/lib.rs"]);
        let config = test_rule_config(diffguard_types::Severity::Warn, "warn_me");
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+let x = warn_me();
diff --git a/other.rs b/other.rs
--- a/other.rs
+++ b/other.rs
@@ -1,1 +1,2 @@
 fn b() {}
+let y = warn_me();
"#;

        let run = run_check(&plan, &config, diff).expect("run_check");
        assert_eq!(run.receipt.findings.len(), 1);
        assert_eq!(run.receipt.findings[0].path, "src/lib.rs");
    }

    #[test]
    fn run_check_dedupes_duplicate_diff_lines() {
        let plan = test_plan(100, FailOn::Error, vec![]);
        let config = test_rule_config(diffguard_types::Severity::Warn, "warn_me");
        let single = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+let x = warn_me();
"#;
        let duplicated = format!("{single}\n{single}");

        let run = run_check(&plan, &config, &duplicated).expect("run_check");
        assert_eq!(run.receipt.findings.len(), 1);
        assert_eq!(run.receipt.verdict.counts.warn, 1);
    }

    #[test]
    fn run_check_force_language_applies_rules_for_unknown_extensions() {
        let mut plan = test_plan(100, FailOn::Error, vec![]);
        plan.force_language = Some("rust".to_string());
        let config = diffguard_types::ConfigFile {
            includes: vec![],
            defaults: diffguard_types::Defaults::default(),
            rule: vec![diffguard_types::RuleConfig {
                id: "test.rule".to_string(),
                description: String::new(),
                severity: diffguard_types::Severity::Warn,
                message: "Test message".to_string(),
                languages: vec!["rust".to_string()],
                patterns: vec!["warn_me".to_string()],
                paths: vec!["**/*.custom".to_string()],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                match_mode: Default::default(),
                multiline: false,
                multiline_window: None,
                context_patterns: vec![],
                context_window: None,
                escalate_patterns: vec![],
                escalate_window: None,
                escalate_to: None,
                depends_on: vec![],
                help: None,
                url: None,
                tags: vec![],
                test_cases: vec![],
            }],
        };
        let diff = r#"
diff --git a/src/file.custom b/src/file.custom
--- a/src/file.custom
+++ b/src/file.custom
@@ -0,0 +1,1 @@
+warn_me();
"#;

        let run = run_check(&plan, &config, diff).expect("run_check");
        assert_eq!(run.receipt.findings.len(), 1);
        assert_eq!(run.receipt.verdict.counts.warn, 1);
    }

    #[test]
    fn run_check_filters_by_allowed_lines() {
        let mut plan = test_plan(100, FailOn::Error, vec![]);
        plan.allowed_lines = Some(BTreeSet::from([(String::from("src/lib.rs"), 3)]));
        let config = test_rule_config(diffguard_types::Severity::Warn, "warn_me");
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,3 @@
 fn a() {}
+let x = warn_me();
+let y = warn_me();
"#;

        let run = run_check(&plan, &config, diff).expect("run_check");
        assert_eq!(run.receipt.findings.len(), 1);
        assert_eq!(run.receipt.findings[0].line, 3);
    }

    #[test]
    fn run_check_filters_acknowledged_false_positive_fingerprints() {
        let config = test_rule_config(diffguard_types::Severity::Warn, "warn_me");
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+let x = warn_me();
"#;

        let run_unfiltered =
            run_check(&test_plan(100, FailOn::Warn, vec![]), &config, diff).expect("run_check");
        let fingerprint = crate::compute_fingerprint(&run_unfiltered.receipt.findings[0]);

        let mut plan = test_plan(100, FailOn::Warn, vec![]);
        plan.false_positive_fingerprints.insert(fingerprint);
        let filtered = run_check(&plan, &config, diff).expect("run_check");

        assert_eq!(filtered.receipt.findings.len(), 0);
        assert_eq!(filtered.receipt.verdict.counts.warn, 0);
        assert_eq!(filtered.receipt.verdict.status, VerdictStatus::Pass);
        assert_eq!(filtered.false_positive_findings, 1);
        assert_eq!(filtered.rule_hits.len(), 1);
        assert_eq!(filtered.rule_hits[0].false_positive, 1);
    }

    #[test]
    fn run_check_sets_warn_verdict_and_reasons() {
        let plan = test_plan(100, FailOn::Warn, vec![]);
        let config = test_rule_config(diffguard_types::Severity::Warn, "warn_me");
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+let x = warn_me();
"#;

        let run = run_check(&plan, &config, diff).expect("run_check");
        assert_eq!(run.receipt.verdict.status, VerdictStatus::Warn);
        assert!(run.receipt.verdict.reasons.is_empty());
    }

    #[test]
    fn run_check_sets_error_verdict_and_reasons() {
        let plan = test_plan(100, FailOn::Error, vec![]);
        let config = test_rule_config(diffguard_types::Severity::Error, "error_me");
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+let x = error_me();
"#;

        let run = run_check(&plan, &config, diff).expect("run_check");
        assert_eq!(run.receipt.verdict.status, VerdictStatus::Fail);
        assert!(run.receipt.verdict.reasons.is_empty());
    }

    #[test]
    fn run_check_includes_truncation_reason() {
        let plan = test_plan(1, FailOn::Warn, vec![]);
        let config = test_rule_config(diffguard_types::Severity::Warn, "warn_me");
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,3 @@
 fn a() {}
+let x = warn_me();
+let y = warn_me();
"#;

        let run = run_check(&plan, &config, diff).expect("run_check");
        assert!(
            run.receipt
                .verdict
                .reasons
                .iter()
                .any(|r| r == REASON_TRUNCATED)
        );
    }

    #[test]
    fn run_check_passes_with_no_findings() {
        let plan = test_plan(100, FailOn::Warn, vec![]);
        let config = test_rule_config(diffguard_types::Severity::Warn, "warn_me");
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 +1,2 @@
 fn a() {}
+let x = clean();
"#;

        let run = run_check(&plan, &config, diff).expect("run_check");
        assert_eq!(run.receipt.verdict.status, VerdictStatus::Pass);
        assert!(run.receipt.verdict.reasons.is_empty());
    }

    #[test]
    fn snapshot_annotations_with_multiple_severities() {
        let findings = vec![
            test_finding(diffguard_types::Severity::Info),
            test_finding(diffguard_types::Severity::Warn),
            test_finding(diffguard_types::Severity::Error),
        ];
        let annotations = super::annotations::render_annotations(&findings);
        insta::assert_snapshot!(annotations.join("\n"));
    }

    #[test]
    fn snapshot_json_receipt_pretty() {
        let receipt = CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: diffguard_types::Scope::Added,
                files_scanned: 1,
                lines_scanned: 2,
            },
            findings: vec![
                test_finding(diffguard_types::Severity::Warn),
                test_finding(diffguard_types::Severity::Error),
            ],
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 1,
                    suppressed: 0,
                },
                reasons: vec![],
            },
            timing: None,
        };

        let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
        insta::assert_snapshot!(json);
    }
}
