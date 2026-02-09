use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};

use diffguard_diff::parse_unified_diff;
use diffguard_domain::{compile_rules, evaluate_lines, InputLine};
use diffguard_types::{
    CheckReceipt, DiffMeta, FailOn, Finding, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
    REASON_TRUNCATED,
};

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
}

#[derive(Debug, thiserror::Error)]
pub enum PathFilterError {
    #[error("invalid path filter glob '{glob}': {source}")]
    InvalidGlob {
        glob: String,
        source: globset::Error,
    },
}

pub fn run_check(
    plan: &CheckPlan,
    config: &diffguard_types::ConfigFile,
    diff_text: &str,
) -> Result<CheckRun, anyhow::Error> {
    let (mut diff_lines, _stats) = parse_unified_diff(diff_text, plan.scope)?;

    if !plan.path_filters.is_empty() {
        let filters = compile_filter_globs(&plan.path_filters)?;
        diff_lines.retain(|l| filters.is_match(Path::new(&l.path)));
    }

    // Filter rules by tags
    let filtered_rules: Vec<_> = config
        .rule
        .iter()
        .filter(|r| filter_rule_by_tags(r, plan))
        .cloned()
        .collect();

    let rules = compile_rules(&filtered_rules)?;
    let rules_evaluated = filtered_rules.len();

    let lines = diff_lines.into_iter().map(|l| InputLine {
        path: l.path,
        line: l.line,
        content: l.content,
    });

    let evaluation = evaluate_lines(lines, &rules, plan.max_findings);

    let verdict_status = if evaluation.counts.error > 0 {
        VerdictStatus::Fail
    } else if evaluation.counts.warn > 0 {
        VerdictStatus::Warn
    } else {
        VerdictStatus::Pass
    };

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
        findings: evaluation.findings.clone(),
        verdict: Verdict {
            status: verdict_status,
            counts: evaluation.counts.clone(),
            reasons,
        },
        timing: None,
    };

    let markdown = crate::render::render_markdown_for_receipt(&receipt);
    let annotations = render_annotations(&receipt.findings);

    let exit_code = compute_exit_code(plan.fail_on, &receipt.verdict.counts);

    Ok(CheckRun {
        receipt,
        markdown,
        annotations,
        exit_code,
        truncated_findings: evaluation.truncated_findings,
        rules_evaluated,
    })
}

fn compile_filter_globs(globs: &[String]) -> Result<GlobSet, PathFilterError> {
    let mut b = GlobSetBuilder::new();
    for g in globs {
        let glob = Glob::new(g).map_err(|e| PathFilterError::InvalidGlob {
            glob: g.clone(),
            source: e,
        })?;
        b.add(glob);
    }
    Ok(b.build().expect("globset build should succeed"))
}

/// Filter a rule based on tag criteria in the plan.
///
/// - If `only_tags` is non-empty, the rule must have at least one matching tag.
/// - If `disable_tags` is non-empty and the rule has any matching tag, it's excluded.
/// - `enable_tags` is currently unused (reserved for future additive logic).
fn filter_rule_by_tags(rule: &diffguard_types::RuleConfig, plan: &CheckPlan) -> bool {
    // If only_tags is specified, rule must have at least one matching tag
    if !plan.only_tags.is_empty() {
        let has_matching_tag = rule
            .tags
            .iter()
            .any(|t| plan.only_tags.iter().any(|ot| ot.eq_ignore_ascii_case(t)));
        if !has_matching_tag {
            return false;
        }
    }

    // If disable_tags is specified, exclude rules that have any matching tag
    if !plan.disable_tags.is_empty() {
        let has_disabled_tag = rule.tags.iter().any(|t| {
            plan.disable_tags
                .iter()
                .any(|dt| dt.eq_ignore_ascii_case(t))
        });
        if has_disabled_tag {
            return false;
        }
    }

    true
}

fn compute_exit_code(fail_on: FailOn, counts: &VerdictCounts) -> i32 {
    if matches!(fail_on, FailOn::Never) {
        return 0;
    }

    if counts.error > 0 {
        return 2;
    }

    if matches!(fail_on, FailOn::Warn) && counts.warn > 0 {
        return 3;
    }

    0
}

fn render_annotations(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                diffguard_types::Severity::Info => "notice",
                diffguard_types::Severity::Warn => "warning",
                diffguard_types::Severity::Error => "error",
            };
            format!(
                "::{level} file={path},line={line}::{rule} {msg}",
                level = level,
                path = f.path,
                line = f.line,
                rule = f.rule_id,
                msg = f.message
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
                severity,
                message: "Test message".to_string(),
                languages: vec!["rust".to_string()],
                patterns: vec![pattern.to_string()],
                paths: vec!["**/*.rs".to_string()],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
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
        }
    }

    #[test]
    fn exit_code_semantics() {
        let mut counts = VerdictCounts::default();
        assert_eq!(compute_exit_code(FailOn::Error, &counts), 0);
        assert_eq!(compute_exit_code(FailOn::Warn, &counts), 0);

        counts.warn = 1;
        assert_eq!(compute_exit_code(FailOn::Error, &counts), 0);
        assert_eq!(compute_exit_code(FailOn::Warn, &counts), 3);

        counts.error = 1;
        assert_eq!(compute_exit_code(FailOn::Error, &counts), 2);
        assert_eq!(compute_exit_code(FailOn::Warn, &counts), 2);
        assert_eq!(compute_exit_code(FailOn::Never, &counts), 0);
    }

    #[test]
    fn compile_filter_globs_rejects_invalid() {
        let err = compile_filter_globs(&["[".to_string()]).unwrap_err();
        match err {
            PathFilterError::InvalidGlob { glob, .. } => assert_eq!(glob, "["),
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
        assert!(run
            .receipt
            .verdict
            .reasons
            .iter()
            .any(|r| r == REASON_TRUNCATED));
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_annotations_format_matches_expected(
            severity in prop_oneof![Just(diffguard_types::Severity::Info), Just(diffguard_types::Severity::Warn), Just(diffguard_types::Severity::Error)],
            line in 1u32..1000,
        ) {
            let mut finding = test_finding(severity);
            finding.line = line;

            let annotations = render_annotations(&[finding.clone()]);
            prop_assert_eq!(annotations.len(), 1);

            let level = match severity {
                diffguard_types::Severity::Info => "notice",
                diffguard_types::Severity::Warn => "warning",
                diffguard_types::Severity::Error => "error",
            };

            let expected = format!(
                "::{level} file={path},line={line}::{rule} {msg}",
                level = level,
                path = finding.path,
                line = finding.line,
                rule = finding.rule_id,
                msg = finding.message
            );

            prop_assert_eq!(annotations[0].as_str(), expected.as_str());
        }
    }

    #[test]
    fn snapshot_annotations_with_multiple_severities() {
        let findings = vec![
            test_finding(diffguard_types::Severity::Info),
            test_finding(diffguard_types::Severity::Warn),
            test_finding(diffguard_types::Severity::Error),
        ];
        let annotations = render_annotations(&findings);
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

    // =========================================================================
    // Tag filtering tests
    // =========================================================================

    fn make_rule_with_tags(id: &str, tags: Vec<&str>) -> diffguard_types::RuleConfig {
        diffguard_types::RuleConfig {
            id: id.to_string(),
            severity: diffguard_types::Severity::Warn,
            message: "Test message".to_string(),
            languages: vec![],
            patterns: vec!["test".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            test_cases: vec![],
        }
    }

    #[test]
    fn filter_rule_by_tags_no_filters() {
        let rule = make_rule_with_tags("test.rule", vec!["debug"]);
        let plan = test_plan(100, FailOn::Error, vec![]);
        assert!(filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn filter_rule_by_tags_only_tags_matches() {
        let rule = make_rule_with_tags("test.rule", vec!["debug", "safety"]);
        let mut plan = test_plan(100, FailOn::Error, vec![]);
        plan.only_tags = vec!["debug".to_string()];
        assert!(filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn filter_rule_by_tags_only_tags_no_match() {
        let rule = make_rule_with_tags("test.rule", vec!["security"]);
        let mut plan = test_plan(100, FailOn::Error, vec![]);
        plan.only_tags = vec!["debug".to_string()];
        assert!(!filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn filter_rule_by_tags_only_tags_case_insensitive() {
        let rule = make_rule_with_tags("test.rule", vec!["DEBUG"]);
        let mut plan = test_plan(100, FailOn::Error, vec![]);
        plan.only_tags = vec!["debug".to_string()];
        assert!(filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn filter_rule_by_tags_disable_tags_excludes() {
        let rule = make_rule_with_tags("test.rule", vec!["debug"]);
        let mut plan = test_plan(100, FailOn::Error, vec![]);
        plan.disable_tags = vec!["debug".to_string()];
        assert!(!filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn filter_rule_by_tags_disable_tags_no_match() {
        let rule = make_rule_with_tags("test.rule", vec!["safety"]);
        let mut plan = test_plan(100, FailOn::Error, vec![]);
        plan.disable_tags = vec!["debug".to_string()];
        assert!(filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn filter_rule_by_tags_combined_filters() {
        // Rule has both "security" and "debug" tags
        let rule = make_rule_with_tags("test.rule", vec!["security", "debug"]);

        // Only security rules, but exclude debug rules
        let mut plan = test_plan(100, FailOn::Error, vec![]);
        plan.only_tags = vec!["security".to_string()];
        plan.disable_tags = vec!["debug".to_string()];

        // Should be excluded because it has a disabled tag
        assert!(!filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn filter_rule_by_tags_rule_without_tags() {
        let rule = make_rule_with_tags("test.rule", vec![]);
        let mut plan = test_plan(100, FailOn::Error, vec![]);
        plan.only_tags = vec!["debug".to_string()];
        // Rule without tags doesn't match only_tags filter
        assert!(!filter_rule_by_tags(&rule, &plan));

        // But with no filters, it should pass
        plan.only_tags.clear();
        assert!(filter_rule_by_tags(&rule, &plan));
    }
}
