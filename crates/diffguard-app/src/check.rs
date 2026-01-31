use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};

use diffguard_diff::parse_unified_diff;
use diffguard_domain::{compile_rules, evaluate_lines, InputLine};
use diffguard_types::{
    CheckReceipt, DiffMeta, FailOn, Finding, ToolMeta, Verdict, VerdictCounts, VerdictStatus,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRun {
    pub receipt: CheckReceipt,
    pub markdown: String,
    pub annotations: Vec<String>,
    pub exit_code: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum PathFilterError {
    #[error("invalid path filter glob '{glob}': {source}")]
    InvalidGlob { glob: String, source: globset::Error },
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

    let rules = compile_rules(&config.rule)?;

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
    if evaluation.counts.error > 0 {
        reasons.push(format!("{} error(s)", evaluation.counts.error));
    }
    if evaluation.counts.warn > 0 {
        reasons.push(format!("{} warning(s)", evaluation.counts.warn));
    }
    if evaluation.truncated_findings > 0 {
        reasons.push(format!(
            "{} additional findings omitted (max_findings)",
            evaluation.truncated_findings
        ));
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
    };

    let markdown = crate::render::render_markdown_for_receipt(&receipt);
    let annotations = render_annotations(&receipt.findings);

    let exit_code = compute_exit_code(plan.fail_on, &receipt.verdict.counts);

    Ok(CheckRun {
        receipt,
        markdown,
        annotations,
        exit_code,
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

    #[test]
    fn exit_code_semantics() {
        let mut counts = VerdictCounts::default();
        assert_eq!(compute_exit_code(FailOn::Error, &counts), 0);

        counts.warn = 1;
        assert_eq!(compute_exit_code(FailOn::Error, &counts), 0);
        assert_eq!(compute_exit_code(FailOn::Warn, &counts), 3);

        counts.error = 1;
        assert_eq!(compute_exit_code(FailOn::Error, &counts), 2);
        assert_eq!(compute_exit_code(FailOn::Warn, &counts), 2);
        assert_eq!(compute_exit_code(FailOn::Never, &counts), 0);
    }
}
