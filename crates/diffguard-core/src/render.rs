use diffguard_types::{
    CheckReceipt, Finding, VerdictStatus, REASON_GIT_UNAVAILABLE, REASON_MISSING_BASE,
    REASON_NO_DIFF_INPUT, REASON_TOOL_ERROR, REASON_TRUNCATED,
};

/// Reasons that are meaningful to render in markdown output.
/// Only meta conditions (truncation, skip reasons, tool errors) should appear.
const RENDERABLE_META_REASONS: &[&str] = &[
    REASON_TRUNCATED,
    REASON_MISSING_BASE,
    REASON_NO_DIFF_INPUT,
    REASON_GIT_UNAVAILABLE,
    REASON_TOOL_ERROR,
];

pub fn render_markdown_for_receipt(receipt: &CheckReceipt) -> String {
    let status = match receipt.verdict.status {
        VerdictStatus::Pass => "PASS",
        VerdictStatus::Warn => "WARN",
        VerdictStatus::Fail => "FAIL",
        VerdictStatus::Skip => "SKIP",
    };

    let mut out = String::new();
    out.push_str(&format!("## diffguard — {status}\n\n"));

    out.push_str(&format!(
        "Scanned **{}** file(s), **{}** line(s) (scope: `{}`, base: `{}`, head: `{}`)\n\n",
        receipt.diff.files_scanned,
        receipt.diff.lines_scanned,
        receipt.diff.scope.as_str(),
        receipt.diff.base,
        receipt.diff.head
    ));

    let meta_reasons: Vec<&String> = receipt
        .verdict
        .reasons
        .iter()
        .filter(|r| RENDERABLE_META_REASONS.contains(&r.as_str()))
        .collect();
    if !meta_reasons.is_empty() {
        out.push_str("**Verdict reasons:**\n");
        for r in &meta_reasons {
            out.push_str(&format!("- {r}\n"));
        }
        out.push('\n');
    }

    if receipt.verdict.counts.suppressed > 0 {
        out.push_str(&format!(
            "**Note:** {} finding(s) suppressed via inline directives.\n\n",
            receipt.verdict.counts.suppressed
        ));
    }

    if receipt.findings.is_empty() {
        out.push_str("No findings.\n");
        return out;
    }

    out.push_str("| Severity | Rule | Location | Message | Snippet |\n");
    out.push_str("|---|---|---|---|---|\n");

    for f in &receipt.findings {
        out.push_str(&render_finding_row(f));
    }

    out.push('\n');
    out
}

fn render_finding_row(f: &Finding) -> String {
    let sev = f.severity.as_str();
    let loc = format!("{}:{}", escape_md(&f.path), f.line);
    let msg = escape_md(&f.message);
    let snippet = escape_md(&f.snippet);

    format!(
        "| {sev} | `{rule}` | `{loc}` | {msg} | `{snippet}` |\n",
        sev = sev,
        rule = escape_md(&f.rule_id),
        loc = loc,
        msg = msg,
        snippet = snippet
    )
}

fn escape_md(s: &str) -> String {
    s.replace('|', "\\|").replace('`', "\\`")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_markdown_table() {
        let receipt = CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: diffguard_types::Scope::Added,
                files_scanned: 1,
                lines_scanned: 1,
            },
            findings: vec![Finding {
                rule_id: "r".to_string(),
                severity: diffguard_types::Severity::Warn,
                message: "m".to_string(),
                path: "src/lib.rs".to_string(),
                line: 1,
                column: Some(3),
                match_text: "unwrap".to_string(),
                snippet: "x.unwrap()".to_string(),
            }],
            verdict: diffguard_types::Verdict {
                status: VerdictStatus::Warn,
                counts: diffguard_types::VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 0,
                    ..Default::default()
                },
                reasons: vec![],
            },
            timing: None,
        };

        let md = render_markdown_for_receipt(&receipt);
        assert!(md.contains("| Severity | Rule"));
        assert!(md.contains("src/lib.rs"));
    }

    #[test]
    fn render_finding_row_escapes_pipes_and_backticks() {
        let finding = Finding {
            rule_id: "rule|id`tick".to_string(),
            severity: diffguard_types::Severity::Warn,
            message: "message with | and `ticks`".to_string(),
            path: "src/lib|name`.rs".to_string(),
            line: 7,
            column: Some(1),
            match_text: "match".to_string(),
            snippet: "snippet with `code` | pipe".to_string(),
        };

        let row = render_finding_row(&finding);

        assert!(row.contains("rule\\|id\\`tick"));
        assert!(row.contains("src/lib\\|name\\`.rs:7"));
        assert!(row.contains("message with \\| and \\`ticks\\`"));
        assert!(row.contains("snippet with \\`code\\` \\| pipe"));
    }

    /// Helper to create a test receipt with multiple findings
    fn create_test_receipt_with_findings() -> CheckReceipt {
        CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: diffguard_types::Scope::Added,
                files_scanned: 3,
                lines_scanned: 42,
            },
            findings: vec![
                Finding {
                    rule_id: "rust.no_unwrap".to_string(),
                    severity: diffguard_types::Severity::Error,
                    message: "Avoid unwrap/expect in production code.".to_string(),
                    path: "src/lib.rs".to_string(),
                    line: 15,
                    column: Some(10),
                    match_text: ".unwrap()".to_string(),
                    snippet: "let value = result.unwrap();".to_string(),
                },
                Finding {
                    rule_id: "rust.no_dbg".to_string(),
                    severity: diffguard_types::Severity::Warn,
                    message: "Remove dbg!/println! before merging.".to_string(),
                    path: "src/main.rs".to_string(),
                    line: 23,
                    column: Some(5),
                    match_text: "dbg!".to_string(),
                    snippet: "    dbg!(config);".to_string(),
                },
                Finding {
                    rule_id: "python.no_print".to_string(),
                    severity: diffguard_types::Severity::Warn,
                    message: "Remove print() before merging.".to_string(),
                    path: "scripts/deploy.py".to_string(),
                    line: 8,
                    column: None,
                    match_text: "print(".to_string(),
                    snippet: "print(\"Deploying...\")".to_string(),
                },
            ],
            verdict: diffguard_types::Verdict {
                status: VerdictStatus::Fail,
                counts: diffguard_types::VerdictCounts {
                    info: 0,
                    warn: 2,
                    error: 1,
                    ..Default::default()
                },
                reasons: vec![],
            },
            timing: None,
        }
    }

    /// Helper to create a test receipt with no findings
    fn create_test_receipt_empty() -> CheckReceipt {
        CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: diffguard_types::Scope::Added,
                files_scanned: 5,
                lines_scanned: 120,
            },
            findings: vec![],
            verdict: diffguard_types::Verdict {
                status: VerdictStatus::Pass,
                counts: diffguard_types::VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 0,
                    suppressed: 0,
                },
                reasons: vec![],
            },
            timing: None,
        }
    }

    /// Helper to create a test receipt for verdict rendering (WARN status)
    fn create_test_receipt_warn_verdict() -> CheckReceipt {
        CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "feature/branch".to_string(),
                head: "HEAD".to_string(),
                context_lines: 3,
                scope: diffguard_types::Scope::Changed,
                files_scanned: 2,
                lines_scanned: 35,
            },
            findings: vec![Finding {
                rule_id: "js.no_console".to_string(),
                severity: diffguard_types::Severity::Warn,
                message: "Remove console.log before merging.".to_string(),
                path: "src/utils.ts".to_string(),
                line: 42,
                column: Some(3),
                match_text: "console.log".to_string(),
                snippet: "  console.log(\"debug info\");".to_string(),
            }],
            verdict: diffguard_types::Verdict {
                status: VerdictStatus::Warn,
                counts: diffguard_types::VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 0,
                    ..Default::default()
                },
                reasons: vec![],
            },
            timing: None,
        }
    }

    /// Snapshot test for markdown output with findings.
    /// Validates: Requirements 7.1, 7.2
    #[test]
    fn snapshot_markdown_with_findings() {
        let receipt = create_test_receipt_with_findings();
        let md = render_markdown_for_receipt(&receipt);
        insta::assert_snapshot!(md);
    }

    /// Snapshot test for markdown output with no findings.
    /// Validates: Requirements 7.1, 7.4
    #[test]
    fn snapshot_markdown_no_findings() {
        let receipt = create_test_receipt_empty();
        let md = render_markdown_for_receipt(&receipt);
        insta::assert_snapshot!(md);
    }

    /// Snapshot test for verdict rendering (WARN status with reasons).
    /// Validates: Requirements 7.1, 7.3
    #[test]
    fn snapshot_verdict_rendering() {
        let receipt = create_test_receipt_warn_verdict();
        let md = render_markdown_for_receipt(&receipt);
        insta::assert_snapshot!(md);
    }

    /// Helper to create a test receipt with suppressed findings
    fn create_test_receipt_with_suppressions() -> CheckReceipt {
        CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: diffguard_types::Scope::Added,
                files_scanned: 2,
                lines_scanned: 30,
            },
            findings: vec![Finding {
                rule_id: "rust.no_dbg".to_string(),
                severity: diffguard_types::Severity::Warn,
                message: "Remove dbg!/println! before merging.".to_string(),
                path: "src/main.rs".to_string(),
                line: 10,
                column: Some(5),
                match_text: "dbg!".to_string(),
                snippet: "    dbg!(value);".to_string(),
            }],
            verdict: diffguard_types::Verdict {
                status: VerdictStatus::Warn,
                counts: diffguard_types::VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 0,
                    suppressed: 3,
                },
                reasons: vec![],
            },
            timing: None,
        }
    }

    /// Test that suppressed findings are shown in markdown output.
    #[test]
    fn markdown_shows_suppressed_count() {
        let receipt = create_test_receipt_with_suppressions();
        let md = render_markdown_for_receipt(&receipt);
        assert!(md.contains("3 finding(s) suppressed via inline directives"));
    }

    /// Test that suppression note is not shown when count is zero.
    #[test]
    fn markdown_hides_suppressed_when_zero() {
        let receipt = create_test_receipt_empty();
        let md = render_markdown_for_receipt(&receipt);
        assert!(!md.contains("suppressed"));
    }

    /// Snapshot test for markdown output with suppressed findings.
    #[test]
    fn snapshot_markdown_with_suppressions() {
        let receipt = create_test_receipt_with_suppressions();
        let md = render_markdown_for_receipt(&receipt);
        insta::assert_snapshot!(md);
    }

    /// Test that non-meta reasons (e.g. has_error, has_warning) are filtered out.
    #[test]
    fn markdown_filters_non_meta_reasons() {
        let receipt = CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: diffguard_types::Scope::Added,
                files_scanned: 1,
                lines_scanned: 1,
            },
            findings: vec![],
            verdict: diffguard_types::Verdict {
                status: VerdictStatus::Fail,
                counts: diffguard_types::VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 1,
                    suppressed: 0,
                },
                reasons: vec![
                    diffguard_types::REASON_HAS_ERROR.to_string(),
                    diffguard_types::REASON_HAS_WARNING.to_string(),
                    "unknown_future_reason".to_string(),
                ],
            },
            timing: None,
        };

        let md = render_markdown_for_receipt(&receipt);
        assert!(
            !md.contains("Verdict reasons"),
            "non-meta reasons should not render"
        );
        assert!(!md.contains("has_error"));
        assert!(!md.contains("has_warning"));
        assert!(!md.contains("unknown_future_reason"));
    }

    /// Test that all 5 meta reasons pass through the filter.
    #[test]
    fn markdown_renders_all_meta_reasons() {
        let receipt = CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: diffguard_types::Scope::Added,
                files_scanned: 0,
                lines_scanned: 0,
            },
            findings: vec![],
            verdict: diffguard_types::Verdict {
                status: VerdictStatus::Skip,
                counts: diffguard_types::VerdictCounts::default(),
                reasons: vec![
                    REASON_TRUNCATED.to_string(),
                    REASON_MISSING_BASE.to_string(),
                    REASON_NO_DIFF_INPUT.to_string(),
                    REASON_GIT_UNAVAILABLE.to_string(),
                    REASON_TOOL_ERROR.to_string(),
                ],
            },
            timing: None,
        };

        let md = render_markdown_for_receipt(&receipt);
        assert!(md.contains("Verdict reasons"), "meta reasons should render");
        assert!(md.contains("- truncated"));
        assert!(md.contains("- missing_base"));
        assert!(md.contains("- no_diff_input"));
        assert!(md.contains("- git_unavailable"));
        assert!(md.contains("- tool_error"));
    }
}
