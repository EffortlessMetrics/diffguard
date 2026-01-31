use diffguard_types::{CheckReceipt, Finding, VerdictStatus};

pub fn render_markdown_for_receipt(receipt: &CheckReceipt) -> String {
    let status = match receipt.verdict.status {
        VerdictStatus::Pass => "PASS",
        VerdictStatus::Warn => "WARN",
        VerdictStatus::Fail => "FAIL",
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

    if !receipt.verdict.reasons.is_empty() {
        out.push_str("**Verdict reasons:**\n");
        for r in &receipt.verdict.reasons {
            out.push_str(&format!("- {r}\n"));
        }
        out.push('\n');
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

pub fn render_markdown(findings: &[Finding]) -> String {
    let mut r = CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: diffguard_types::ToolMeta {
            name: "diffguard".to_string(),
            version: "0.0.0".to_string(),
        },
        diff: diffguard_types::DiffMeta {
            base: "".to_string(),
            head: "".to_string(),
            context_lines: 0,
            scope: diffguard_types::Scope::Added,
            files_scanned: 0,
            lines_scanned: 0,
        },
        findings: findings.to_vec(),
        verdict: diffguard_types::Verdict {
            status: VerdictStatus::Pass,
            counts: diffguard_types::VerdictCounts::default(),
            reasons: Vec::new(),
        },
    };

    render_markdown_for_receipt(&mut r)
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
                },
                reasons: vec!["1 warning".to_string()],
            },
        };

        let md = render_markdown_for_receipt(&receipt);
        assert!(md.contains("| Severity | Rule"));
        assert!(md.contains("src/lib.rs"));
    }
}
