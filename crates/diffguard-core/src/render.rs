use diffguard_types::{
    CheckReceipt, Finding, REASON_GIT_UNAVAILABLE, REASON_MISSING_BASE, REASON_NO_DIFF_INPUT,
    REASON_TOOL_ERROR, REASON_TRUNCATED, VerdictStatus,
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

/// Renders a CheckReceipt as a Markdown table for human-readable output.
///
/// Produces a markdown-formatted report with:
/// - Header with status (PASS/WARN/FAIL/SKIP)
/// - Scan summary (file count, line count, scope, base, head)
/// - Verdict reasons (only meta-level reasons like truncation/errors)
/// - Suppressed findings count if any
/// - Table of findings with severity, rule, location, message, and snippet
///
/// # Arguments
///
/// * `receipt` - The check receipt containing findings and verdict
///
/// # Returns
///
/// A markdown-formatted string suitable for console output or documentation.
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

/// Renders a single Finding as a markdown table row.
///
/// Escapes all special markdown characters in the finding fields to ensure
/// the table structure remains valid. The location is formatted as "path:line".
///
/// # Arguments
///
/// * `f` - The finding to render
///
/// # Returns
///
/// A markdown table row string with escaped cell contents.
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

/// Escapes special Markdown characters in table cell content.
///
/// Escapes pipe (`|`), backtick (`` ` ``), hash (`#`), asterisk (`*`),
/// underscore (`_`), open bracket (`[`), close bracket (`]`), and greater-than
/// (`>`) characters by prefixing with backslash. Also escapes CRLF (`\r\n`)
/// and LF (`\n`) line endings to prevent breaking the markdown table structure.
///
/// These escapes are needed to prevent breaking the markdown table structure
/// and prevent unintended markdown formatting.
fn escape_md(s: &str) -> String {
    s.replace('|', "\\|")
        .replace('`', "\\`")
        .replace('#', "\\#")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('>', "\\>")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
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

// =============================================================================
// Property-based tests for escape_md function
// =============================================================================

#[cfg(test)]
mod escape_md_properties {
    use super::*;
    use proptest::prelude::*;

    /// The set of special markdown characters that escape_md should escape.
    const SPECIAL_CHARS: &[char] = &['|', '`', '#', '*', '_', '[', ']', '>'];

    // ============================================================================
    // Property 1: Special characters are escaped (appear with backslash prefix)
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn property_special_char_pipe_is_escaped(s in "[^|]*[|][^|]*") {
            let result = escape_md(&s);
            // Every | in output should be preceded by backslash
            // Check: no unescaped | OR has escaped |
            prop_assert!(!result.contains('|') || result.contains("\\|"));
        }

        #[test]
        fn property_special_char_backtick_is_escaped(s in "[^`]*[`][^`]*") {
            let result = escape_md(&s);
            prop_assert!(!result.contains("`") || result.contains("\\`"));
        }

        #[test]
        fn property_special_char_hash_is_escaped(s in "[^#]*[#][^#]*") {
            let result = escape_md(&s);
            prop_assert!(!result.contains("#") || result.contains("\\#"));
        }

        #[test]
        fn property_special_char_asterisk_is_escaped(s in "[^*]*[*][^*]*") {
            let result = escape_md(&s);
            prop_assert!(!result.contains("*") || result.contains("\\*"));
        }

        #[test]
        fn property_special_char_underscore_is_escaped(s in "[^_]*[_][^_]*") {
            let result = escape_md(&s);
            prop_assert!(!result.contains("_") || result.contains("\\_"));
        }

        #[test]
        fn property_special_char_open_bracket_is_escaped(s in "[^\\[]*\\[[^\\[]*") {
            let result = escape_md(&s);
            prop_assert!(!result.contains("[") || result.contains("\\["));
        }

        #[test]
        fn property_special_char_close_bracket_is_escaped(s in "[^\\]]*\\][^\\]]*") {
            let result = escape_md(&s);
            prop_assert!(!result.contains("]") || result.contains("\\]"));
        }

        #[test]
        fn property_special_char_greater_than_is_escaped(s in "[^>]*[>][^>]*") {
            let result = escape_md(&s);
            prop_assert!(!result.contains(">") || result.contains("\\>"));
        }
    }

    // ============================================================================
    // Property 2: Non-special characters are preserved unchanged
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn property_non_special_chars_preserved(s in "[a-zA-Z0-9 \\t.,;:+-=(){}]{0,200}") {
            let result = escape_md(&s);
            // All these chars are not special, so they should pass through unchanged
            prop_assert_eq!(result, s, "non-special chars should be preserved");
        }

        #[test]
        fn property_alpha_numeric_preserved(s in "[a-zA-Z0-9]{0,500}") {
            let result = escape_md(&s);
            prop_assert_eq!(result, s, "alphanumeric should pass through unchanged");
        }
    }

    // ============================================================================
    // Property 3: Line endings are escaped
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn property_carriage_return_escaped(s1 in "[^\\r]*", s2 in ".*") {
            let input = format!("{}\r{}", s1, s2);
            let result = escape_md(&input);
            prop_assert!(!result.contains("\r"), "CR should be escaped to \\r");
            prop_assert!(result.contains("\\r"), "escaped CR should appear as \\r");
        }

        #[test]
        fn property_newline_escaped(s1 in "[^\\n]*", s2 in ".*") {
            let input = format!("{}\n{}", s1, s2);
            let result = escape_md(&input);
            prop_assert!(!result.contains("\n"), "LF should be escaped to \\n");
            prop_assert!(result.contains("\\n"), "escaped LF should appear as \\n");
        }
    }

    // ============================================================================
    // Property 4: Multiple special characters in various positions
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(300))]

        #[test]
        fn property_consecutive_special_chars(s in "[|*#*_\\[\\]>]{3,20}") {
            let result = escape_md(&s);

            // Count special chars in original
            let original_special_count: usize = s.chars().filter(|c| SPECIAL_CHARS.contains(c)).count();

            // Count escaped special chars in result (backslash followed by special char)
            let mut escaped_count = 0;
            let mut chars = result.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(&next) = chars.peek() {
                        if SPECIAL_CHARS.contains(&next) {
                            escaped_count += 1;
                            chars.next(); // consume the special char
                        }
                    }
                }
            }
            prop_assert_eq!(escaped_count, original_special_count,
                "all {} special chars should be escaped", original_special_count);
        }
    }

    // ============================================================================
    // Property 5: Strings at boundaries (empty, single char, very long)
    // ============================================================================

    #[test]
    fn property_escape_md_empty_string() {
        let result = escape_md("");
        assert_eq!(result, "", "empty string should produce empty string");
    }

    #[test]
    fn property_escape_md_single_special_char() {
        for c in SPECIAL_CHARS {
            let result = escape_md(&c.to_string());
            assert_eq!(
                result,
                format!("\\{}", c),
                "single {:?} should be escaped",
                c
            );
        }
    }

    #[test]
    fn property_escape_md_single_non_special_char() {
        for c in ['a', 'Z', '9', ' ', '\t', '.', ','] {
            let result = escape_md(&c.to_string());
            assert_eq!(
                result,
                c.to_string(),
                "non-special {:?} should pass through",
                c
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_long_string(s in "[a-zA-Z0-9 .,;:+-=_(){}|\\[`\\]>*#]{0,1000}") {
            let result = escape_md(&s);
            // Should not panic and should have reasonable output size
            prop_assert!(result.len() <= s.len() * 2, "output length should be bounded");
        }
    }

    // ============================================================================
    // Property 6: Backslash in input is preserved (not double-escaped)
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        #[test]
        fn property_backslash_preserved(s in "[^\\\\]*") {
            let input = format!("{}\\", s);
            let result = escape_md(&input);
            // Backslash should pass through unchanged
            prop_assert!(result.contains('\\'), "backslash should be preserved");
        }
    }
}
