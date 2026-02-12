//! CSV and TSV output renderers.
//!
//! Converts CheckReceipt to CSV or TSV format for spreadsheet/data analysis.
//! CSV follows RFC 4180 for proper escaping.

use diffguard_types::{CheckReceipt, Finding};

/// CSV header row.
const CSV_HEADER: &str = "file,line,rule_id,severity,message,snippet";

/// Renders a CheckReceipt as a CSV report (RFC 4180 compliant).
///
/// Columns: file, line, rule_id, severity, message, snippet
pub fn render_csv_for_receipt(receipt: &CheckReceipt) -> String {
    let mut out = String::new();

    // Header row
    out.push_str(CSV_HEADER);
    out.push('\n');

    // Data rows
    for f in &receipt.findings {
        out.push_str(&render_csv_row(f));
    }

    out
}

/// Renders a CheckReceipt as a TSV report.
///
/// Columns: file, line, rule_id, severity, message, snippet
pub fn render_tsv_for_receipt(receipt: &CheckReceipt) -> String {
    let mut out = String::new();

    // Header row
    out.push_str(&CSV_HEADER.replace(',', "\t"));
    out.push('\n');

    // Data rows
    for f in &receipt.findings {
        out.push_str(&render_tsv_row(f));
    }

    out
}

/// Renders a single finding as a CSV row.
fn render_csv_row(f: &Finding) -> String {
    format!(
        "{},{},{},{},{},{}\n",
        escape_csv_field(&f.path),
        f.line,
        escape_csv_field(&f.rule_id),
        f.severity.as_str(),
        escape_csv_field(&f.message),
        escape_csv_field(&f.snippet)
    )
}

/// Renders a single finding as a TSV row.
fn render_tsv_row(f: &Finding) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\n",
        escape_tsv_field(&f.path),
        f.line,
        escape_tsv_field(&f.rule_id),
        f.severity.as_str(),
        escape_tsv_field(&f.message),
        escape_tsv_field(&f.snippet)
    )
}

/// Escapes a field for CSV according to RFC 4180.
///
/// Fields containing commas, double quotes, or newlines are quoted.
/// Double quotes within the field are escaped by doubling them.
fn escape_csv_field(s: &str) -> String {
    let needs_quoting = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');

    if needs_quoting {
        let escaped = s.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        s.to_string()
    }
}

/// Escapes a field for TSV.
///
/// Tabs and newlines are escaped with backslash notation.
fn escape_tsv_field(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::{
        CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
        VerdictCounts, VerdictStatus,
    };

    fn create_test_receipt_with_findings() -> CheckReceipt {
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 3,
                lines_scanned: 42,
            },
            findings: vec![
                Finding {
                    rule_id: "rust.no_unwrap".to_string(),
                    severity: Severity::Error,
                    message: "Avoid unwrap/expect in production code.".to_string(),
                    path: "src/lib.rs".to_string(),
                    line: 15,
                    column: Some(10),
                    match_text: ".unwrap()".to_string(),
                    snippet: "let value = result.unwrap();".to_string(),
                },
                Finding {
                    rule_id: "rust.no_dbg".to_string(),
                    severity: Severity::Warn,
                    message: "Remove dbg!/println! before merging.".to_string(),
                    path: "src/main.rs".to_string(),
                    line: 23,
                    column: Some(5),
                    match_text: "dbg!".to_string(),
                    snippet: "    dbg!(config);".to_string(),
                },
            ],
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 1,
                    ..Default::default()
                },
                reasons: vec![
                    "1 error-level finding".to_string(),
                    "1 warning-level finding".to_string(),
                ],
            },
            timing: None,
        }
    }

    fn create_test_receipt_empty() -> CheckReceipt {
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 5,
                lines_scanned: 120,
            },
            findings: vec![],
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: VerdictCounts::default(),
                reasons: vec![],
            },
            timing: None,
        }
    }

    fn create_test_receipt_with_special_chars() -> CheckReceipt {
        CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "origin/main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 1,
                lines_scanned: 10,
            },
            findings: vec![Finding {
                rule_id: "test.rule".to_string(),
                severity: Severity::Warn,
                message: "Message with \"quotes\" and, commas".to_string(),
                path: "src/file.rs".to_string(),
                line: 5,
                column: None,
                match_text: "test".to_string(),
                snippet: "let s = \"hello\nworld\";".to_string(),
            }],
            verdict: Verdict {
                status: VerdictStatus::Warn,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 0,
                    ..Default::default()
                },
                reasons: vec!["1 warning".to_string()],
            },
            timing: None,
        }
    }

    // ==================== CSV Tests ====================

    #[test]
    fn csv_has_header_row() {
        let receipt = create_test_receipt_empty();
        let csv = render_csv_for_receipt(&receipt);
        assert!(csv.starts_with("file,line,rule_id,severity,message,snippet\n"));
    }

    #[test]
    fn csv_has_correct_row_count() {
        let receipt = create_test_receipt_with_findings();
        let csv = render_csv_for_receipt(&receipt);
        let lines: Vec<&str> = csv.lines().collect();
        // 1 header + 2 data rows
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn csv_empty_receipt_has_header_only() {
        let receipt = create_test_receipt_empty();
        let csv = render_csv_for_receipt(&receipt);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "file,line,rule_id,severity,message,snippet");
    }

    #[test]
    fn csv_escapes_quotes() {
        let receipt = create_test_receipt_with_special_chars();
        let csv = render_csv_for_receipt(&receipt);
        // Quotes in message should be escaped as ""
        assert!(csv.contains("\"\"quotes\"\""));
    }

    #[test]
    fn csv_escapes_commas() {
        let receipt = create_test_receipt_with_special_chars();
        let csv = render_csv_for_receipt(&receipt);
        // Field with comma should be quoted
        assert!(csv.contains("\"Message with"));
    }

    #[test]
    fn csv_escapes_newlines() {
        let receipt = create_test_receipt_with_special_chars();
        let csv = render_csv_for_receipt(&receipt);
        // Snippet with newline should be quoted
        assert!(csv.contains("\"let s = \"\"hello"));
    }

    // ==================== TSV Tests ====================

    #[test]
    fn tsv_has_header_row() {
        let receipt = create_test_receipt_empty();
        let tsv = render_tsv_for_receipt(&receipt);
        assert!(tsv.starts_with("file\tline\trule_id\tseverity\tmessage\tsnippet\n"));
    }

    #[test]
    fn tsv_has_correct_row_count() {
        let receipt = create_test_receipt_with_findings();
        let tsv = render_tsv_for_receipt(&receipt);
        let lines: Vec<&str> = tsv.lines().collect();
        // 1 header + 2 data rows
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn tsv_empty_receipt_has_header_only() {
        let receipt = create_test_receipt_empty();
        let tsv = render_tsv_for_receipt(&receipt);
        let lines: Vec<&str> = tsv.lines().collect();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn tsv_escapes_tabs() {
        let mut receipt = create_test_receipt_with_findings();
        receipt.findings[0].snippet = "let\tx = 1;".to_string();
        let tsv = render_tsv_for_receipt(&receipt);
        // Tab in snippet should be escaped
        assert!(tsv.contains("let\\tx = 1;"));
    }

    #[test]
    fn tsv_escapes_newlines() {
        let receipt = create_test_receipt_with_special_chars();
        let tsv = render_tsv_for_receipt(&receipt);
        // Newline in snippet should be escaped as \n
        assert!(tsv.contains("hello\\nworld"));
    }

    // ==================== Field Escaping Tests ====================

    #[test]
    fn escape_csv_field_plain_text() {
        assert_eq!(escape_csv_field("plain text"), "plain text");
    }

    #[test]
    fn escape_csv_field_with_comma() {
        assert_eq!(escape_csv_field("a,b"), "\"a,b\"");
    }

    #[test]
    fn escape_csv_field_with_quote() {
        assert_eq!(escape_csv_field("say \"hello\""), "\"say \"\"hello\"\"\"");
    }

    #[test]
    fn escape_csv_field_with_newline() {
        assert_eq!(escape_csv_field("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn escape_csv_field_with_carriage_return() {
        assert_eq!(escape_csv_field("line1\rline2"), "\"line1\rline2\"");
    }

    #[test]
    fn escape_tsv_field_plain_text() {
        assert_eq!(escape_tsv_field("plain text"), "plain text");
    }

    #[test]
    fn escape_tsv_field_with_tab() {
        assert_eq!(escape_tsv_field("a\tb"), "a\\tb");
    }

    #[test]
    fn escape_tsv_field_with_newline() {
        assert_eq!(escape_tsv_field("a\nb"), "a\\nb");
    }

    #[test]
    fn escape_tsv_field_with_carriage_return() {
        assert_eq!(escape_tsv_field("a\rb"), "a\\rb");
    }

    #[test]
    fn escape_tsv_field_with_backslash() {
        assert_eq!(escape_tsv_field("a\\b"), "a\\\\b");
    }

    // ==================== Snapshot Tests ====================

    #[test]
    fn snapshot_csv_with_findings() {
        let receipt = create_test_receipt_with_findings();
        let csv = render_csv_for_receipt(&receipt);
        insta::assert_snapshot!(csv);
    }

    #[test]
    fn snapshot_csv_no_findings() {
        let receipt = create_test_receipt_empty();
        let csv = render_csv_for_receipt(&receipt);
        insta::assert_snapshot!(csv);
    }

    #[test]
    fn snapshot_tsv_with_findings() {
        let receipt = create_test_receipt_with_findings();
        let tsv = render_tsv_for_receipt(&receipt);
        insta::assert_snapshot!(tsv);
    }

    #[test]
    fn snapshot_tsv_no_findings() {
        let receipt = create_test_receipt_empty();
        let tsv = render_tsv_for_receipt(&receipt);
        insta::assert_snapshot!(tsv);
    }

    #[test]
    fn snapshot_csv_special_chars() {
        let receipt = create_test_receipt_with_special_chars();
        let csv = render_csv_for_receipt(&receipt);
        insta::assert_snapshot!(csv);
    }

    #[test]
    fn snapshot_tsv_special_chars() {
        let receipt = create_test_receipt_with_special_chars();
        let tsv = render_tsv_for_receipt(&receipt);
        insta::assert_snapshot!(tsv);
    }
}
