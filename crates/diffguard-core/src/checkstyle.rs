//! Checkstyle XML output renderer.
//!
//! Converts CheckReceipt to Checkstyle XML format for integration with
//! CI systems that natively consume Checkstyle reports (SonarQube, Jenkins, GitLab CI).
//!
//! Schema reference: https://checkstyle.org/index.html

use std::collections::BTreeMap;

use super::xml_utils::escape_xml;
use diffguard_types::{CheckReceipt, Finding, Severity};

/// XML 1.0 declaration with UTF-8 encoding.
const XML_DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

/// Checkstyle root element — version 5.0 is the widely-supported canonical version.
const CHECKSTYLE_ROOT: &str = "<checkstyle version=\"5.0\">\n";

/// Renders a CheckReceipt as a Checkstyle XML report.
///
/// The Checkstyle format groups findings by file path:
/// ```xml
/// <?xml version="1.0" encoding="UTF-8"?>
/// <checkstyle version="5.0">
///   <file name="src/main.rs">
///     <error line="42" column="8" severity="warning" message="..." source="rule-id"/>
///   </file>
/// </checkstyle>
/// ```
///
/// Severity mapping:
/// - `Error` → "error"
/// - `Warn`  → "warning"
/// - `Info`  → "info"
///
/// Formats a single `<error>` element for a Checkstyle XML report.
///
/// The column attribute is only included when a column number is provided.
fn error_element(
    line: u32,
    column: Option<u32>,
    severity: &str,
    message: &str,
    rule_id: &str,
) -> String {
    let column_attr = column
        .map(|c| format!(" column=\"{c}\""))
        .unwrap_or_default();
    format!(
        "    <error line=\"{}\"{column_attr} severity=\"{}\" message=\"{}\" source=\"{}\"/>\n",
        line,
        severity,
        escape_xml(message),
        escape_xml(rule_id),
    )
}

pub fn render_checkstyle_for_receipt(receipt: &CheckReceipt) -> String {
    let mut out = String::new();

    // XML declaration
    out.push_str(XML_DECLARATION);

    // Root element — Checkstyle version 5.0 is the widely-supported canonical version
    out.push_str(CHECKSTYLE_ROOT);

    // Group findings by file path using BTreeMap for deterministic output
    let mut files: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in &receipt.findings {
        files.entry(f.path.clone()).or_default().push(f);
    }

    // Emit a <file> element per unique path
    for (path, findings) in &files {
        out.push_str(&format!("  <file name=\"{}\">\n", escape_xml(path)));
        for f in findings {
            let severity_str = match f.severity {
                Severity::Error => "error",
                Severity::Warn => "warning",
                Severity::Info => "info",
            };

            out.push_str(&error_element(
                f.line,
                f.column,
                severity_str,
                &f.message,
                &f.rule_id,
            ));
        }
        out.push_str("  </file>\n");
    }

    out.push_str("</checkstyle>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use diffguard_types::DiffMeta;
    use diffguard_types::ToolMeta;
    use diffguard_types::{Finding, Scope, Severity, Verdict, VerdictCounts, VerdictStatus};

    fn make_receipt(findings: Vec<Finding>) -> CheckReceipt {
        CheckReceipt {
            schema: "check-v1".into(),
            tool: ToolMeta {
                name: "diffguard".into(),
                version: "0.1.0".into(),
            },
            diff: DiffMeta {
                base: "abc".into(),
                head: "def".into(),
                context_lines: 3,
                scope: Scope::Added,
                files_scanned: 1,
                lines_scanned: 10,
            },
            findings,
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 1,
                    suppressed: 0,
                },
                reasons: vec!["2 findings found".into()],
            },
            timing: None,
        }
    }

    #[test]
    fn renders_checkstyle_xml_structure() {
        let findings = vec![
            Finding {
                rule_id: "no-secrets".into(),
                severity: Severity::Error,
                message: "Potential secret detected".into(),
                path: "src/main.rs".into(),
                line: 42,
                column: Some(8),
                match_text: "api_key = ".into(),
                snippet: "  api_key = \"hunter2\"".into(),
            },
            Finding {
                rule_id: "long-line".into(),
                severity: Severity::Warn,
                message: "Line exceeds 100 characters".into(),
                path: "src/main.rs".into(),
                line: 100,
                column: None,
                match_text: "...".into(),
                snippet: "...".into(),
            },
        ];
        let receipt = make_receipt(findings);
        let xml = render_checkstyle_for_receipt(&receipt);

        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<checkstyle version=\"5.0\">"));
        assert!(xml.contains("  <file name=\"src/main.rs\">"));
        assert!(xml.contains("    <error line=\"42\" column=\"8\" severity=\"error\""));
        assert!(xml.contains("    <error line=\"100\" severity=\"warning\""));
        assert!(xml.contains("</checkstyle>"));
    }

    #[test]
    fn escapes_xml_special_characters() {
        let findings = vec![Finding {
            rule_id: "x&y".into(),
            severity: Severity::Error,
            message: "Message with <brackets> and \"quotes\"".into(),
            path: "src/special'.rs".into(),
            line: 1,
            column: None,
            match_text: "".into(),
            snippet: "".into(),
        }];
        let receipt = make_receipt(findings);
        let xml = render_checkstyle_for_receipt(&receipt);

        assert!(xml.contains("&amp;")); // rule_id: x&y
        assert!(xml.contains("&lt;")); // message with <
        assert!(xml.contains("&gt;")); // message with >
        assert!(xml.contains("&quot;")); // message with "
        assert!(xml.contains("&apos;")); // path with '
        // Unescaped chars must NOT appear
        assert!(!xml.contains(" x&y "));
        assert!(!xml.contains(" <brackets>"));
    }

    #[test]
    fn info_maps_to_info() {
        let findings = vec![Finding {
            rule_id: "todo".into(),
            severity: Severity::Info,
            message: "TODO comment".into(),
            path: "src/lib.rs".into(),
            line: 10,
            column: None,
            match_text: "TODO".into(),
            snippet: "    // TODO: refactor".into(),
        }];
        let receipt = make_receipt(findings);
        let xml = render_checkstyle_for_receipt(&receipt);

        // Info should map to "info" in Checkstyle
        assert!(xml.contains("severity=\"info\""));
        assert!(!xml.contains("severity=\"warning\""));
    }

    #[test]
    fn column_omitted_when_none() {
        let findings = vec![Finding {
            rule_id: "no-tab".into(),
            severity: Severity::Warn,
            message: "Tab character".into(),
            path: "src/lib.rs".into(),
            line: 5,
            column: None,
            match_text: "\t".into(),
            snippet: "\tindented".into(),
        }];
        let receipt = make_receipt(findings);
        let xml = render_checkstyle_for_receipt(&receipt);

        // Should be "line" but no "column"
        assert!(xml.contains("line=\"5\""));
        assert!(!xml.contains("column="));
    }

    #[test]
    fn column_included_when_present() {
        let findings = vec![Finding {
            rule_id: "no-tab".into(),
            severity: Severity::Warn,
            message: "Tab character".into(),
            path: "src/lib.rs".into(),
            line: 5,
            column: Some(3),
            match_text: "\t".into(),
            snippet: "\tindented".into(),
        }];
        let receipt = make_receipt(findings);
        let xml = render_checkstyle_for_receipt(&receipt);

        assert!(xml.contains("column=\"3\""));
    }

    #[test]
    fn multiple_files_grouped_separately() {
        let findings = vec![
            Finding {
                rule_id: "no-secrets".into(),
                severity: Severity::Error,
                message: "Secret".into(),
                path: "src/a.rs".into(),
                line: 1,
                column: None,
                match_text: "".into(),
                snippet: "".into(),
            },
            Finding {
                rule_id: "no-secrets".into(),
                severity: Severity::Error,
                message: "Secret".into(),
                path: "src/b.rs".into(),
                line: 2,
                column: None,
                match_text: "".into(),
                snippet: "".into(),
            },
        ];
        let receipt = make_receipt(findings);
        let xml = render_checkstyle_for_receipt(&receipt);

        assert!(xml.contains("  <file name=\"src/a.rs\">"));
        assert!(xml.contains("  <file name=\"src/b.rs\">"));
    }

    #[test]
    fn empty_receipt_renders_valid_xml() {
        let receipt = make_receipt(vec![]);
        let xml = render_checkstyle_for_receipt(&receipt);

        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<checkstyle version=\"5.0\">"));
        assert!(xml.contains("</checkstyle>"));
    }
}
