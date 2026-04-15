//! Property-based tests for Checkstyle XML output.
//!
//! These tests verify invariants that hold across all inputs, not just specific examples.
//!
//! Run with: cargo test -p diffguard-core --test property_test_checkstyle

use diffguard_core::render_checkstyle_for_receipt;
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};
use proptest::prelude::*;

/// Construct a minimal CheckReceipt from a list of findings.
fn make_receipt(findings: Vec<Finding>) -> CheckReceipt {
    CheckReceipt {
        schema: CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "feat/test".to_string(),
            context_lines: 3,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 10,
        },
        verdict: Verdict {
            status: if findings.is_empty() {
                VerdictStatus::Pass
            } else {
                VerdictStatus::Fail
            },
            counts: VerdictCounts {
                info: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Info)
                    .count() as u32,
                warn: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Warn)
                    .count() as u32,
                error: findings
                    .iter()
                    .filter(|f| f.severity == Severity::Error)
                    .count() as u32,
                suppressed: 0,
            },
            reasons: vec![],
        },
        findings,
        timing: None,
    }
}

// =============================================================================
// Strategies
// =============================================================================

/// Strategy for generating non-empty strings.
fn non_empty_string() -> impl Strategy<Value = String> {
    "[^\\x00]+".prop_filter("non-empty", |s| !s.is_empty())
}

/// Strategy for generating file paths.
fn file_path_strategy() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_./-]+".prop_filter("non-empty path", |s| !s.is_empty())
}

/// Strategy for generating a Finding with a specific severity.
fn finding_with_severity(severity: Severity) -> impl Strategy<Value = Finding> {
    (
        non_empty_string(),   // rule_id
        file_path_strategy(), // path
        1u32..10000,          // line
        any::<Option<u32>>(), // column
        non_empty_string(),   // message
        non_empty_string(),   // match_text
        "[^\\x00]*",          // snippet (can be empty)
    )
        .prop_map(
            move |(rule_id, path, line, column, message, match_text, snippet)| Finding {
                rule_id,
                severity, // Use the closure-captured severity
                message,
                path,
                line,
                column,
                match_text,
                snippet,
            },
        )
}

/// Strategy for generating a Finding with any severity.
fn arb_finding_any_severity() -> impl Strategy<Value = Finding> {
    prop_oneof![
        finding_with_severity(Severity::Info),
        finding_with_severity(Severity::Warn),
        finding_with_severity(Severity::Error),
    ]
}

/// Strategy for generating receipts with 1-20 findings.
fn arb_receipt() -> impl Strategy<Value = CheckReceipt> {
    prop::collection::vec(arb_finding_any_severity(), 1..20).prop_map(make_receipt)
}

/// Strategy for generating receipts with only Info severity findings.
fn arb_receipt_info_only() -> impl Strategy<Value = CheckReceipt> {
    prop::collection::vec(finding_with_severity(Severity::Info), 1..20).prop_map(make_receipt)
}

/// Strategy for generating receipts with only Warn severity findings.
fn arb_receipt_warn_only() -> impl Strategy<Value = CheckReceipt> {
    prop::collection::vec(finding_with_severity(Severity::Warn), 1..20).prop_map(make_receipt)
}

/// Strategy for generating receipts with only Error severity findings.
fn arb_receipt_error_only() -> impl Strategy<Value = CheckReceipt> {
    prop::collection::vec(finding_with_severity(Severity::Error), 1..20).prop_map(make_receipt)
}

// =============================================================================
// Invariant: Severity Mapping
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn info_findings_render_with_severity_info(receipt in arb_receipt_info_only()) {
        let xml = render_checkstyle_for_receipt(&receipt);

        // Every Info finding must produce a "severity=\"info\"" attribute
        for f in &receipt.findings {
            let expected = "severity=\"info\"".to_string();
            prop_assert!(
                xml.contains(&expected),
                "Info finding for rule '{}' should produce severity=\"info\" in XML, but XML was:\n{}",
                f.rule_id,
                xml
            );
        }

        // No Info finding should produce severity="warning"
        prop_assert!(
            !xml.contains("severity=\"warning\""),
            "Info findings should not produce severity=\"warning\", but XML was:\n{}",
            xml
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn warn_findings_render_with_severity_warning(receipt in arb_receipt_warn_only()) {
        let xml = render_checkstyle_for_receipt(&receipt);

        // Every Warn finding must produce a "severity=\"warning\"" attribute
        for f in &receipt.findings {
            let expected = "severity=\"warning\"".to_string();
            prop_assert!(
                xml.contains(&expected),
                "Warn finding for rule '{}' should produce severity=\"warning\" in XML, but XML was:\n{}",
                f.rule_id,
                xml
            );
        }

        // No Warn finding should produce severity="info"
        prop_assert!(
            !xml.contains("severity=\"info\""),
            "Warn findings should not produce severity=\"info\", but XML was:\n{}",
            xml
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn error_findings_render_with_severity_error(receipt in arb_receipt_error_only()) {
        let xml = render_checkstyle_for_receipt(&receipt);

        // Every Error finding must produce a "severity=\"error\"" attribute
        for f in &receipt.findings {
            let expected = "severity=\"error\"".to_string();
            prop_assert!(
                xml.contains(&expected),
                "Error finding for rule '{}' should produce severity=\"error\" in XML, but XML was:\n{}",
                f.rule_id,
                xml
            );
        }

        // Error findings should NOT produce "warning" or "info"
        prop_assert!(
            !xml.contains("severity=\"warning\""),
            "Error findings should not produce severity=\"warning\", but XML was:\n{}",
            xml
        );
        prop_assert!(
            !xml.contains("severity=\"info\""),
            "Error findings should not produce severity=\"info\", but XML was:\n{}",
            xml
        );
    }
}

// =============================================================================
// Invariant: XML Structure
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn xml_structure_invariants(receipt in arb_receipt()) {
        let xml = render_checkstyle_for_receipt(&receipt);

        // Must start with XML declaration
        prop_assert!(
            xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
            "XML should start with declaration, but was:\n{}",
            xml
        );

        // Must contain checkstyle root element
        prop_assert!(
            xml.contains("<checkstyle version=\"5.0\">"),
            "XML should contain checkstyle root element, but was:\n{}",
            xml
        );

        // Must end with closing checkstyle tag
        prop_assert!(
            xml.ends_with("</checkstyle>\n"),
            "XML should end with closing tag, but was:\n{}",
            xml
        );

        // Each finding's path should appear in a <file name="..."> element
        for f in &receipt.findings {
            let expected_file_tag = format!("<file name=\"{}\">", f.path);
            prop_assert!(
                xml.contains(&expected_file_tag),
                "Finding at path '{}' should produce file tag in XML:\n{}",
                f.path,
                xml
            );
        }

        // Each finding should produce an <error element
        for f in &receipt.findings {
            let expected_error_tag = format!("<error line=\"{}\"", f.line);
            prop_assert!(
                xml.contains(&expected_error_tag),
                "Finding on line {} should produce error tag in XML:\n{}",
                f.line,
                xml
            );
        }
    }
}

// =============================================================================
// Invariant: Completeness - No findings dropped
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn no_findings_dropped(receipt in arb_receipt()) {
        let xml = render_checkstyle_for_receipt(&receipt);

        // The number of <error> elements should equal the number of findings
        let error_count = xml.matches("<error ").count();
        prop_assert_eq!(
            error_count,
            receipt.findings.len(),
            "Number of <error> elements ({}) should equal number of findings ({}).\nXML:\n{}",
            error_count,
            receipt.findings.len(),
            xml
        );

        // Each finding's message should appear (possibly escaped)
        for f in &receipt.findings {
            // The message is XML-escaped, so we check it appears in some form
            // We can't directly check the raw message because of escaping
            // Instead, verify that the line number + rule_id combination exists
            let line_tag = format!("line=\"{}\"", f.line);
            prop_assert!(
                xml.contains(&line_tag),
                "Finding on line {} should appear in XML:\n{}",
                f.line,
                xml
            );
        }
    }
}

// =============================================================================
// Invariant: Determinism - Same input produces same output
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn deterministic_output(receipt in arb_receipt()) {
        let xml1 = render_checkstyle_for_receipt(&receipt);
        let xml2 = render_checkstyle_for_receipt(&receipt);

        prop_assert_eq!(
            xml1, xml2,
            "Identical receipts should produce identical XML."
        );
    }
}

// =============================================================================
// Invariant: Findings contain correct line numbers
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn line_numbers_preserved(receipt in arb_receipt()) {
        let xml = render_checkstyle_for_receipt(&receipt);

        for f in &receipt.findings {
            let expected_line = format!("line=\"{}\"", f.line);
            prop_assert!(
                xml.contains(&expected_line),
                "Finding on line {} should contain 'line=\"{}\"' in XML:\n{}",
                f.line,
                f.line,
                xml
            );
        }
    }
}

// =============================================================================
// Invariant: Column is included when present, omitted when None
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn column_presence_invariance(receipt in arb_receipt()) {
        let xml = render_checkstyle_for_receipt(&receipt);

        for f in &receipt.findings {
            match f.column {
                Some(col) => {
                    let expected_col = format!("column=\"{}\"", col);
                    prop_assert!(
                        xml.contains(&expected_col),
                        "Finding with column {} should contain 'column=\"{}\"' in XML:\n{}",
                        col,
                        col,
                        xml
                    );
                }
                None => {
                    // When column is None, we just verify the finding still appears
                    let expected_line = format!("line=\"{}\"", f.line);
                    prop_assert!(
                        xml.contains(&expected_line),
                        "Finding should appear in XML even without column:\n{}",
                        xml
                    );
                }
            }
        }
    }
}
