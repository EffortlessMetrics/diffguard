//! Property-based tests for JUnit XML output.
//!
//! These tests verify invariants that hold across all inputs, not just specific examples.
//!
//! Run with: cargo test -p diffguard-core --test property_test_junit

use diffguard_core::render_junit_for_receipt;
use diffguard_types::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};
use proptest::prelude::*;

/// Count occurrences of a substring.
fn count_occurrences(s: &str, sub: &str) -> usize {
    s.matches(sub).count()
}

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

/// Strategy for generating non-empty strings (no null chars).
fn non_empty_string() -> impl Strategy<Value = String> {
    "[^\x00]+".prop_filter("non-empty", |s| !s.is_empty())
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
        "[^\x00]*",           // snippet (can be empty, but no nulls)
    )
        .prop_map(
            move |(rule_id, path, line, column, message, match_text, snippet)| Finding {
                rule_id,
                severity,
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

/// Strategy for generating receipts with 1-20 findings, all Info severity.
fn arb_receipt_info_only() -> impl Strategy<Value = CheckReceipt> {
    prop::collection::vec(finding_with_severity(Severity::Info), 1..20).prop_map(make_receipt)
}

/// Strategy for generating receipts with 1-20 findings, all Warn severity.
fn arb_receipt_warn_only() -> impl Strategy<Value = CheckReceipt> {
    prop::collection::vec(finding_with_severity(Severity::Warn), 1..20).prop_map(make_receipt)
}

/// Strategy for generating receipts with 1-20 findings, all Error severity.
fn arb_receipt_error_only() -> impl Strategy<Value = CheckReceipt> {
    prop::collection::vec(finding_with_severity(Severity::Error), 1..20).prop_map(make_receipt)
}

/// Strategy for generating receipts with 1-20 findings, mixed Warn and Error only.
fn arb_receipt_warn_error_mixed() -> impl Strategy<Value = CheckReceipt> {
    prop::collection::vec(
        prop_oneof![
            finding_with_severity(Severity::Warn),
            finding_with_severity(Severity::Error),
        ],
        1..20,
    )
    .prop_map(make_receipt)
}

/// Strategy for generating receipts with 0 findings (empty).
fn arb_receipt_empty() -> impl Strategy<Value = CheckReceipt> {
    Just(make_receipt(vec![]))
}

/// Strategy for generating receipts with many findings (20-50).
fn arb_receipt_large() -> impl Strategy<Value = CheckReceipt> {
    prop::collection::vec(arb_finding_any_severity(), 20..50).prop_map(make_receipt)
}

// =============================================================================
// Invariant: XML Declaration
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn xml_always_starts_with_xml_declaration(receipt in arb_receipt()) {
        let xml = render_junit_for_receipt(&receipt);
        prop_assert!(
            xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
            "JUnit XML should start with XML declaration, but was: {}",
            &xml[..xml.len().min(100)]
        );
    }
}

// =============================================================================
// Invariant: Root Element Structure
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn has_testsuites_root_element(receipt in arb_receipt()) {
        let xml = render_junit_for_receipt(&receipt);
        prop_assert!(
            xml.contains("<testsuites name=\"diffguard\""),
            "XML should contain '<testsuites name=\"diffguard\"', but was: {}",
            &xml[..xml.len().min(200)]
        );
    }

    #[test]
    fn has_closing_testsuites_tag(receipt in arb_receipt()) {
        let xml = render_junit_for_receipt(&receipt);
        prop_assert!(
            xml.contains("</testsuites>"),
            "XML should contain '</testsuites>', but was: {}",
            xml
        );
    }
}

// =============================================================================
// Invariant: Test Count Consistency (using testcase counting)
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn testcase_count_equals_findings_count(receipt in arb_receipt()) {
        let xml = render_junit_for_receipt(&receipt);
        let finding_count = receipt.findings.len();

        // Count <testcase ...> opening tags - each finding produces one testcase
        let testcase_count = count_occurrences(&xml, "<testcase classname=");

        prop_assert_eq!(
            testcase_count, finding_count,
            "Number of testcases {} should equal number of findings {}",
            testcase_count, finding_count
        );
    }

    #[test]
    fn empty_receipt_has_no_findings_testcase(receipt in arb_receipt_empty()) {
        let xml = render_junit_for_receipt(&receipt);
        prop_assert!(
            xml.contains("name=\"no_findings\""),
            "Empty receipt should have testcase with name=\"no_findings\", but XML was: {}",
            xml
        );
    }
}

// =============================================================================
// Invariant: Failure Count Consistency
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn error_failure_type_count_equals_error_findings(receipt in arb_receipt_error_only()) {
        let xml = render_junit_for_receipt(&receipt);
        let error_count = receipt.findings.len();

        // Every Error finding produces a failure with type="error"
        let error_failure_count = count_occurrences(&xml, "<failure type=\"error\"");

        prop_assert_eq!(
            error_failure_count, error_count,
            "Error findings {} should produce {} type=\"error\" failures",
            error_count, error_failure_count
        );
    }

    #[test]
    fn warn_failure_type_count_equals_warn_findings(receipt in arb_receipt_warn_only()) {
        let xml = render_junit_for_receipt(&receipt);
        let warn_count = receipt.findings.len();

        // Every Warn finding produces a failure with type="warning"
        let warn_failure_count = count_occurrences(&xml, "<failure type=\"warning\"");

        prop_assert_eq!(
            warn_failure_count, warn_count,
            "Warn findings {} should produce {} type=\"warning\" failures",
            warn_count, warn_failure_count
        );
    }

    #[test]
    fn info_findings_produce_no_failure_element(receipt in arb_receipt_info_only()) {
        let xml = render_junit_for_receipt(&receipt);

        // Info findings should NOT produce any <failure> elements
        prop_assert!(
            !xml.contains("<failure type="),
            "Info findings should not produce failure elements, but XML contained: {}",
            xml
        );
    }
}

// =============================================================================
// Invariant: Rule ID Grouping
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn each_unique_rule_id_produces_one_testsuite(receipt in arb_receipt()) {
        let xml = render_junit_for_receipt(&receipt);
        let unique_rule_ids: std::collections::HashSet<_> =
            receipt.findings.iter().map(|f| f.rule_id.as_str()).collect();

        // Count number of <testsuite ...> opening tags
        let testsuite_count = count_occurrences(&xml, "<testsuite name=");

        prop_assert_eq!(
            testsuite_count, unique_rule_ids.len(),
            "Number of testsuites {} should equal number of unique rule_ids {}",
            testsuite_count, unique_rule_ids.len()
        );
    }
}

// =============================================================================
// Invariant: Testcase Details
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn failure_element_contains_rule_file_line(receipt in arb_receipt_warn_error_mixed()) {
        let xml = render_junit_for_receipt(&receipt);

        // For each finding, verify failure details
        for f in &receipt.findings {
            if matches!(f.severity, Severity::Error | Severity::Warn) {
                prop_assert!(
                    xml.contains(&format!("Rule: {}", f.rule_id)),
                    "Failure should contain 'Rule: {}'",
                    f.rule_id
                );
                prop_assert!(
                    xml.contains(&format!("File: {}", f.path)),
                    "Failure should contain 'File: {}'",
                    f.path
                );
                prop_assert!(
                    xml.contains(&format!("Line: {}", f.line)),
                    "Failure should contain 'Line: {}'",
                    f.line
                );
            }
        }
    }
}

// =============================================================================
// Invariant: XML Escaping
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn special_xml_chars_in_message_are_escaped(_i in 0..1) {
        // Fixed test with known special characters in message
        // Use Error severity so failure element is emitted
        let receipt = {
            let findings = vec![Finding {
                rule_id: "test.rule".to_string(),
                severity: Severity::Error,
                message: "a & b < c > d \" e ' f".to_string(),
                path: "test.rs".to_string(),
                line: 1,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }];
            make_receipt(findings)
        };

        let xml = render_junit_for_receipt(&receipt);

        // These characters should be escaped in the output
        prop_assert!(xml.contains("&amp;"), "Should escape &");
        prop_assert!(xml.contains("&lt;"), "Should escape <");
        prop_assert!(xml.contains("&gt;"), "Should escape >");
        prop_assert!(xml.contains("&quot;"), "Should escape \"");
        prop_assert!(xml.contains("&apos;"), "Should escape '");
    }

    #[test]
    fn special_xml_chars_in_path_are_escaped(_i in 0..1) {
        // Fixed test with known special characters in path
        // Use Error severity so failure element is emitted
        let receipt = {
            let findings = vec![Finding {
                rule_id: "test.rule".to_string(),
                severity: Severity::Error,
                message: "test message".to_string(),
                path: "src/a & b <c> \"file\".rs".to_string(),
                line: 1,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }];
            make_receipt(findings)
        };

        let xml = render_junit_for_receipt(&receipt);

        // The path appears in classname attribute - these should be escaped
        prop_assert!(xml.contains("&amp;"), "Should escape & in path");
        prop_assert!(xml.contains("&lt;"), "Should escape < in path");
        prop_assert!(xml.contains("&gt;"), "Should escape > in path");
    }

    #[test]
    fn special_xml_chars_in_rule_id_are_escaped(_i in 0..1) {
        // Fixed test with known special characters in rule_id
        // Use Error severity so failure element is emitted
        let receipt = {
            let findings = vec![Finding {
                rule_id: "a & b <c> \"rule\"".to_string(),
                severity: Severity::Error,
                message: "test message".to_string(),
                path: "test.rs".to_string(),
                line: 1,
                column: None,
                match_text: "test".to_string(),
                snippet: "test".to_string(),
            }];
            make_receipt(findings)
        };

        let xml = render_junit_for_receipt(&receipt);

        prop_assert!(xml.contains("&amp;"), "Should escape & in rule_id");
        prop_assert!(xml.contains("&lt;"), "Should escape < in rule_id");
        prop_assert!(xml.contains("&gt;"), "Should escape > in rule_id");
    }
}

// =============================================================================
// Invariant: BTreeMap Deterministic Ordering
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn suite_order_is_deterministic_by_rule_id(receipt in arb_receipt()) {
        let xml1 = render_junit_for_receipt(&receipt);
        let xml2 = render_junit_for_receipt(&receipt);

        // Same receipt should produce identical XML
        prop_assert_eq!(
            xml1, xml2,
            "render_junit_for_receipt should be deterministic"
        );
    }
}

// =============================================================================
// Invariant: Large Receipts
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn large_receipt_testcase_count_accurate(receipt in arb_receipt_large()) {
        let xml = render_junit_for_receipt(&receipt);
        let finding_count = receipt.findings.len();

        let testcase_count = count_occurrences(&xml, "<testcase classname=");

        prop_assert_eq!(
            testcase_count, finding_count,
            "Large receipt: testcase count {} should equal findings count {}",
            testcase_count, finding_count
        );
    }
}
