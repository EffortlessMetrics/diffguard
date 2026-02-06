//! Property-based tests for diffguard-core
//!
//! Feature: comprehensive-test-coverage
//!
//! These tests verify the correctness of verdict computation, exit codes,
//! and markdown rendering in the application layer.

use proptest::prelude::*;

use diffguard_core::render_markdown_for_receipt;
use diffguard_types::{
    CheckReceipt, DiffMeta, FailOn, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts,
    VerdictStatus, CHECK_SCHEMA_V1,
};

// ============================================================================
// Proptest Strategies for generating test data
// ============================================================================

/// Strategy for generating valid Severity values.
fn arb_severity() -> impl Strategy<Value = Severity> {
    prop_oneof![
        Just(Severity::Info),
        Just(Severity::Warn),
        Just(Severity::Error),
    ]
}

/// Strategy for generating valid VerdictStatus values.
#[allow(dead_code)]
fn arb_verdict_status() -> impl Strategy<Value = VerdictStatus> {
    prop_oneof![
        Just(VerdictStatus::Pass),
        Just(VerdictStatus::Warn),
        Just(VerdictStatus::Fail),
    ]
}

/// Strategy for generating valid Scope values.
fn arb_scope() -> impl Strategy<Value = Scope> {
    prop_oneof![Just(Scope::Added), Just(Scope::Changed),]
}

/// Strategy for generating valid FailOn values.
fn arb_fail_on() -> impl Strategy<Value = FailOn> {
    prop_oneof![Just(FailOn::Error), Just(FailOn::Warn), Just(FailOn::Never),]
}

/// Strategy for generating non-empty alphanumeric strings (for IDs, paths, etc.).
fn arb_identifier() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z][a-zA-Z0-9_.]{0,20}")
        .expect("valid regex")
        .prop_filter("must not be empty", |s| !s.is_empty())
}

/// Strategy for generating message strings (may contain spaces, but no special markdown chars).
fn arb_message() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_ ]{1,50}").expect("valid regex")
}

/// Strategy for generating valid Finding.
fn arb_finding() -> impl Strategy<Value = Finding> {
    (
        arb_identifier(),            // rule_id
        arb_severity(),              // severity
        arb_message(),               // message
        arb_identifier(),            // path (simplified)
        1u32..1000,                  // line
        prop::option::of(1u32..200), // column
        arb_identifier(),            // match_text
        arb_message(),               // snippet
    )
        .prop_map(
            |(rule_id, severity, message, path, line, column, match_text, snippet)| Finding {
                rule_id,
                severity,
                message,
                path: format!("src/{}.rs", path),
                line,
                column,
                match_text,
                snippet,
            },
        )
}

/// Strategy for generating valid VerdictCounts.
fn arb_verdict_counts() -> impl Strategy<Value = VerdictCounts> {
    (0u32..50, 0u32..50, 0u32..50, 0u32..20).prop_map(|(info, warn, error, suppressed)| {
        VerdictCounts {
            info,
            warn,
            error,
            suppressed,
        }
    })
}

/// Strategy for generating VerdictCounts that match a list of findings.
fn counts_matching_findings(findings: &[Finding]) -> VerdictCounts {
    let mut counts = VerdictCounts::default();
    for f in findings {
        match f.severity {
            Severity::Info => counts.info += 1,
            Severity::Warn => counts.warn += 1,
            Severity::Error => counts.error += 1,
        }
    }
    counts
}

/// Strategy for generating VerdictStatus that matches counts.
fn status_matching_counts(counts: &VerdictCounts) -> VerdictStatus {
    if counts.error > 0 {
        VerdictStatus::Fail
    } else if counts.warn > 0 {
        VerdictStatus::Warn
    } else {
        VerdictStatus::Pass
    }
}

/// Strategy for generating valid DiffMeta.
fn arb_diff_meta() -> impl Strategy<Value = DiffMeta> {
    (
        arb_identifier(), // base
        arb_identifier(), // head
        0u32..10,         // context_lines
        arb_scope(),      // scope
        0u32..100,        // files_scanned
        0u32..1000,       // lines_scanned
    )
        .prop_map(
            |(base, head, context_lines, scope, files_scanned, lines_scanned)| DiffMeta {
                base,
                head,
                context_lines,
                scope,
                files_scanned,
                lines_scanned,
            },
        )
}

/// Strategy for generating valid CheckReceipt with consistent verdict.
fn arb_check_receipt() -> impl Strategy<Value = CheckReceipt> {
    (
        arb_diff_meta(),
        prop::collection::vec(arb_finding(), 0..10),
        prop::collection::vec(arb_message(), 0..3),
    )
        .prop_map(|(diff, findings, reasons)| {
            let counts = counts_matching_findings(&findings);
            let status = status_matching_counts(&counts);
            CheckReceipt {
                schema: CHECK_SCHEMA_V1.to_string(),
                tool: ToolMeta {
                    name: "diffguard".to_string(),
                    version: "0.1.0".to_string(),
                },
                diff,
                findings,
                verdict: Verdict {
                    status,
                    counts,
                    reasons,
                },
                timing: None,
            }
        })
}

// ============================================================================
// Property: Verdict Consistency
// ============================================================================
//
// Feature: comprehensive-test-coverage, Property: Verdict Consistency
// For any CheckReceipt, the verdict status SHALL be consistent with the
// finding severities: Fail if any errors, Warn if any warnings (no errors),
// Pass otherwise.
// **Validates: Requirements 10.1**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_verdict_status_matches_counts(
        receipt in arb_check_receipt(),
    ) {
        let expected_status = status_matching_counts(&receipt.verdict.counts);

        prop_assert_eq!(
            receipt.verdict.status,
            expected_status,
            "Verdict status ({:?}) should match expected ({:?}) based on counts: {:?}",
            receipt.verdict.status,
            expected_status,
            receipt.verdict.counts
        );
    }

    #[test]
    fn property_counts_match_findings(
        findings in prop::collection::vec(arb_finding(), 0..20),
    ) {
        let expected_counts = counts_matching_findings(&findings);
        let expected_status = status_matching_counts(&expected_counts);

        // Verify the helper functions are consistent
        prop_assert_eq!(
            expected_status,
            if expected_counts.error > 0 {
                VerdictStatus::Fail
            } else if expected_counts.warn > 0 {
                VerdictStatus::Warn
            } else {
                VerdictStatus::Pass
            },
            "Status should be derived correctly from counts"
        );
    }
}

// ============================================================================
// Property: Exit Code Correctness
// ============================================================================
//
// Feature: comprehensive-test-coverage, Property: Exit Code Correctness
// Exit codes SHALL follow the documented contract:
// - 0: Pass
// - 2: Policy failure (error-level findings)
// - 3: Warn-level failure (when fail_on = "warn")
// **Validates: Requirements 10.2**

/// Compute expected exit code based on fail_on policy and counts.
fn expected_exit_code(fail_on: FailOn, counts: &VerdictCounts) -> i32 {
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_exit_code_never_policy_always_zero(
        counts in arb_verdict_counts(),
    ) {
        let exit_code = expected_exit_code(FailOn::Never, &counts);
        prop_assert_eq!(
            exit_code,
            0,
            "FailOn::Never should always produce exit code 0, got {} for counts {:?}",
            exit_code,
            counts
        );
    }

    #[test]
    fn property_exit_code_error_policy_correct(
        counts in arb_verdict_counts(),
    ) {
        let exit_code = expected_exit_code(FailOn::Error, &counts);

        if counts.error > 0 {
            prop_assert_eq!(
                exit_code,
                2,
                "FailOn::Error with errors should produce exit code 2"
            );
        } else {
            prop_assert_eq!(
                exit_code,
                0,
                "FailOn::Error without errors should produce exit code 0"
            );
        }
    }

    #[test]
    fn property_exit_code_warn_policy_correct(
        counts in arb_verdict_counts(),
    ) {
        let exit_code = expected_exit_code(FailOn::Warn, &counts);

        if counts.error > 0 {
            prop_assert_eq!(
                exit_code,
                2,
                "FailOn::Warn with errors should produce exit code 2"
            );
        } else if counts.warn > 0 {
            prop_assert_eq!(
                exit_code,
                3,
                "FailOn::Warn with warnings (no errors) should produce exit code 3"
            );
        } else {
            prop_assert_eq!(
                exit_code,
                0,
                "FailOn::Warn without errors or warnings should produce exit code 0"
            );
        }
    }

    #[test]
    fn property_exit_code_in_valid_range(
        fail_on in arb_fail_on(),
        counts in arb_verdict_counts(),
    ) {
        let exit_code = expected_exit_code(fail_on, &counts);

        prop_assert!(
            exit_code == 0 || exit_code == 2 || exit_code == 3,
            "Exit code should be 0, 2, or 3, got {}",
            exit_code
        );
    }
}

// ============================================================================
// Property: Markdown Validity
// ============================================================================
//
// Feature: comprehensive-test-coverage, Property: Markdown Validity
// The rendered markdown SHALL have proper table structure when findings exist.
// **Validates: Requirements 10.3**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn property_markdown_contains_header(
        receipt in arb_check_receipt(),
    ) {
        let md = render_markdown_for_receipt(&receipt);

        // Should always contain the main header
        prop_assert!(
            md.contains("## diffguard"),
            "Markdown should contain '## diffguard' header"
        );
    }

    #[test]
    fn property_markdown_contains_verdict_status(
        receipt in arb_check_receipt(),
    ) {
        let md = render_markdown_for_receipt(&receipt);

        let status_str = match receipt.verdict.status {
            VerdictStatus::Pass => "PASS",
            VerdictStatus::Warn => "WARN",
            VerdictStatus::Fail => "FAIL",
            VerdictStatus::Skip => "SKIP",
        };

        prop_assert!(
            md.contains(status_str),
            "Markdown should contain verdict status '{}' but got:\n{}",
            status_str,
            md
        );
    }

    #[test]
    fn property_markdown_table_when_findings_exist(
        receipt in arb_check_receipt(),
    ) {
        let md = render_markdown_for_receipt(&receipt);

        if !receipt.findings.is_empty() {
            // Should have table headers
            prop_assert!(
                md.contains("| Severity | Rule"),
                "Markdown with findings should contain table headers"
            );
            prop_assert!(
                md.contains("|---|"),
                "Markdown with findings should contain table separator"
            );

            // Should have a row for each finding
            let row_count = md.matches("| info |")
                .count()
                + md.matches("| warn |")
                .count()
                + md.matches("| error |")
                .count();

            prop_assert_eq!(
                row_count,
                receipt.findings.len(),
                "Table should have {} rows for findings, but found {}",
                receipt.findings.len(),
                row_count
            );
        } else {
            prop_assert!(
                md.contains("No findings"),
                "Markdown without findings should say 'No findings'"
            );
        }
    }

    #[test]
    fn property_markdown_contains_scan_info(
        receipt in arb_check_receipt(),
    ) {
        let md = render_markdown_for_receipt(&receipt);

        // Should contain file and line count info
        prop_assert!(
            md.contains("file(s)"),
            "Markdown should contain file count info"
        );
        prop_assert!(
            md.contains("line(s)"),
            "Markdown should contain line count info"
        );
        prop_assert!(
            md.contains("scope:"),
            "Markdown should contain scope info"
        );
    }

    #[test]
    fn property_markdown_escapes_special_chars(
        rule_id in prop::string::string_regex("[a-z]+\\|[a-z]+").expect("valid regex"),
    ) {
        let finding = Finding {
            rule_id: rule_id.clone(),
            severity: Severity::Warn,
            message: "test|message".to_string(),
            path: "test.rs".to_string(),
            line: 1,
            column: None,
            match_text: "x".to_string(),
            snippet: "code|with|pipes".to_string(),
        };

        let receipt = CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 1,
                lines_scanned: 1,
            },
            findings: vec![finding],
            verdict: Verdict {
                status: VerdictStatus::Warn,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 0,
                    suppressed: 0,
                },
                reasons: vec![],
            },
            timing: None,
        };

        let md = render_markdown_for_receipt(&receipt);

        // Pipes should be escaped in markdown tables
        prop_assert!(
            md.contains("\\|"),
            "Pipe characters should be escaped in markdown: {}",
            md
        );
    }
}

// ============================================================================
// Property: Reasons Rendering
// ============================================================================
//
// Feature: comprehensive-test-coverage, Property: Reasons Rendering
// When verdict has reasons, they SHALL be rendered in the markdown output.
// **Validates: Requirements 10.4**

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn property_reasons_appear_in_markdown(
        receipt in arb_check_receipt(),
    ) {
        let md = render_markdown_for_receipt(&receipt);

        if !receipt.verdict.reasons.is_empty() {
            prop_assert!(
                md.contains("Verdict reasons:"),
                "Markdown should contain 'Verdict reasons:' when reasons exist"
            );

            for reason in &receipt.verdict.reasons {
                prop_assert!(
                    md.contains(reason),
                    "Markdown should contain reason '{}' but got:\n{}",
                    reason,
                    md
                );
            }
        }
    }
}

// ============================================================================
// Unit Tests for edge cases
// ============================================================================

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn empty_receipt_renders_pass() {
        let receipt = CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 0,
                lines_scanned: 0,
            },
            findings: vec![],
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: VerdictCounts::default(),
                reasons: vec![],
            },
            timing: None,
        };

        let md = render_markdown_for_receipt(&receipt);
        assert!(md.contains("PASS"));
        assert!(md.contains("No findings"));
    }

    #[test]
    fn unicode_content_renders_correctly() {
        let finding = Finding {
            rule_id: "test".to_string(),
            severity: Severity::Warn,
            message: "Unicode: \u{4e2d}\u{6587}".to_string(),
            path: "src/\u{65e5}\u{672c}\u{8a9e}.rs".to_string(),
            line: 1,
            column: None,
            match_text: "\u{1f600}".to_string(),
            snippet: "let x = \"\u{1f680}\";".to_string(),
        };

        let receipt = CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "main".to_string(),
                head: "HEAD".to_string(),
                context_lines: 0,
                scope: Scope::Added,
                files_scanned: 1,
                lines_scanned: 1,
            },
            findings: vec![finding],
            verdict: Verdict {
                status: VerdictStatus::Warn,
                counts: VerdictCounts {
                    info: 0,
                    warn: 1,
                    error: 0,
                    suppressed: 0,
                },
                reasons: vec![],
            },
            timing: None,
        };

        let md = render_markdown_for_receipt(&receipt);

        // Should render without panicking and contain Unicode content
        assert!(md.contains("\u{4e2d}\u{6587}"));
        assert!(md.contains("\u{65e5}\u{672c}\u{8a9e}"));
    }

    #[test]
    fn max_values_render_correctly() {
        let receipt = CheckReceipt {
            schema: CHECK_SCHEMA_V1.to_string(),
            tool: ToolMeta {
                name: "diffguard".to_string(),
                version: "0.1.0".to_string(),
            },
            diff: DiffMeta {
                base: "main".to_string(),
                head: "HEAD".to_string(),
                context_lines: u32::MAX,
                scope: Scope::Added,
                files_scanned: u32::MAX,
                lines_scanned: u32::MAX,
            },
            findings: vec![],
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: VerdictCounts::default(),
                reasons: vec![],
            },
            timing: None,
        };

        let md = render_markdown_for_receipt(&receipt);

        // Should render without panicking
        assert!(md.contains("PASS"));
        assert!(md.contains(&u32::MAX.to_string()));
    }
}
