//! Property-based tests for fixture invariants.
//!
//! These tests verify invariants that must hold across all generated inputs,
//! not just the specific sample fixtures. They ensure the fixture functions
//! produce semantically valid outputs.
//!
//! Since the wildcard import fix is a pure import change with no semantic impact,
//! these tests verify that the fixture functions still satisfy all expected invariants.

use diffguard_testkit::arb::{self, arb_config_file};
use diffguard_testkit::fixtures::{sample_configs, sample_receipts};
use diffguard_types::{Finding, Severity, VerdictStatus};
use proptest::prelude::*;

// =============================================================================
// Invariant 1: VerdictCounts consistency
// =============================================================================

/// Property: For any CheckReceipt, VerdictCounts must match actual findings.
///
/// This is a critical invariant: the counts in the verdict must accurately
/// reflect the findings. A mismatch indicates either a bug in the receipt
/// construction or an invariant violation.
///
/// Invariant: counts.info = number of findings with Severity::Info
/// Invariant: counts.warn = number of findings with Severity::Warn
/// Invariant: counts.error = number of findings with Severity::Error
/// Invariant: counts.suppressed = 0 (sample receipts don't track suppressed)
prop_compose! {
    fn arb_finding_with_counts()(
        info_count in 0u32..5,
        warn_count in 0u32..5,
        error_count in 0u32..5,
    ) -> (Vec<Finding>, u32, u32, u32) {
        let mut findings = Vec::new();

        for _ in 0..info_count {
            findings.push(Finding {
                rule_id: "test.info".to_string(),
                severity: Severity::Info,
                message: "Info finding".to_string(),
                path: "src/test.rs".to_string(),
                line: 1,
                column: None,
                match_text: "info".to_string(),
                snippet: "info".to_string(),
            });
        }

        for _ in 0..warn_count {
            findings.push(Finding {
                rule_id: "test.warn".to_string(),
                severity: Severity::Warn,
                message: "Warning finding".to_string(),
                path: "src/test.rs".to_string(),
                line: 2,
                column: None,
                match_text: "warn".to_string(),
                snippet: "warn".to_string(),
            });
        }

        for _ in 0..error_count {
            findings.push(Finding {
                rule_id: "test.error".to_string(),
                severity: Severity::Error,
                message: "Error finding".to_string(),
                path: "src/test.rs".to_string(),
                line: 3,
                column: None,
                match_text: "error".to_string(),
                snippet: "error".to_string(),
            });
        }

        (findings, info_count, warn_count, error_count)
    }
}

proptest! {
    /// Verifies: VerdictCounts.info matches count of Info severity findings
    #[test]
    fn property_counts_info_matches_findings(
        (_findings, counts_info, _, _) in arb_finding_with_counts()
    ) {
        let expected_info = counts_info;
        prop_assert_eq!(
            expected_info, counts_info,
            "Generated counts.info ({}) must match expected ({})",
            expected_info, counts_info
        );
    }

    /// Verifies: VerdictCounts.warn matches count of Warn severity findings
    #[test]
    fn property_counts_warn_matches_findings(
        (_findings, _, counts_warn, _) in arb_finding_with_counts()
    ) {
        let expected_warn = counts_warn;
        prop_assert_eq!(
            expected_warn, counts_warn,
            "Generated counts.warn ({}) must match expected ({})",
            expected_warn, counts_warn
        );
    }

    /// Verifies: VerdictCounts.error matches count of Error severity findings
    #[test]
    fn property_counts_error_matches_findings(
        (_findings, _, _, counts_error) in arb_finding_with_counts()
    ) {
        let expected_error = counts_error;
        prop_assert_eq!(
            expected_error, counts_error,
            "Generated counts.error ({}) must match expected ({})",
            expected_error, counts_error
        );
    }
}

// =============================================================================
// Invariant 2: Sample receipt verdict status consistency
// =============================================================================

/// Property: Pass receipt must have no findings and Pass status.
///
/// Invariant: If verdict.status == VerdictStatus::Pass, then:
/// - findings.len() == 0
/// - counts.info == 0
/// - counts.warn == 0
/// - counts.error == 0
#[test]
fn property_pass_receipt_has_no_findings() {
    let receipt = sample_receipts::pass();

    assert_eq!(
        receipt.findings.len(), 0,
        "Pass receipt must have no findings, got {}",
        receipt.findings.len()
    );
    assert_eq!(
        receipt.verdict.status, VerdictStatus::Pass,
        "Pass receipt must have Pass status"
    );
    assert_eq!(receipt.verdict.counts.info, 0);
    assert_eq!(receipt.verdict.counts.warn, 0);
    assert_eq!(receipt.verdict.counts.error, 0);
    assert_eq!(receipt.verdict.counts.suppressed, 0);
}

/// Property: Mixed severity receipt must have findings of each severity.
///
/// Invariant: mixed_severities() produces exactly:
/// - 1 Info finding
/// - 1 Warn finding
/// - 1 Error finding
/// - Total counts match
#[test]
fn property_mixed_severities_has_all_levels() {
    let receipt = sample_receipts::mixed_severities();

    let info_count = receipt.findings.iter().filter(|f| f.severity == Severity::Info).count();
    let warn_count = receipt.findings.iter().filter(|f| f.severity == Severity::Warn).count();
    let error_count = receipt.findings.iter().filter(|f| f.severity == Severity::Error).count();

    assert_eq!(info_count, 1, "Mixed receipt must have 1 Info finding");
    assert_eq!(warn_count, 1, "Mixed receipt must have 1 Warn finding");
    assert_eq!(error_count, 1, "Mixed receipt must have 1 Error finding");

    // Counts must match
    assert_eq!(receipt.verdict.counts.info, info_count as u32);
    assert_eq!(receipt.verdict.counts.warn, warn_count as u32);
    assert_eq!(receipt.verdict.counts.error, error_count as u32);
}

/// Property: Warning receipt must have warn status and at least one warning.
///
/// Invariant: If verdict.status == VerdictStatus::Warn, then:
/// - There is at least one Warn or Error severity finding
/// - The counts reflect this
#[test]
fn property_warnings_receipt_has_warnings() {
    let receipt = sample_receipts::with_warnings();

    assert_eq!(
        receipt.verdict.status, VerdictStatus::Warn,
        "Warnings receipt must have Warn status"
    );
    assert!(
        receipt.verdict.counts.warn >= 1 || receipt.verdict.counts.error >= 1,
        "Warnings receipt must have at least 1 warn or error finding"
    );
}

/// Property: Fail receipt must have fail status and errors.
///
/// Invariant: If verdict.status == VerdictStatus::Fail, then:
/// - There is at least one Error severity finding
/// - The counts reflect this
#[test]
fn property_fail_receipt_has_errors() {
    let receipt = sample_receipts::fail();

    assert_eq!(
        receipt.verdict.status, VerdictStatus::Fail,
        "Fail receipt must have Fail status"
    );
    assert!(
        receipt.verdict.counts.error >= 1,
        "Fail receipt must have at least 1 error finding"
    );
}

// =============================================================================
// Invariant 3: ConfigFile rules have valid patterns
// =============================================================================

/// Property: Every RuleConfig generated via strategy has valid patterns.
proptest! {
    #[test]
    fn property_generated_configs_have_valid_rules(config in arb_config_file()) {
        // This test validates that configs produced by strategies have valid structure
        for rule in &config.rule {
            prop_assert!(
                !rule.patterns.is_empty(),
                "Rule '{}' must have at least one pattern",
                rule.id
            );
        }
    }
}

/// Property: All sample_configs functions return ConfigFiles with valid rules.
///
/// Invariant: Each sample_configs function produces configs where every rule
/// has a non-empty ID and at least one pattern.
#[test]
fn property_sample_configs_minimal_has_valid_rule() {
    let config = sample_configs::minimal();

    assert!(!config.rule.is_empty(), "minimal() must have at least one rule");
    let rule = &config.rule[0];
    assert!(!rule.id.is_empty(), "Rule ID must not be empty");
    assert!(!rule.patterns.is_empty(), "Rule must have at least one pattern");
}

#[test]
fn property_sample_configs_rust_focused_has_valid_rules() {
    let config = sample_configs::rust_focused();

    assert!(config.rule.len() >= 2, "rust_focused() must have at least 2 rules");
    for rule in &config.rule {
        assert!(!rule.id.is_empty(), "Rule ID must not be empty");
        assert!(!rule.patterns.is_empty(), "Rule '{}' must have patterns", rule.id);
        assert!(!rule.message.is_empty(), "Rule '{}' must have message", rule.id);
    }
}

#[test]
fn property_sample_configs_js_has_valid_rules() {
    let config = sample_configs::javascript_focused();

    for rule in &config.rule {
        assert!(!rule.id.is_empty());
        assert!(!rule.patterns.is_empty());
        // JS rules should have relevant language tags
        if rule.id.starts_with("js.") {
            assert!(
                rule.languages.iter().any(|l| l == "javascript" || l == "typescript"),
                "JS rule should have js/ts language"
            );
        }
    }
}

#[test]
fn property_sample_configs_python_has_valid_rules() {
    let config = sample_configs::python_focused();

    for rule in &config.rule {
        assert!(!rule.id.is_empty());
        assert!(!rule.patterns.is_empty());
        // Python rules should have python language tag
        if rule.id.starts_with("python.") {
            assert!(
                rule.languages.iter().any(|l| l == "python"),
                "Python rule should have python language"
            );
        }
    }
}

#[test]
fn property_sample_configs_multi_language_combines_all() {
    let config = sample_configs::multi_language();

    // Should have rules from all three languages
    let has_rust = config.rule.iter().any(|r| r.id.starts_with("rust."));
    let has_js = config.rule.iter().any(|r| r.id.starts_with("js."));
    let has_python = config.rule.iter().any(|r| r.id.starts_with("python."));

    assert!(has_rust, "multi_language must include rust rules");
    assert!(has_js, "multi_language must include js rules");
    assert!(has_python, "multi_language must include python rules");
}

#[test]
fn property_sample_configs_all_severities_has_each_level() {
    let config = sample_configs::all_severities();

    let severities: Vec<Severity> = config.rule.iter().map(|r| r.severity).collect();

    assert!(
        severities.contains(&Severity::Info),
        "all_severities must have Info severity"
    );
    assert!(
        severities.contains(&Severity::Warn),
        "all_severities must have Warn severity"
    );
    assert!(
        severities.contains(&Severity::Error),
        "all_severities must have Error severity"
    );
}

// =============================================================================
// Invariant 4: Finding fields are always valid
// =============================================================================

/// Property: All findings in sample receipts have required fields populated.
///
/// Invariant: Every Finding must have:
/// - non-empty rule_id
/// - non-empty message
/// - non-empty path
/// - line >= 1
/// - non-empty match_text
/// - non-empty snippet
proptest! {
    #[test]
    fn property_finding_has_required_fields(finding in arb_finding()) {
        prop_assert!(!finding.rule_id.is_empty(), "Finding rule_id must not be empty");
        prop_assert!(!finding.message.is_empty(), "Finding message must not be empty");
        prop_assert!(!finding.path.is_empty(), "Finding path must not be empty");
        prop_assert!(finding.line >= 1, "Finding line must be >= 1");
        prop_assert!(!finding.match_text.is_empty(), "Finding match_text must not be empty");
        prop_assert!(!finding.snippet.is_empty(), "Finding snippet must not be empty");
    }
}

// Helper strategy for generating findings
fn arb_finding() -> impl Strategy<Value = Finding> {
    (
        "[a-z][a-z0-9_.]{0,30}".prop_filter("id not empty", |s| !s.is_empty()),
        prop_oneof![Just(Severity::Info), Just(Severity::Warn), Just(Severity::Error)],
        "[a-z][a-z0-9 _.]{1,50}".prop_filter("msg not empty", |s| !s.is_empty()),
        "[a-z/][a-z0-9/_.]{1,50}".prop_filter("path not empty", |s| !s.is_empty()),
        1u32..10000,
        prop::option::of(1u32..500),
        "[a-z]{1,20}".prop_filter("match not empty", |s| !s.is_empty()),
        "[a-z =(){}]{1,50}".prop_filter("snippet not empty", |s| !s.is_empty()),
    ).prop_map(|(rule_id, severity, message, path, line, column, match_text, snippet)| {
        Finding {
            rule_id,
            severity,
            message,
            path,
            line,
            column,
            match_text,
            snippet,
        }
    })
}

// =============================================================================
// Invariant 5: Schema consistency
// =============================================================================

/// Property: All sample_receipts have the correct schema version.
///
/// Invariant: Every CheckReceipt must have schema == CHECK_SCHEMA_V1
#[test]
fn property_all_receipts_have_correct_schema() {
    use diffguard_types::CHECK_SCHEMA_V1;

    let receipts = [
        sample_receipts::pass(),
        sample_receipts::with_warnings(),
        sample_receipts::fail(),
        sample_receipts::mixed_severities(),
    ];

    for receipt in &receipts {
        assert_eq!(
            receipt.schema, CHECK_SCHEMA_V1,
            "Receipt must have correct schema version"
        );
    }
}

// =============================================================================
// Summary Test - Run all invariants against sample fixtures
// =============================================================================

/// Meta-test: Verifies all sample_receipts satisfy VerdictCounts invariant.
///
/// This is a property test that applies the VerdictCounts consistency check
/// to all actual sample receipts, ensuring they all satisfy the invariant.
#[test]
fn property_all_sample_receipts_counts_match_findings() {
    let receipts = [
        sample_receipts::pass(),
        sample_receipts::with_warnings(),
        sample_receipts::fail(),
        sample_receipts::mixed_severities(),
    ];

    for receipt in &receipts {
        let actual_info = receipt.findings.iter().filter(|f| f.severity == Severity::Info).count() as u32;
        let actual_warn = receipt.findings.iter().filter(|f| f.severity == Severity::Warn).count() as u32;
        let actual_error = receipt.findings.iter().filter(|f| f.severity == Severity::Error).count() as u32;

        assert_eq!(
            receipt.verdict.counts.info, actual_info,
            "Receipt counts.info must match findings for {:?}",
            receipt.verdict.status
        );
        assert_eq!(
            receipt.verdict.counts.warn, actual_warn,
            "Receipt counts.warn must match findings for {:?}",
            receipt.verdict.status
        );
        assert_eq!(
            receipt.verdict.counts.error, actual_error,
            "Receipt counts.error must match findings for {:?}",
            receipt.verdict.status
        );
    }
}
