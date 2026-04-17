//! Edge case tests for fixtures module.
//!
//! These tests cover edge cases and untested fixture functions to provide
//! comprehensive validation of the sample_configs and sample_receipts fixtures.
//!
//! The wildcard_imports lint fix is orthogonal to fixture functionality — these
//! tests verify the fixtures themselves work correctly with the new explicit imports.

use diffguard_testkit::fixtures::{sample_configs, sample_receipts};
use diffguard_types::{
    CheckReceipt, ConfigFile, Defaults, FailOn, Finding, RuleConfig, Scope, Severity,
    VerdictCounts, VerdictStatus,
};

// =============================================================================
// sample_configs edge cases
// =============================================================================

/// Verifies sample_configs::built_in() returns a valid ConfigFile.
/// Edge case: Built-in config is special — may have defaults populated.
#[test]
fn test_sample_configs_built_in_returns_valid_config() {
    let config = sample_configs::built_in();

    // Should be a valid ConfigFile per schema
    // Note: built_in() delegates to ConfigFile::built_in() which is tested
    // in schema validation tests - here we just verify it returns something
    assert!(!config.rule.is_empty() || !config.includes.is_empty());
}

/// Verifies sample_configs::javascript_focused() returns proper language configs.
/// Edge case: Multi-language rule with JS/TS file patterns and exclude patterns.
#[test]
fn test_sample_configs_javascript_focused_has_js_rules() {
    let config = sample_configs::javascript_focused();

    // Should have at least 2 rules
    assert!(config.rule.len() >= 2);

    // First rule should be js.no_console
    let first_rule = &config.rule[0];
    assert_eq!(first_rule.id, "js.no_console");
    assert_eq!(first_rule.severity, Severity::Warn);

    // Should include JS/TS file patterns
    let has_js_pattern = config
        .rule
        .iter()
        .any(|r| r.paths.iter().any(|p| p.contains("*.js")));
    assert!(has_js_pattern, "Should have JavaScript file patterns");

    // Should have exclude patterns for tests
    let has_exclude = config
        .rule
        .iter()
        .any(|r| r.exclude_paths.iter().any(|p| p.contains("tests")));
    assert!(has_exclude, "Should exclude test files");
}

/// Verifies sample_configs::python_focused() returns Python-specific configs.
/// Edge case: Python-specific rules with pdb/breakpoint detection.
#[test]
fn test_sample_configs_python_focused_has_python_rules() {
    let config = sample_configs::python_focused();

    // Should have at least 2 rules
    assert!(config.rule.len() >= 2);

    // First rule should be python.no_print
    let first_rule = &config.rule[0];
    assert_eq!(first_rule.id, "python.no_print");
    assert_eq!(first_rule.severity, Severity::Warn);

    // Should include Python file patterns
    let has_py_pattern = config
        .rule
        .iter()
        .any(|r| r.paths.iter().any(|p| p.contains("*.py")));
    assert!(has_py_pattern, "Should have Python file patterns");

    // Should have pdb/breakpoint rule with Error severity
    let has_debug_rule = config
        .rule
        .iter()
        .any(|r| r.id == "python.no_pdb" && r.severity == Severity::Error);
    assert!(
        has_debug_rule,
        "Should have python.no_pdb rule with Error severity"
    );
}

/// Verifies sample_configs::multi_language() combines configs from all languages.
/// Edge case: Composite config with rules from multiple language configs.
#[test]
fn test_sample_configs_multi_language_has_all_language_rules() {
    let config = sample_configs::multi_language();

    // Should have rules from rust + javascript + python = at least 6 rules
    assert!(
        config.rule.len() >= 6,
        "multi_language should have at least 6 rules (2 each from 3 languages)"
    );

    // Should have rules from each language
    let has_rust = config.rule.iter().any(|r| r.id.starts_with("rust."));
    let has_js = config.rule.iter().any(|r| r.id.starts_with("js."));
    let has_python = config.rule.iter().any(|r| r.id.starts_with("python."));

    assert!(has_rust, "Should have Rust rules");
    assert!(has_js, "Should have JavaScript rules");
    assert!(has_python, "Should have Python rules");
}

/// Verifies sample_configs::all_severities() includes all severity levels.
/// Edge case: Config with rules for Info, Warn, and Error severities.
#[test]
fn test_sample_configs_all_severities_has_each_severity() {
    let config = sample_configs::all_severities();

    // Should have exactly 3 rules
    assert_eq!(config.rule.len(), 3);

    // Should have one rule per severity level
    let severities: Vec<Severity> = config.rule.iter().map(|r| r.severity).collect();

    assert!(
        severities.contains(&Severity::Info),
        "Should have Info severity rule"
    );
    assert!(
        severities.contains(&Severity::Warn),
        "Should have Warn severity rule"
    );
    assert!(
        severities.contains(&Severity::Error),
        "Should have Error severity rule"
    );

    // Each rule ID should indicate its severity level
    assert!(config.rule.iter().any(|r| r.id == "test.info"));
    assert!(config.rule.iter().any(|r| r.id == "test.warn"));
    assert!(config.rule.iter().any(|r| r.id == "test.error"));
}

/// Verifies sample_configs::minimal() creates a valid pattern.
/// Edge case: Minimal config with single rule using default MatchMode.
#[test]
fn test_sample_configs_minimal_uses_default_match_mode() {
    let config = sample_configs::minimal();

    assert_eq!(config.rule.len(), 1);
    let rule = &config.rule[0];

    // MatchMode should be Default
    assert_eq!(rule.match_mode, Default::default());

    // Should have at least one pattern
    assert!(!rule.patterns.is_empty());

    // Patterns should be valid strings
    assert!(!rule.patterns[0].is_empty());
}

/// Verifies that all sample_configs fixtures have valid Schema.
/// Edge case: Schema validation for configs that weren't individually tested.
#[test]
fn test_sample_configs_js_python_multi_all_severities_valid() {
    // These configs were not individually tested in red tests
    let configs = [
        sample_configs::javascript_focused(),
        sample_configs::python_focused(),
        sample_configs::multi_language(),
        sample_configs::all_severities(),
    ];

    for config in configs {
        // Each should have valid structure
        assert!(
            !config.rule.is_empty(),
            "Config should have at least one rule"
        );

        // Each rule should have valid required fields
        for rule in &config.rule {
            assert!(!rule.id.is_empty(), "Rule ID should not be empty");
            assert!(!rule.message.is_empty(), "Rule message should not be empty");
            assert!(
                !rule.patterns.is_empty(),
                "Rule should have at least one pattern"
            );
        }
    }
}

// =============================================================================
// sample_receipts edge cases
// =============================================================================

/// Verifies sample_receipts::pass() verdict counts are all zero.
/// Edge case: Empty verdict with zero counts.
#[test]
fn test_sample_receipts_pass_has_zero_counts() {
    let receipt = sample_receipts::pass();

    assert_eq!(receipt.verdict.status, VerdictStatus::Pass);
    assert!(receipt.findings.is_empty());

    // Verdict counts should all be zero for a passing receipt
    assert_eq!(receipt.verdict.counts.info, 0);
    assert_eq!(receipt.verdict.counts.warn, 0);
    assert_eq!(receipt.verdict.counts.error, 0);
    assert_eq!(receipt.verdict.counts.suppressed, 0);

    // Reasons should be empty for pass
    assert!(receipt.verdict.reasons.is_empty());
}

/// Verifies sample_receipts::mixed_severities() has all severity levels.
/// Edge case: Multi-finding receipt with Info, Warn, and Error findings.
#[test]
fn test_sample_receipts_mixed_severities_has_all_levels() {
    let receipt = sample_receipts::mixed_severities();

    assert_eq!(receipt.verdict.status, VerdictStatus::Fail);
    assert_eq!(receipt.findings.len(), 3);

    // Should have one of each severity
    let severities: Vec<Severity> = receipt.findings.iter().map(|f| f.severity).collect();

    assert!(
        severities.contains(&Severity::Info),
        "Should have Info severity finding"
    );
    assert!(
        severities.contains(&Severity::Warn),
        "Should have Warn severity finding"
    );
    assert!(
        severities.contains(&Severity::Error),
        "Should have Error severity finding"
    );

    // Verdict counts should match findings
    assert_eq!(receipt.verdict.counts.info, 1);
    assert_eq!(receipt.verdict.counts.warn, 1);
    assert_eq!(receipt.verdict.counts.error, 1);
    assert_eq!(receipt.verdict.counts.suppressed, 0);
}

/// Verifies sample_receipts::mixed_severities() has correct reasons.
/// Edge case: Multiple reasons listed for multi-severity findings.
#[test]
fn test_sample_receipts_mixed_severities_has_reasons() {
    let receipt = sample_receipts::mixed_severities();

    // Should have reasons since there are errors
    assert!(!receipt.verdict.reasons.is_empty());

    // Should mention error-level findings in reasons
    let has_error_reason = receipt.verdict.reasons.iter().any(|r| r.contains("error"));
    assert!(
        has_error_reason,
        "Reasons should mention error-level findings"
    );
}

/// Verifies sample_receipts::with_warnings() has correct counts.
/// Edge case: Warning-only receipt with suppressed=0.
#[test]
fn test_sample_receipts_with_warnings_suppressed_is_zero() {
    let receipt = sample_receipts::with_warnings();

    assert_eq!(receipt.verdict.status, VerdictStatus::Warn);
    assert_eq!(receipt.verdict.counts.warn, 1);
    assert_eq!(receipt.verdict.counts.suppressed, 0);
    assert_eq!(receipt.verdict.counts.info, 0);
    assert_eq!(receipt.verdict.counts.error, 0);
}

/// Verifies sample_receipts::fail() has correct counts.
/// Edge case: Error-only receipt with one error finding.
#[test]
fn test_sample_receipts_fail_counts_match_findings() {
    let receipt = sample_receipts::fail();

    assert_eq!(receipt.verdict.status, VerdictStatus::Fail);
    assert_eq!(receipt.findings.len(), 1);
    assert_eq!(receipt.findings[0].severity, Severity::Error);

    // Counts should match
    assert_eq!(receipt.verdict.counts.error, 1);
    assert_eq!(receipt.verdict.counts.warn, 0);
    assert_eq!(receipt.verdict.counts.info, 0);
    assert_eq!(receipt.verdict.counts.suppressed, 0);
}

/// Verifies all sample_receipts fixtures have valid Finding structure.
/// Edge case: Verifies Finding fields (rule_id, severity, message, path, line).
#[test]
fn test_sample_receipts_all_finding_fields_valid() {
    let receipts = [
        sample_receipts::with_warnings(),
        sample_receipts::fail(),
        sample_receipts::mixed_severities(),
    ];

    for receipt in receipts {
        for finding in &receipt.findings {
            // All finding fields should be populated
            assert!(
                !finding.rule_id.is_empty(),
                "Finding rule_id should not be empty"
            );
            assert!(
                !finding.message.is_empty(),
                "Finding message should not be empty"
            );
            assert!(!finding.path.is_empty(), "Finding path should not be empty");
            assert!(finding.line > 0, "Finding line should be > 0");
            assert!(
                !finding.match_text.is_empty(),
                "Finding match_text should not be empty"
            );
        }
    }
}

/// Verifies sample_receipts::pass() uses Scope::Added.
/// Edge case: Verify scope is not Changed or Modified in pass receipt.
#[test]
fn test_sample_receipts_pass_uses_scope_added() {
    let receipt = sample_receipts::pass();

    assert_eq!(receipt.diff.scope, Scope::Added);

    // Verify it doesn't use other scopes
    assert_ne!(receipt.diff.scope, Scope::Modified);
    assert_ne!(receipt.diff.scope, Scope::Changed);
}

/// Verifies sample_receipts::mixed_severities() uses Scope::Changed.
/// Edge case: Mixed severity receipt scans changed scope.
#[test]
fn test_sample_receipts_mixed_severities_uses_scope_changed() {
    let receipt = sample_receipts::mixed_severities();

    assert_eq!(receipt.diff.scope, Scope::Changed);
}

/// Verifies sample_receipts fixtures have non-zero diff stats.
/// Edge case: Verify files_scanned and lines_scanned are meaningful.
#[test]
fn test_sample_receipts_diff_stats_meaningful() {
    let receipts = [
        sample_receipts::pass(),
        sample_receipts::with_warnings(),
        sample_receipts::fail(),
        sample_receipts::mixed_severities(),
    ];

    for receipt in receipts {
        assert!(
            receipt.diff.files_scanned > 0,
            "files_scanned should be > 0"
        );
        assert!(
            receipt.diff.lines_scanned > 0,
            "lines_scanned should be > 0"
        );
    }
}

/// Verifies sample_receipts fixtures have correct schema version.
/// Edge case: All receipts should use CHECK_SCHEMA_V1 ("diffguard.check.v1").
#[test]
fn test_sample_receipts_all_use_schema_v1() {
    use diffguard_types::CHECK_SCHEMA_V1;

    let receipts = [
        sample_receipts::pass(),
        sample_receipts::with_warnings(),
        sample_receipts::fail(),
        sample_receipts::mixed_severities(),
    ];

    for receipt in receipts {
        assert_eq!(
            receipt.schema, CHECK_SCHEMA_V1,
            "All receipts should use the current schema version"
        );
    }
}

/// Verifies sample_receipts fixtures have tool metadata.
/// Edge case: Tool name and version should be populated.
#[test]
fn test_sample_receipts_tool_metadata_populated() {
    let receipts = [
        sample_receipts::pass(),
        sample_receipts::with_warnings(),
        sample_receipts::fail(),
        sample_receipts::mixed_severities(),
    ];

    for receipt in receipts {
        assert_eq!(receipt.tool.name, "diffguard");
        assert!(!receipt.tool.version.is_empty());
    }
}

// =============================================================================
// Cross-fixture consistency tests
// =============================================================================

/// Verifies that verdict counts across receipts are consistent.
/// Edge case: VerdictCounts should be consistent with findings list length.
#[test]
fn test_sample_receipts_counts_consistent_with_findings() {
    let receipts = [
        sample_receipts::pass(),
        sample_receipts::with_warnings(),
        sample_receipts::fail(),
        sample_receipts::mixed_severities(),
    ];

    for receipt in receipts {
        let total_findings = receipt.findings.len();
        let total_counts = receipt.verdict.counts.info
            + receipt.verdict.counts.warn
            + receipt.verdict.counts.error
            + receipt.verdict.counts.suppressed;

        assert_eq!(
            total_findings as u32, total_counts,
            "Total findings should match sum of verdict counts"
        );
    }
}

/// Verifies that Scope defaults are used consistently.
/// Edge case: Defaults::default() uses Scope::Added; rust_focused() overrides it to Scope::Added explicitly.
#[test]
fn test_sample_configs_scope_defaults_vary() {
    // empty uses Defaults::default() which has scope: Some(Scope::Added)
    let empty_config = sample_configs::empty();
    assert_eq!(empty_config.defaults.scope, Some(Scope::Added));

    // rust_focused explicitly sets Scope::Added
    let rust_config = sample_configs::rust_focused();
    assert_eq!(rust_config.defaults.scope, Some(Scope::Added));
}
