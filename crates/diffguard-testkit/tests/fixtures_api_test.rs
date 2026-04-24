//! API tests for fixtures module.
//!
//! These tests verify that the `sample_configs` and `sample_receipts` submodules
//! correctly expose their functions with proper types. The fixture functions must
//! be accessible and return the expected types.
//!
//! This test module DOES NOT trigger clippy's wildcard_imports warning in
//! fixtures.rs because it only imports from the PUBLIC API of diffguard_testkit,
//! not from the internal module structure. The wildcard_imports lint is
//! verified separately via:
//!   cargo clippy -p diffguard-testkit -- -W clippy::wildcard-imports
//!
//! The fix (replacing `use super::*;` with explicit imports) ensures that when
//! clippy's wildcard_imports lint IS enabled, no warnings are produced.

use diffguard_testkit::fixtures::{sample_configs, sample_receipts};
use diffguard_types::{CheckReceipt, ConfigFile, Defaults, FailOn, Scope, Severity, VerdictStatus};

// =============================================================================
// sample_configs tests
// =============================================================================

/// Verifies sample_configs::empty() returns a valid ConfigFile with no rules.
#[test]
fn test_sample_configs_empty_returns_config_file() {
    let config = sample_configs::empty();

    // Should be a valid ConfigFile
    assert_eq!(config.includes.len(), 0);
    assert_eq!(config.rule.len(), 0);

    // Defaults should be the default value
    assert_eq!(config.defaults, Defaults::default());
}

/// Verifies sample_configs::minimal() returns a ConfigFile with one rule.
#[test]
fn test_sample_configs_minimal_returns_config_file_with_one_rule() {
    let config = sample_configs::minimal();

    assert_eq!(config.includes.len(), 0);
    assert_eq!(config.rule.len(), 1);

    let rule = &config.rule[0];
    assert_eq!(rule.id, "test.rule");
    assert_eq!(rule.severity, Severity::Warn);
}

/// Verifies sample_configs::rust_focused() returns a ConfigFile with
/// FailOn::Error in defaults and multiple rules.
#[test]
fn test_sample_configs_rust_focused_has_fail_on_error() {
    let config = sample_configs::rust_focused();

    // Should have FailOn::Error set
    assert_eq!(config.defaults.fail_on, Some(FailOn::Error));

    // Should have multiple rules
    assert!(config.rule.len() >= 2);

    // First rule should be rust.no_unwrap
    let first_rule = &config.rule[0];
    assert_eq!(first_rule.id, "rust.no_unwrap");
    assert_eq!(first_rule.severity, Severity::Error);

    // Should use Scope::Added
    assert_eq!(config.defaults.scope, Some(Scope::Added));
}

/// Verifies sample_configs functions use proper types from parent module.
/// This is a compile-time verification - if explicit imports are incorrect,
/// this test will fail to compile.
#[test]
fn test_sample_configs_types_are_accessible() {
    // These type annotations verify the return types match expectations
    let _empty: ConfigFile = sample_configs::empty();
    let _minimal: ConfigFile = sample_configs::minimal();
    let _rust: ConfigFile = sample_configs::rust_focused();

    // Verify the types used internally are accessible
    let config = sample_configs::rust_focused();
    let _rule_config = &config.rule[0];
    let _severity = config.rule[0].severity;
    let _defaults = &config.defaults;
    let _fail_on = config.defaults.fail_on;
    let _scope = config.defaults.scope;
}

// =============================================================================
// sample_receipts tests
// =============================================================================

/// Verifies sample_receipts::pass() returns a passing CheckReceipt.
#[test]
fn test_sample_receipts_pass_returns_passing_receipt() {
    let receipt = sample_receipts::pass();

    assert_eq!(receipt.verdict.status, VerdictStatus::Pass);
    assert_eq!(receipt.findings.len(), 0);
    assert_eq!(receipt.diff.scope, Scope::Added);
}

/// Verifies sample_receipts::with_warnings() returns a warning-level receipt.
#[test]
fn test_sample_receipts_with_warnings_has_one_warning() {
    let receipt = sample_receipts::with_warnings();

    assert_eq!(receipt.verdict.status, VerdictStatus::Warn);
    assert_eq!(receipt.findings.len(), 1);
    assert_eq!(receipt.findings[0].severity, Severity::Warn);
    assert_eq!(receipt.verdict.counts.warn, 1);
}

/// Verifies sample_receipts::fail() returns a failing receipt.
#[test]
fn test_sample_receipts_fail_returns_failing_receipt() {
    let receipt = sample_receipts::fail();

    assert_eq!(receipt.verdict.status, VerdictStatus::Fail);
    assert_eq!(receipt.findings.len(), 1);
    assert_eq!(receipt.findings[0].severity, Severity::Error);
    assert_eq!(receipt.verdict.counts.error, 1);
}

/// Verifies sample_receipts functions use proper types from parent module.
/// This is a compile-time verification - if explicit imports are incorrect,
/// this test will fail to compile.
#[test]
fn test_sample_receipts_types_are_accessible() {
    // These type annotations verify the return types match expectations
    let _pass: CheckReceipt = sample_receipts::pass();
    let _warn: CheckReceipt = sample_receipts::with_warnings();
    let _fail: CheckReceipt = sample_receipts::fail();
    let _mixed: CheckReceipt = sample_receipts::mixed_severities();

    // Verify the types used internally are accessible
    let receipt = sample_receipts::with_warnings();
    let _finding = &receipt.findings[0];
    let _severity = receipt.findings[0].severity;
    let _scope = receipt.diff.scope;
    let _verdict = &receipt.verdict;
    let _verdict_counts = &receipt.verdict.counts;
    let _verdict_status = receipt.verdict.status;
}

/// Verifies that CheckReceipt fields used in fixtures are properly structured.
#[test]
fn test_sample_receipts_check_receipt_structure() {
    let receipt = sample_receipts::pass();

    // Verify schema is set
    assert!(!receipt.schema.is_empty());

    // Verify tool metadata
    assert_eq!(receipt.tool.name, "diffguard");
    assert!(!receipt.tool.version.is_empty());

    // Verify diff metadata
    assert_eq!(receipt.diff.base, "origin/main");
    assert_eq!(receipt.diff.head, "HEAD");
    assert_eq!(receipt.diff.scope, Scope::Added);
}
