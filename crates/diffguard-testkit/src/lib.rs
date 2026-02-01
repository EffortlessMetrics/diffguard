//! Shared test utilities for diffguard workspace.
//!
//! This crate provides:
//! - **arb**: Proptest strategies for generating valid test inputs
//! - **diff_builder**: Unified diff builders for constructing test diffs
//! - **schema**: JSON schema validators for DTOs
//! - **fixtures**: Common test fixtures (sample configs, diffs, expected outputs)
//!
//! # Example
//!
//! ```rust,ignore
//! use diffguard_testkit::arb;
//! use proptest::prelude::*;
//!
//! proptest! {
//!     fn test_rule_config(rule in arb::rule_config()) {
//!         // Use the generated rule config
//!         assert!(!rule.id.is_empty());
//!     }
//! }
//! ```

pub mod arb;
pub mod diff_builder;
pub mod fixtures;
pub mod schema;

// Re-export commonly used items
pub use arb::{
    arb_fail_on, arb_glob_pattern, arb_regex_pattern, arb_rule_config, arb_scope, arb_severity,
};
pub use diff_builder::{DiffBuilder, FileBuilder, HunkBuilder};
pub use fixtures::{sample_configs, sample_diffs};
pub use schema::{validate_check_receipt, validate_config_file};
