//! BDD-style integration tests for diffguard CLI workflows.
//!
//! These tests follow Given/When/Then patterns to verify end-to-end CLI behavior.

#[path = "integration/test_repo.rs"]
mod test_repo;

#[path = "integration/diff_only_scoping.rs"]
mod diff_only_scoping;

#[path = "integration/base_only_unchanged.rs"]
mod base_only_unchanged;

#[path = "integration/suppression_directive.rs"]
mod suppression_directive;

#[path = "integration/max_findings_cap.rs"]
mod max_findings_cap;

#[path = "integration/missing_base_shallow_clone.rs"]
mod missing_base_shallow_clone;

#[path = "integration/config_file_loading.rs"]
mod config_file_loading;

#[path = "integration/multiple_file_types.rs"]
mod multiple_file_types;

#[path = "integration/directory_overrides.rs"]
mod directory_overrides;
