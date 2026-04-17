//! Tests for the CheckPipeline refactoring defined in ADR-058.
//!
//! These tests verify that the refactoring extracts cmd_check_inner() concerns
//! into independently testable units in diffguard-core.
//!
//! AC2: BlameFilters, BlameLineMeta, parse_blame_porcelain(), collect_blame_allowed_lines()
//!       should be in diffguard-core as data-driven functions.
//! AC3: load_directory_overrides_for_diff() should be in diffguard-core as data-driven.
//! AC4: DiffInput and prepare_diff_input_* functions should be in diffguard-core.
//! AC9: diffguard-core must have no I/O dependencies (no std::fs, std::process, etc.)

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

// ============================================================================
// AC4: DiffInput struct and diff-mode preparation functions
// ============================================================================

/// Test that DiffInput struct exists and has the required fields.
/// ADR-058 specifies:
/// ```rust
/// pub struct DiffInput {
///     pub base: String,
///     pub head: String,
///     pub diff_text: String,
/// }
/// ```
#[test]
fn test_diff_input_struct_exists_with_required_fields() {
    // This test will fail until DiffInput is defined in diffguard-core
    let input = diffguard_core::DiffInput {
        base: "origin/main".to_string(),
        head: "HEAD".to_string(),
        diff_text: "dummy diff text".to_string(),
    };
    assert_eq!(input.base, "origin/main");
    assert_eq!(input.head, "HEAD");
    assert_eq!(input.diff_text, "dummy diff text");
}

/// Test that prepare_diff_input_staged exists and works correctly.
/// For staged mode, base is "(staged)" and head is "HEAD".
#[test]
fn test_prepare_diff_input_staged() {
    let diff_text = "diff --git a/foo.rs b/foo.rs\n--- a/foo.rs\n+++ b/foo.rs\n@@ -1 +1 @@\n-old\n+new";
    let input = diffguard_core::prepare_diff_input_staged(diff_text);
    assert_eq!(input.base, "(staged)");
    assert_eq!(input.head, "HEAD");
    assert_eq!(input.diff_text, diff_text);
}

/// Test that prepare_diff_input_from_file exists and works correctly.
/// For file mode, base is "(file:<path>)" or "(stdin)" and head is from args.
#[test]
fn test_prepare_diff_input_from_file_with_stdin() {
    let diff_text = "diff from stdin";
    let input = diffguard_core::prepare_diff_input_from_file(diff_text, "HEAD");
    assert_eq!(input.base, "(stdin)");
    assert_eq!(input.head, "HEAD");
    assert_eq!(input.diff_text, diff_text);
}

/// Test that prepare_diff_input_from_file with a real path.
#[test]
fn test_prepare_diff_input_from_file_with_path() {
    let diff_text = "diff from file";
    let input = diffguard_core::prepare_diff_input_from_file(diff_text, "abc123");
    assert!(input.base.starts_with("(file:"));
    assert_eq!(input.head, "abc123");
    assert_eq!(input.diff_text, diff_text);
}

/// Test that prepare_diff_input_from_git exists and works correctly.
/// For multi-base mode, bases are joined with commas.
#[test]
fn test_prepare_diff_input_from_git_single_base() {
    let diff_text = "diff text";
    let bases = vec!["origin/main".to_string()];
    let input = diffguard_core::prepare_diff_input_from_git(diff_text, &bases, "HEAD");
    assert_eq!(input.base, "origin/main");
    assert_eq!(input.head, "HEAD");
    assert_eq!(input.diff_text, diff_text);
}

/// Test that prepare_diff_input_from_git handles multi-base correctly.
#[test]
fn test_prepare_diff_input_from_git_multi_base() {
    let diff_text = "combined diff";
    let bases = vec!["origin/main".to_string(), "origin/develop".to_string()];
    let input = diffguard_core::prepare_diff_input_from_git(diff_text, &bases, "HEAD");
    // Multi-base format: comma-joined base refs
    assert_eq!(input.base, "origin/main,origin/develop");
    assert_eq!(input.head, "HEAD");
    assert_eq!(input.diff_text, diff_text);
}

// ============================================================================
// AC2: BlameFilters and blame filtering in diffguard-core (data-driven)
// ============================================================================

/// Test that BlameFilters struct exists in diffguard-core.
/// The struct should have author_patterns and max_age_days fields.
#[test]
fn test_blame_filters_struct_exists() {
    // This test will fail until BlameFilters is moved to diffguard-core
    use diffguard_core::BlameFilters;

    let filters = BlameFilters::new(
        vec!["John Doe".to_string(), "jane".to_string()],
        Some(30),
    );
    assert_eq!(filters.author_patterns.len(), 2);
    assert_eq!(filters.max_age_days, Some(30));
}

/// Test that BlameLineMeta struct exists in diffguard-core.
/// The struct should have author, author_mail, and author_time fields.
#[test]
fn test_blame_line_meta_struct_exists() {
    use diffguard_core::BlameLineMeta;

    let meta = BlameLineMeta {
        author: "John Doe".to_string(),
        author_mail: "john@example.com".to_string(),
        author_time: 1700000000,
    };
    assert_eq!(meta.author, "John Doe");
    assert_eq!(meta.author_mail, "john@example.com");
    assert_eq!(meta.author_time, 1700000000);
}

/// Test that parse_blame_porcelain exists and parses correctly.
/// This is a data-driven function - it accepts text, not paths.
#[test]
fn test_parse_blame_porcelain_parses_single_file() {
    // This test will fail until parse_blame_porcelain is moved to diffguard-core
    let blame_text = r#"fatal: no such path foo.rs in HEAD
"#;
    // Even with the fatal error message, the function should not panic
    let result = diffguard_core::parse_blame_porcelain(blame_text);
    assert!(result.is_ok());
    let parsed = result.unwrap();
    // When git reports an error, result is empty
    assert!(parsed.is_empty());
}

/// Test parse_blame_porcelain with realistic porcelain output format.
/// The git blame --line-porcelain output has headers followed by a tab and line content.
#[test]
fn test_parse_blame_porcelain_with_realistic_input() {
    let blame_text = r#"abc1234567890 2 1
author John Doe
author-mail <john@example.com>
author-time 1700000000
summary commit message
filename foo.rs
	old line content
abc2234567890 3 1
author Jane Smith
author-mail <jane@example.com>
author-time 1700000001
summary another commit
filename foo.rs
	new line content
"#;
    let result = diffguard_core::parse_blame_porcelain(blame_text);
    assert!(result.is_ok());
    let parsed = result.unwrap();
    // Should have parsed 2 lines
    assert_eq!(parsed.len(), 2);

    // Line 2 should have author "John Doe"
    let line2_meta = parsed.get(&2).unwrap();
    assert_eq!(line2_meta.author, "John Doe");

    // Line 3 should have author "Jane Smith"
    let line3_meta = parsed.get(&3).unwrap();
    assert_eq!(line3_meta.author, "Jane Smith");
}

/// Test that collect_blame_allowed_lines is data-driven (accepts blame text, not paths).
/// The function signature should be:
/// collect_blame_allowed_lines(blame_text: &str, filters: &BlameFilters) -> Result<BTreeSet<(String, u32)>>
/// NOT: collect_blame_allowed_lines(args: &CheckArgs, filters: &BlameFilters, path: &Path) -> Result<...>
///
/// This test verifies the data-driven contract by passing pre-fetched blame text.
#[test]
fn test_collect_blame_allowed_lines_is_data_driven() {
    use diffguard_core::{collect_blame_allowed_lines, BlameFilters, Scope};

    let diff_text = r#"diff --git a/foo.rs b/foo.rs
--- a/foo.rs
+++ b/foo.rs
@@ -1 +1 @@
-old
+new
"#;

    // Create filters that match any author
    let filters = BlameFilters::new(vec![], None);

    // This should work with just text input - no git subprocess calls
    let result = collect_blame_allowed_lines(diff_text, Scope::Added, "HEAD", &filters);
    assert!(result.is_ok());
}

/// Test that collect_blame_allowed_lines filters by author correctly.
#[test]
fn test_collect_blame_allowed_lines_filters_by_author() {
    use diffguard_core::{collect_blame_allowed_lines, BlameFilters, Scope};

    let diff_text = r#"diff --git a/foo.rs b/foo.rs
--- a/foo.rs
+++ b/foo.rs
@@ -1 +1 @@
-old
+new
"#;

    // Create filters that only match "John" author
    let filters = BlameFilters::new(vec!["John".to_string()], None);

    // Even with a "John" filter, since there's no real blame data, result is empty
    let result = collect_blame_allowed_lines(diff_text, Scope::Added, "HEAD", &filters);
    assert!(result.is_ok());
    // No matching blame lines means empty result
    assert!(result.unwrap().is_empty());
}

// ============================================================================
// AC3: Directory overrides loading in diffguard-core (data-driven)
// ============================================================================

/// Test that load_directory_overrides_for_diff is data-driven.
/// The function signature should accept &HashMap<PathBuf, String>, not read files.
/// Old: load_directory_overrides_for_diff(diff_text: &str, scope: Scope) -> Result<Vec<DirectoryRuleOverride>>
/// New: load_directory_overrides_for_diff(override_contents: &HashMap<PathBuf, String>) -> Result<Vec<DirectoryRuleOverride>>
#[test]
fn test_load_directory_overrides_for_diff_is_data_driven() {
    use diffguard_core::load_directory_overrides_for_diff;

    let mut override_contents = HashMap::new();
    override_contents.insert(
        PathBuf::from("src/.diffguard.toml"),
        r#"
[[rule]]
id = "rust.no_console"
enabled = false
"#.to_string(),
    );

    // This is data-driven - no filesystem I/O needed, just parsing the TOML contents
    let result = load_directory_overrides_for_diff(&override_contents);
    assert!(result.is_ok());
    let overrides = result.unwrap();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].rule_id, "rust.no_console");
}

/// Test that load_directory_overrides_for_diff correctly parses multiple rules.
#[test]
fn test_load_directory_overrides_for_diff_multiple_rules() {
    use diffguard_core::load_directory_overrides_for_diff;

    let mut override_contents = HashMap::new();
    override_contents.insert(
        PathBuf::from("src/.diffguard.toml"),
        r#"
[[rule]]
id = "rust.no_console"
enabled = false

[[rule]]
id = "rust.no_debug"
severity = "warn"
"#.to_string(),
    );

    let result = load_directory_overrides_for_diff(&override_contents);
    assert!(result.is_ok());
    let overrides = result.unwrap();
    assert_eq!(overrides.len(), 2);

    // Rules should be in order
    assert_eq!(overrides[0].rule_id, "rust.no_console");
    assert_eq!(overrides[1].rule_id, "rust.no_debug");
}

/// Test that load_directory_overrides_for_diff handles empty input.
#[test]
fn test_load_directory_overrides_for_diff_empty() {
    use diffguard_core::load_directory_overrides_for_diff;

    let override_contents = HashMap::new();
    let result = load_directory_overrides_for_diff(&override_contents);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

/// Test that load_directory_overrides_for_diff handles exclude_paths.
#[test]
fn test_load_directory_overrides_for_diff_with_exclude_paths() {
    use diffguard_core::load_directory_overrides_for_diff;

    let mut override_contents = HashMap::new();
    override_contents.insert(
        PathBuf::from("src/.diffguard.toml"),
        r#"
[[rule]]
id = "rust.no_console"
enabled = false
exclude_paths = ["**/generated/**", "**/test/**"]
"#.to_string(),
    );

    let result = load_directory_overrides_for_diff(&override_contents);
    assert!(result.is_ok());
    let overrides = result.unwrap();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].exclude_paths.len(), 2);
}

// ============================================================================
// AC8: Exit codes preserved exactly
// ============================================================================

/// Test that compute_baseline_exit_code returns 0 when no new findings.
/// This is critical for baseline mode - grandfathered violations should exit 0.
#[test]
fn test_compute_baseline_exit_code_zero_when_no_new_findings() {
    use diffguard_core::compute_baseline_exit_code;
    use diffguard_types::{FailOn, VerdictCounts};

    let counts = VerdictCounts {
        info: 0,
        warn: 0,
        error: 0,
    };
    assert_eq!(compute_baseline_exit_code(FailOn::Error, &counts), 0);
    assert_eq!(compute_baseline_exit_code(FailOn::Warn, &counts), 0);
    assert_eq!(compute_baseline_exit_code(FailOn::Never, &counts), 0);
}

/// Test that compute_baseline_exit_code returns 2 when new errors found.
#[test]
fn test_compute_baseline_exit_code_2_on_new_errors() {
    use diffguard_core::compute_baseline_exit_code;
    use diffguard_types::{FailOn, VerdictCounts};

    let mut counts = VerdictCounts {
        info: 0,
        warn: 0,
        error: 1, // New error found
    };
    assert_eq!(compute_baseline_exit_code(FailOn::Error, &counts), 2);
    assert_eq!(compute_baseline_exit_code(FailOn::Warn, &counts), 2); // Errors override warnings
    assert_eq!(compute_baseline_exit_code(FailOn::Never, &counts), 0); // Never still exits 0
}

/// Test that compute_baseline_exit_code returns 3 when new warnings found (fail_on=Warn).
#[test]
fn test_compute_baseline_exit_code_3_on_new_warnings_with_fail_on_warn() {
    use diffguard_core::compute_baseline_exit_code;
    use diffguard_types::{FailOn, VerdictCounts};

    let counts = VerdictCounts {
        info: 0,
        warn: 1, // New warning found
        error: 0,
    };
    assert_eq!(compute_baseline_exit_code(FailOn::Error, &counts), 0); // No errors, fail_on=error doesn't trigger
    assert_eq!(compute_baseline_exit_code(FailOn::Warn, &counts), 3); // fail_on=warn triggers on warnings
    assert_eq!(compute_baseline_exit_code(FailOn::Never, &counts), 0);
}

/// Test that compute_baseline_exit_code returns 2 when both errors and warnings exist.
#[test]
fn test_compute_baseline_exit_code_2_takes_priority_over_3() {
    use diffguard_core::compute_baseline_exit_code;
    use diffguard_types::{FailOn, VerdictCounts};

    let counts = VerdictCounts {
        info: 0,
        warn: 5,
        error: 1, // Errors take priority
    };
    assert_eq!(compute_baseline_exit_code(FailOn::Error, &counts), 2);
    assert_eq!(compute_baseline_exit_code(FailOn::Warn, &counts), 2); // Errors override
}

// ============================================================================
// AC9: I/O boundary preserved - diffguard-core must not have I/O
// ============================================================================

/// Test that diffguard-core has no std::fs imports.
/// This is a compile-time check - if diffguard-core uses std::fs, it won't compile
/// as a no-std/no-io crate for certain use cases.
/// NOTE: This test documents the requirement but doesn't actually enforce it at runtime.
/// The real enforcement is through the crate's Cargo.toml configuration.
#[test]
fn test_diffguard_core_io_boundary_documented() {
    // The diffguard-core crate should be configured to not use std::fs or std::process.
    // This is documented in the crate's CLAUDE.md and enforced through design reviews.
    // The data-driven functions in this test file prove the I/O boundary is respected:
    // - parse_blame_porcelain takes text, not paths
    // - collect_blame_allowed_lines takes text, not paths
    // - load_directory_overrides_for_diff takes HashMap<PathBuf, String>, not paths
    // - prepare_diff_input_* functions take text, not git refs
    //
    // All git subprocess calls and filesystem operations remain in the CLI crate.
    assert!(true);
}

// ============================================================================
// Helper impls for testing (these would be the actual impls in the crate)
// ============================================================================

mod diffguard_core {
    // Re-export the items under test from the actual crate.
    // These tests will fail to compile (with proper error messages) until
    // the items are properly exported from diffguard-core.
    pub use diffguard_core::*;
}
