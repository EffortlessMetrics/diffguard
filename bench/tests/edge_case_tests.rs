//! Edge case tests for diffguard-bench dependency structure.
//!
//! These tests validate edge cases not covered by the red tests,
//! ensuring the implementation is robust against future regressions.
//!
//! Edge cases covered:
//! - Bench code actually uses diffguard_core from dev-dependencies
//! - Test code actually uses diffguard_core from dev-dependencies
//! - Commented dependencies are not counted by the parser
//! - Similar dependency names (prefix collision) don't cause false positives

use std::env;
use std::fs;

/// Get the path to the bench crate directory.
fn bench_crate_dir() -> std::path::PathBuf {
    env::var("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
}

// =============================================================================
// Edge Case 1: Bench code actually uses diffguard_core
// =============================================================================

/// Verify that benchmark code actually uses diffguard_core.
///
/// This confirms that diffguard-core being in [dev-dependencies] is
/// not just correct, but actually required by the benchmark code.
#[test]
fn test_benchmark_code_uses_diffguard_core() {
    let manifest_dir = bench_crate_dir();
    let rendering_rs_path = manifest_dir.join("benches/rendering.rs");

    let rendering_rs = fs::read_to_string(&rendering_rs_path)
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", rendering_rs_path, e));

    // The rendering benchmark uses render_markdown_for_receipt and render_sarif_for_receipt
    // which are imported from diffguard_core
    assert!(
        rendering_rs.contains("use diffguard_core::"),
        "benches/rendering.rs should import from diffguard_core. \
         If this fails, diffguard-core might be incorrectly placed or the import was removed."
    );

    // More specifically, check for the actual imports used in rendering benchmarks
    assert!(
        rendering_rs.contains("render_markdown_for_receipt"),
        "benches/rendering.rs should use render_markdown_for_receipt from diffguard_core"
    );
    assert!(
        rendering_rs.contains("render_sarif_for_receipt"),
        "benches/rendering.rs should use render_sarif_for_receipt from diffguard_core"
    );
}

// =============================================================================
// Edge Case 2: Test code actually uses diffguard_core
// =============================================================================

/// Verify that test code actually uses diffguard_core.
///
/// This confirms that diffguard-core being in [dev-dependencies] is
/// not just correct, but actually required by the test code.
#[test]
fn test_test_code_uses_diffguard_core() {
    let manifest_dir = bench_crate_dir();
    let snapshot_tests_path = manifest_dir.join("tests/snapshot_tests.rs");

    let snapshot_tests = fs::read_to_string(&snapshot_tests_path)
        .unwrap_or_else(|e| panic!("Failed to read {:?}: {}", snapshot_tests_path, e));

    // The snapshot tests use rendering functions from diffguard_core
    assert!(
        snapshot_tests.contains("use diffguard_core::"),
        "tests/snapshot_tests.rs should import from diffguard_core. \
         If this fails, diffguard-core might be incorrectly placed or the import was removed."
    );

    // More specifically, check for the actual imports used in snapshot tests
    assert!(
        snapshot_tests.contains("render_markdown_for_receipt"),
        "tests/snapshot_tests.rs should use render_markdown_for_receipt from diffguard_core"
    );
    assert!(
        snapshot_tests.contains("render_sarif_for_receipt"),
        "tests/snapshot_tests.rs should use render_sarif_for_receipt from diffguard_core"
    );
}

// =============================================================================
// Edge Case 3: Commented dependencies are not counted
// =============================================================================

/// Verify that the dependency counting logic ignores commented lines.
///
/// This is critical because a commented-out duplicate should NOT be
/// counted as an actual dependency declaration.
#[test]
fn test_comment_lines_are_ignored() {
    // Simulate a Cargo.toml with a commented duplicate dependency
    let content = r#"
[dependencies]
# diffguard-core = { path = "../crates/diffguard-core", version = "0.2.0" }
other-dep = "1.0"

[dev-dependencies]
diffguard-core = { path = "../crates/diffguard-core", version = "0.2.0" }
"#;

    let count = count_dependency_occurrences(content, "diffguard-core");

    // The commented line should NOT be counted
    assert_eq!(
        count, 1,
        "Commented dependency lines should be ignored. Found {} occurrences but expected 1",
        count
    );
}

/// Count occurrences of a dependency name in Cargo.toml content.
/// This is a pure parsing function that ignores:
/// - Comment lines (starting with # after trimming)
/// - Incomplete declarations (not ending with =)
fn count_dependency_occurrences(content: &str, dep_name: &str) -> usize {
    let mut count = 0;
    for line in content.lines() {
        let trimmed = line.trim();
        // Skip empty lines and comment-only lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // Match dependency declarations
        // Must start with dep_name, followed by = (not part of a path)
        if trimmed.starts_with(dep_name)
            && trimmed.len() > dep_name.len()
            && trimmed[dep_name.len()..].trim().starts_with('=')
        {
            count += 1;
        }
    }
    count
}

// =============================================================================
// Edge Case 4: Prefix collision - similar names don't cause false positives
// =============================================================================

/// Verify that a dependency with a similar prefix name doesn't cause
/// false positives in dependency counting.
///
/// For example, if we had `diffguard-core` and `diffguard-core-extra`,
/// counting `diffguard-core` should NOT match the longer name.
#[test]
fn test_prefix_collision_handled() {
    // Simulate a Cargo.toml with a similar-named dependency
    let content = r#"
[dependencies]
diffguard-core-extra = "1.0"

[dev-dependencies]
diffguard-core = { path = "../crates/diffguard-core", version = "0.2.0" }
"#;

    // Count should be exactly 1 for diffguard-core (not 2)
    let count = count_dependency_occurrences(content, "diffguard-core");
    assert_eq!(
        count, 1,
        "Prefix collision: diffguard-core-extra should NOT be counted as diffguard-core. \
         Found {} occurrences but expected 1",
        count
    );

    // Verify diffguard-core-extra is NOT in our count
    let extra_count = count_dependency_occurrences(content, "diffguard-core-extra");
    assert_eq!(
        extra_count, 1,
        "diffguard-core-extra should be counted separately. Found {} occurrences",
        extra_count
    );
}

// =============================================================================
// Edge Case 6: Empty lines and whitespace variations
// =============================================================================

/// Verify that empty lines and various whitespace patterns don't break parsing.
#[test]
fn test_whitespace_variations_handled() {
    // Cargo.toml with various whitespace patterns
    let content = "
[dependencies]
\tcriterion = \"0.5\"
    
    diffguard-diff = { path = \"../crates/diffguard-diff\", version = \"0.2.0\" }
  diffguard-domain = { path = \"../crates/diffguard-domain\", version = \"0.2.0\" }

[dev-dependencies]
proptest = \"1.5\"
diffguard-core = { path = \"../crates/diffguard-core\", version = \"0.2.0\" }
";

    let count = count_dependency_occurrences(content, "diffguard-core");

    assert_eq!(
        count, 1,
        "Whitespace variations should not affect counting. Found {} occurrences",
        count
    );

    // Also verify the other deps are counted
    let diff_count = count_dependency_occurrences(content, "diffguard-diff");
    assert_eq!(diff_count, 1);
    let domain_count = count_dependency_occurrences(content, "diffguard-domain");
    assert_eq!(domain_count, 1);
    let criterion_count = count_dependency_occurrences(content, "criterion");
    assert_eq!(criterion_count, 1);
}

// =============================================================================
// Edge Case 7: Section boundaries - deps in wrong section detected
// =============================================================================

/// Verify that a dependency appearing in the wrong section is detected.
#[test]
fn test_dep_in_wrong_section_detected() {
    // diffguard-core in [dependencies] when it should only be in [dev-dependencies]
    let content = "
[dependencies]
diffguard-core = { path = \"../crates/diffguard-core\", version = \"0.2.0\" }

[dev-dependencies]
diffguard-core = { path = \"../crates/diffguard-core\", version = \"0.2.0\" }
";

    let in_deps = dep_in_dependencies_section(content, "diffguard-core");

    assert!(
        in_deps,
        "diffguard-core in [dependencies] should be detected as being in the wrong section"
    );
}

/// Check if a dependency appears in the [dependencies] section (not [dev-dependencies]).
fn dep_in_dependencies_section(content: &str, dep_name: &str) -> bool {
    let deps_section_start = content.find("[dependencies]");
    let dev_deps_section_start = content.find("[dev-dependencies]");

    if let Some(deps_pos) = deps_section_start {
        let deps_end = dev_deps_section_start.unwrap_or(content.len());
        let deps_section = &content[deps_pos..deps_end];

        let mut found_section_header = false;
        for line in deps_section.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.starts_with('[') {
                if found_section_header {
                    break;
                }
                found_section_header = true;
                continue;
            }
            if trimmed.starts_with(dep_name)
                && trimmed.len() > dep_name.len()
                && trimmed[dep_name.len()..].trim().starts_with('=')
            {
                return true;
            }
        }
    }
    false
}
