//! Property-based tests for GitHub Actions SHA Pinning
//!
//! Verifies that all GitHub Actions in workflow files are pinned to SHA commits
//! rather than version tags like @v4, @v2, @stable.
//!
//! These tests verify invariants about the workflow files themselves.
//!
//! Run with: cargo test -p diffguard-core github_actions_sha_pinning

use std::fs;
use std::path::PathBuf;

/// Version tags that should NOT appear in uses: declarations
const VERSION_TAGS: &[&str] = &["@v4", "@v3", "@v2", "@v7", "@stable"];

/// Known action name prefixes that should be SHA-pinned
const KNOWN_ACTIONS: &[&str] = &[
    "actions/checkout",
    "actions/upload-artifact",
    "actions/download-artifact",
    "actions/github-script",
    "Swatinem/rust-cache",
    "github/codeql-action/upload-sarif",
    "softprops/action-gh-release",
];

/// Returns the path to a workflow file at the repo root
fn workflow_file_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows")
        .join(name)
}

fn read_workflow_file(name: &str) -> String {
    let path = workflow_file_path(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read workflow file {:?}: {}", path, e))
}

/// Extract all `uses:` declarations from a workflow file content
/// Note: GitHub Actions workflow lines look like "      - uses: actions/checkout@v4"
/// so we check for lines containing "uses:" after stripping leading whitespace.
/// Ignores commented-out lines (starting with #).
fn extract_uses_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            // Skip commented lines (out of scope per specs)
            if trimmed.starts_with('#') {
                return false;
            }
            // Check if this is a uses: line
            trimmed.starts_with("uses:") || trimmed.contains("uses:")
        })
        .map(|line| line.trim().to_string())
        .collect()
}

/// Extract the action reference from a uses line
/// Lines look like "- uses: actions/checkout@v4" or "uses: actions/checkout@v4"
/// We extract just the "owner/repo@ref" part
fn extract_action_ref(line: &str) -> Option<String> {
    // Find "uses:" in the line and take everything after it
    if let Some(pos) = line.find("uses:") {
        let after_uses = &line[pos + 5..]; // 5 = len("uses:")
        let ref_part = after_uses.trim();
        // ref_part should look like "actions/checkout@v4"
        // Remove leading dash and space if present (e.g., "- actions/checkout@v4")
        let ref_part = ref_part.strip_prefix('-').unwrap_or(ref_part).trim();
        if ref_part.is_empty() {
            None
        } else {
            Some(ref_part.to_string())
        }
    } else {
        None
    }
}

/// Check if a string is a valid 40-character hexadecimal SHA
fn is_valid_sha(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ============================================================================
// Property 1: No version tags in uses declarations
// Invariant: For all workflow files, no uses: line contains version tags (@v4, @v2, etc.)
// ============================================================================

fn check_no_version_tags_in_uses_lines(uses_lines: &[String]) -> Vec<(String, String)> {
    // Returns list of (line, offending_tag) pairs
    let mut violations = Vec::new();
    for line in uses_lines {
        for tag in VERSION_TAGS {
            if line.contains(tag) {
                violations.push((line.clone(), tag.to_string()));
            }
        }
    }
    violations
}

// ============================================================================
// Property 2: All known action references are SHA-pinned
// Invariant: Any uses: line with a known action must end with a 40-char SHA
// ============================================================================

fn check_known_actions_are_sha_pinned(uses_lines: &[String]) -> Vec<(String, String)> {
    // Returns list of (line, action_name) pairs where SHA is missing or invalid
    let mut violations = Vec::new();
    for line in uses_lines {
        if let Some(action_ref) = extract_action_ref(line) {
            // Check if it's a known action
            for action_name in KNOWN_ACTIONS {
                if action_ref.starts_with(action_name) {
                    // Extract what comes after the @
                    if let Some(at_pos) = action_ref.find('@') {
                        let after_at = &action_ref[at_pos + 1..];
                        if !is_valid_sha(after_at) {
                            violations.push((line.clone(), action_name.to_string()));
                        }
                    } else {
                        // Has no @ at all
                        violations.push((line.clone(), action_name.to_string()));
                    }
                }
            }
        }
    }
    violations
}

// ============================================================================
// Property 3: dtolnay/rust-toolchain uses specific version (not @stable)
// Invariant: dtolnay/rust-toolchain@<version> where version is a valid Rust version
// ============================================================================

fn check_rust_toolchain_uses_version(uses_lines: &[String]) -> Vec<(String, String)> {
    // Returns list of (line, reason) pairs for dtolnay/rust-toolchain violations
    let mut violations = Vec::new();
    for line in uses_lines {
        if let Some(action_ref) = extract_action_ref(line) {
            if action_ref.starts_with("dtolnay/rust-toolchain") {
                // Should have @<version> not @stable
                if action_ref.contains("@stable") {
                    violations.push((line.clone(), "uses @stable instead of version".to_string()));
                } else if let Some(at_pos) = action_ref.find('@') {
                    let version = &action_ref[at_pos + 1..];
                    // Version should look like a version number (e.g., 1.85.0)
                    if !version.contains('.') || version.len() < 5 {
                        violations.push((line.clone(), format!("invalid version: {}", version)));
                    }
                }
            }
        }
    }
    violations
}

// ============================================================================
// Property 4: All uses: lines have well-formed references
// Invariant: Every uses: value matches the pattern owner/repo@ref
// ============================================================================

fn check_well_formed_uses_lines(uses_lines: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();
    for line in uses_lines {
        if let Some(action_ref) = extract_action_ref(line) {
            // Must contain @ and have at least one /
            if !action_ref.contains('@') {
                violations.push((line.clone(), "missing @ separator".to_string()));
            } else if !action_ref.contains('/') {
                violations.push((line.clone(), "missing / in action reference".to_string()));
            }
        }
    }
    violations
}

// ============================================================================
// Test for ci.yml
// ============================================================================

#[test]
fn property_ci_workflow_no_version_tags() {
    let content = read_workflow_file("ci.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_no_version_tags_in_uses_lines(&uses_lines);

    assert!(
        violations.is_empty(),
        "ci.yml contains version tags in uses: declarations: {:?}",
        violations
    );
}

#[test]
fn property_ci_workflow_known_actions_sha_pinned() {
    let content = read_workflow_file("ci.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_known_actions_are_sha_pinned(&uses_lines);

    assert!(
        violations.is_empty(),
        "ci.yml has known actions not SHA-pinned: {:?}",
        violations
    );
}

#[test]
fn property_ci_workflow_rust_toolchain_versioned() {
    let content = read_workflow_file("ci.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_rust_toolchain_uses_version(&uses_lines);

    assert!(
        violations.is_empty(),
        "ci.yml has dtolnay/rust-toolchain issues: {:?}",
        violations
    );
}

#[test]
fn property_ci_workflow_well_formed_uses() {
    let content = read_workflow_file("ci.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_well_formed_uses_lines(&uses_lines);

    assert!(
        violations.is_empty(),
        "ci.yml has malformed uses: declarations: {:?}",
        violations
    );
}

// ============================================================================
// Test for publish.yml
// ============================================================================

#[test]
fn property_publish_workflow_no_version_tags() {
    let content = read_workflow_file("publish.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_no_version_tags_in_uses_lines(&uses_lines);

    assert!(
        violations.is_empty(),
        "publish.yml contains version tags in uses: declarations: {:?}",
        violations
    );
}

#[test]
fn property_publish_workflow_known_actions_sha_pinned() {
    let content = read_workflow_file("publish.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_known_actions_are_sha_pinned(&uses_lines);

    assert!(
        violations.is_empty(),
        "publish.yml has known actions not SHA-pinned: {:?}",
        violations
    );
}

#[test]
fn property_publish_workflow_rust_toolchain_versioned() {
    let content = read_workflow_file("publish.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_rust_toolchain_uses_version(&uses_lines);

    assert!(
        violations.is_empty(),
        "publish.yml has dtolnay/rust-toolchain issues: {:?}",
        violations
    );
}

#[test]
fn property_publish_workflow_well_formed_uses() {
    let content = read_workflow_file("publish.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_well_formed_uses_lines(&uses_lines);

    assert!(
        violations.is_empty(),
        "publish.yml has malformed uses: declarations: {:?}",
        violations
    );
}

// ============================================================================
// Test for sarif-example.yml
// ============================================================================

#[test]
fn property_sarif_example_workflow_no_version_tags() {
    let content = read_workflow_file("sarif-example.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_no_version_tags_in_uses_lines(&uses_lines);

    assert!(
        violations.is_empty(),
        "sarif-example.yml contains version tags in uses: declarations: {:?}",
        violations
    );
}

#[test]
fn property_sarif_example_workflow_known_actions_sha_pinned() {
    let content = read_workflow_file("sarif-example.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_known_actions_are_sha_pinned(&uses_lines);

    assert!(
        violations.is_empty(),
        "sarif-example.yml has known actions not SHA-pinned: {:?}",
        violations
    );
}

#[test]
fn property_sarif_example_workflow_rust_toolchain_versioned() {
    let content = read_workflow_file("sarif-example.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_rust_toolchain_uses_version(&uses_lines);

    assert!(
        violations.is_empty(),
        "sarif-example.yml has dtolnay/rust-toolchain issues: {:?}",
        violations
    );
}

#[test]
fn property_sarif_example_workflow_well_formed_uses() {
    let content = read_workflow_file("sarif-example.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_well_formed_uses_lines(&uses_lines);

    assert!(
        violations.is_empty(),
        "sarif-example.yml has malformed uses: declarations: {:?}",
        violations
    );
}

// ============================================================================
// Test for diffguard.yml
// ============================================================================

#[test]
fn property_diffguard_workflow_no_version_tags() {
    let content = read_workflow_file("diffguard.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_no_version_tags_in_uses_lines(&uses_lines);

    assert!(
        violations.is_empty(),
        "diffguard.yml contains version tags in uses: declarations: {:?}",
        violations
    );
}

#[test]
fn property_diffguard_workflow_known_actions_sha_pinned() {
    let content = read_workflow_file("diffguard.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_known_actions_are_sha_pinned(&uses_lines);

    assert!(
        violations.is_empty(),
        "diffguard.yml has known actions not SHA-pinned: {:?}",
        violations
    );
}

#[test]
fn property_diffguard_workflow_rust_toolchain_versioned() {
    let content = read_workflow_file("diffguard.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_rust_toolchain_uses_version(&uses_lines);

    assert!(
        violations.is_empty(),
        "diffguard.yml has dtolnay/rust-toolchain issues: {:?}",
        violations
    );
}

#[test]
fn property_diffguard_workflow_well_formed_uses() {
    let content = read_workflow_file("diffguard.yml");
    let uses_lines = extract_uses_lines(&content);
    let violations = check_well_formed_uses_lines(&uses_lines);

    assert!(
        violations.is_empty(),
        "diffguard.yml has malformed uses: declarations: {:?}",
        violations
    );
}
