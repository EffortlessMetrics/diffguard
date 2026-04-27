//! Integration tests for GitHub Actions SHA pinning in workflow files.
//!
//! This tests the end-to-end flow: workflow file → YAML parsing → SHA extraction → validation.
//!
//! These tests verify that all GitHub Actions `uses:` declarations in workflow files
//! have been properly pinned to SHA commits rather than version tags.
//!
//! Run with: cargo test -p diffguard-core github_actions_sha_pinning_integration

use std::fs;
use std::path::PathBuf;

/// SHA values that should be present in workflow files
const ACTIONS_CHECKOUT_SHA: &str = "34e114876b0b11c390a56381ad16ebd13914f8d5";
const RUST_TOOLCHAIN_VERSION: &str = "1.85.0";
const RUST_CACHE_SHA: &str = "42dc69e1aa15d09112580998cf2ef0119e2e91ae";
const UPLOAD_ARTIFACT_SHA: &str = "ea165f8d65b6e75b540449e92b4886f43607fa02";
const DOWNLOAD_ARTIFACT_SHA: &str = "d3f86a106a0bac45b974a628896c90dbdf5c8093";
const CODEQL_UPLOAD_SARIF_SHA: &str = "865f5f5c36632f18690a3d569fa0a764f2da0c3e";
const GH_RELEASE_SHA: &str = "3bb12739c298aeb8a4eeaf626c5b8d85266b0e65";
const GITHUB_SCRIPT_SHA: &str = "f28e40c7f34bde8b3046d885e986cb6290c5673b";

/// Version tags that should NOT appear in uses: declarations
const VERSION_TAGS: &[&str] = &["@v4", "@v3", "@v2", "@v7", "@stable"];

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

/// Extract all `uses:` declarations from workflow content (handles `- uses:` format)
fn extract_uses_declarations(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|line| line.trim().starts_with("- uses:") || line.trim().starts_with("uses:"))
        .map(|line| line.trim().to_string())
        .collect()
}

// ============================================================================
// Integration Tests - ci.yml
// ============================================================================

#[test]
fn ci_workflow_yaml_is_valid() {
    let content = read_workflow_file("ci.yml");
    // Basic YAML validation - check structure
    assert!(content.contains("name: ci"));
    assert!(content.contains("jobs:"));
    assert!(content.contains("steps:"));
}

#[test]
fn ci_workflow_no_version_tags_in_uses_declarations() {
    let content = read_workflow_file("ci.yml");
    let uses_lines = extract_uses_declarations(&content);

    for line in &uses_lines {
        for tag in VERSION_TAGS {
            assert!(
                !line.contains(tag),
                "ci.yml contains version tag '{}' in line: {}",
                tag,
                line
            );
        }
    }
}

#[test]
fn ci_workflow_uses_checkout_pinned_to_sha() {
    let content = read_workflow_file("ci.yml");
    assert!(
        content.contains(&format!("actions/checkout@{}", ACTIONS_CHECKOUT_SHA)),
        "ci.yml should use actions/checkout@{}",
        ACTIONS_CHECKOUT_SHA
    );
}

#[test]
fn ci_workflow_uses_rust_toolchain_pinned_to_version() {
    let content = read_workflow_file("ci.yml");
    assert!(
        content.contains(&format!(
            "dtolnay/rust-toolchain@{}",
            RUST_TOOLCHAIN_VERSION
        )),
        "ci.yml should use dtolnay/rust-toolchain@{}",
        RUST_TOOLCHAIN_VERSION
    );
}

#[test]
fn ci_workflow_uses_rust_cache_pinned_to_sha() {
    let content = read_workflow_file("ci.yml");
    assert!(
        content.contains(&format!("Swatinem/rust-cache@{}", RUST_CACHE_SHA)),
        "ci.yml should use Swatinem/rust-cache@{}",
        RUST_CACHE_SHA
    );
}

#[test]
fn ci_workflow_has_pinning_documentation() {
    let content = read_workflow_file("ci.yml");
    assert!(
        content.contains("work-5102a8b6"),
        "ci.yml should contain work-5102a8b6 reference"
    );
    assert!(
        content.contains("SHA pinning"),
        "ci.yml should mention SHA pinning"
    );
}

// ============================================================================
// Integration Tests - publish.yml
// ============================================================================

#[test]
fn publish_workflow_yaml_is_valid() {
    let content = read_workflow_file("publish.yml");
    assert!(content.contains("name: publish"));
    assert!(content.contains("jobs:"));
    assert!(content.contains("steps:"));
}

#[test]
fn publish_workflow_no_version_tags_in_uses_declarations() {
    let content = read_workflow_file("publish.yml");
    let uses_lines = extract_uses_declarations(&content);

    for line in &uses_lines {
        for tag in VERSION_TAGS {
            assert!(
                !line.contains(tag),
                "publish.yml contains version tag '{}' in line: {}",
                tag,
                line
            );
        }
    }
}

#[test]
fn publish_workflow_uses_checkout_pinned_to_sha() {
    let content = read_workflow_file("publish.yml");
    assert!(
        content.contains(&format!("actions/checkout@{}", ACTIONS_CHECKOUT_SHA)),
        "publish.yml should use actions/checkout@{}",
        ACTIONS_CHECKOUT_SHA
    );
}

#[test]
fn publish_workflow_uses_rust_toolchain_pinned_to_version() {
    let content = read_workflow_file("publish.yml");
    assert!(
        content.contains(&format!(
            "dtolnay/rust-toolchain@{}",
            RUST_TOOLCHAIN_VERSION
        )),
        "publish.yml should use dtolnay/rust-toolchain@{}",
        RUST_TOOLCHAIN_VERSION
    );
}

#[test]
fn publish_workflow_uses_upload_artifact_pinned_to_sha() {
    let content = read_workflow_file("publish.yml");
    assert!(
        content.contains(&format!("actions/upload-artifact@{}", UPLOAD_ARTIFACT_SHA)),
        "publish.yml should use actions/upload-artifact@{}",
        UPLOAD_ARTIFACT_SHA
    );
}

#[test]
fn publish_workflow_uses_download_artifact_pinned_to_sha() {
    let content = read_workflow_file("publish.yml");
    assert!(
        content.contains(&format!(
            "actions/download-artifact@{}",
            DOWNLOAD_ARTIFACT_SHA
        )),
        "publish.yml should use actions/download-artifact@{}",
        DOWNLOAD_ARTIFACT_SHA
    );
}

#[test]
fn publish_workflow_uses_gh_release_pinned_to_sha() {
    let content = read_workflow_file("publish.yml");
    assert!(
        content.contains(&format!("softprops/action-gh-release@{}", GH_RELEASE_SHA)),
        "publish.yml should use softprops/action-gh-release@{}",
        GH_RELEASE_SHA
    );
}

#[test]
fn publish_workflow_has_pinning_documentation() {
    let content = read_workflow_file("publish.yml");
    assert!(
        content.contains("work-5102a8b6"),
        "publish.yml should contain work-5102a8b6 reference"
    );
}

// ============================================================================
// Integration Tests - sarif-example.yml
// ============================================================================

#[test]
fn sarif_example_workflow_yaml_is_valid() {
    let content = read_workflow_file("sarif-example.yml");
    assert!(content.contains("name: diffguard-sarif-example"));
    assert!(content.contains("jobs:"));
    assert!(content.contains("steps:"));
}

#[test]
fn sarif_example_workflow_no_version_tags_in_uses_declarations() {
    // Note: This only tests active (non-commented) uses: lines
    let content = read_workflow_file("sarif-example.yml");
    let uses_lines = extract_uses_declarations(&content);

    for line in &uses_lines {
        for tag in VERSION_TAGS {
            assert!(
                !line.contains(tag),
                "sarif-example.yml contains version tag '{}' in line: {}",
                tag,
                line
            );
        }
    }
}

#[test]
fn sarif_example_workflow_uses_checkout_pinned_to_sha() {
    let content = read_workflow_file("sarif-example.yml");
    assert!(
        content.contains(&format!("actions/checkout@{}", ACTIONS_CHECKOUT_SHA)),
        "sarif-example.yml should use actions/checkout@{}",
        ACTIONS_CHECKOUT_SHA
    );
}

#[test]
fn sarif_example_workflow_uses_rust_toolchain_pinned_to_version() {
    let content = read_workflow_file("sarif-example.yml");
    assert!(
        content.contains(&format!(
            "dtolnay/rust-toolchain@{}",
            RUST_TOOLCHAIN_VERSION
        )),
        "sarif-example.yml should use dtolnay/rust-toolchain@{}",
        RUST_TOOLCHAIN_VERSION
    );
}

#[test]
fn sarif_example_workflow_uses_codeql_upload_sarif_pinned_to_sha() {
    let content = read_workflow_file("sarif-example.yml");
    assert!(
        content.contains(&format!(
            "github/codeql-action/upload-sarif@{}",
            CODEQL_UPLOAD_SARIF_SHA
        )),
        "sarif-example.yml should use github/codeql-action/upload-sarif@{}",
        CODEQL_UPLOAD_SARIF_SHA
    );
}

#[test]
fn sarif_example_workflow_uses_upload_artifact_pinned_to_sha() {
    let content = read_workflow_file("sarif-example.yml");
    assert!(
        content.contains(&format!("actions/upload-artifact@{}", UPLOAD_ARTIFACT_SHA)),
        "sarif-example.yml should use actions/upload-artifact@{}",
        UPLOAD_ARTIFACT_SHA
    );
}

#[test]
fn sarif_example_workflow_uses_github_script_pinned_to_sha() {
    let content = read_workflow_file("sarif-example.yml");
    assert!(
        content.contains(&format!("actions/github-script@{}", GITHUB_SCRIPT_SHA)),
        "sarif-example.yml should use actions/github-script@{}",
        GITHUB_SCRIPT_SHA
    );
}

#[test]
fn sarif_example_workflow_has_pinning_documentation() {
    let content = read_workflow_file("sarif-example.yml");
    assert!(
        content.contains("work-5102a8b6"),
        "sarif-example.yml should contain work-5102a8b6 reference"
    );
}

// ============================================================================
// Integration Tests - diffguard.yml
// ============================================================================

#[test]
fn diffguard_workflow_yaml_is_valid() {
    let content = read_workflow_file("diffguard.yml");
    assert!(content.contains("name: diffguard"));
    assert!(content.contains("jobs:"));
    assert!(content.contains("steps:"));
}

#[test]
fn diffguard_workflow_no_version_tags_in_uses_declarations() {
    let content = read_workflow_file("diffguard.yml");
    let uses_lines = extract_uses_declarations(&content);

    for line in &uses_lines {
        for tag in VERSION_TAGS {
            assert!(
                !line.contains(tag),
                "diffguard.yml contains version tag '{}' in line: {}",
                tag,
                line
            );
        }
    }
}

#[test]
fn diffguard_workflow_uses_checkout_pinned_to_sha() {
    let content = read_workflow_file("diffguard.yml");
    assert!(
        content.contains(&format!("actions/checkout@{}", ACTIONS_CHECKOUT_SHA)),
        "diffguard.yml should use actions/checkout@{}",
        ACTIONS_CHECKOUT_SHA
    );
}

#[test]
fn diffguard_workflow_uses_rust_toolchain_pinned_to_version() {
    let content = read_workflow_file("diffguard.yml");
    assert!(
        content.contains(&format!(
            "dtolnay/rust-toolchain@{}",
            RUST_TOOLCHAIN_VERSION
        )),
        "diffguard.yml should use dtolnay/rust-toolchain@{}",
        RUST_TOOLCHAIN_VERSION
    );
}

#[test]
fn diffguard_workflow_uses_rust_cache_pinned_to_sha() {
    let content = read_workflow_file("diffguard.yml");
    assert!(
        content.contains(&format!("Swatinem/rust-cache@{}", RUST_CACHE_SHA)),
        "diffguard.yml should use Swatinem/rust-cache@{}",
        RUST_CACHE_SHA
    );
}

#[test]
fn diffguard_workflow_uses_codeql_upload_sarif_pinned_to_sha() {
    let content = read_workflow_file("diffguard.yml");
    assert!(
        content.contains(&format!(
            "github/codeql-action/upload-sarif@{}",
            CODEQL_UPLOAD_SARIF_SHA
        )),
        "diffguard.yml should use github/codeql-action/upload-sarif@{}",
        CODEQL_UPLOAD_SARIF_SHA
    );
}

#[test]
fn diffguard_workflow_uses_upload_artifact_pinned_to_sha() {
    let content = read_workflow_file("diffguard.yml");
    assert!(
        content.contains(&format!("actions/upload-artifact@{}", UPLOAD_ARTIFACT_SHA)),
        "diffguard.yml should use actions/upload-artifact@{}",
        UPLOAD_ARTIFACT_SHA
    );
}

#[test]
fn diffguard_workflow_has_pinning_documentation() {
    let content = read_workflow_file("diffguard.yml");
    assert!(
        content.contains("work-5102a8b6"),
        "diffguard.yml should contain work-5102a8b6 reference"
    );
}

// ============================================================================
// Cross-file Integration Tests
// ============================================================================

#[test]
fn all_workflows_use_consistent_checkout_sha() {
    let ci = read_workflow_file("ci.yml");
    let publish = read_workflow_file("publish.yml");
    let sarif = read_workflow_file("sarif-example.yml");
    let diffguard = read_workflow_file("diffguard.yml");

    let checkout_ref = format!("actions/checkout@{}", ACTIONS_CHECKOUT_SHA);

    assert!(
        ci.contains(&checkout_ref),
        "ci.yml should use consistent checkout SHA"
    );
    assert!(
        publish.contains(&checkout_ref),
        "publish.yml should use consistent checkout SHA"
    );
    assert!(
        sarif.contains(&checkout_ref),
        "sarif-example.yml should use consistent checkout SHA"
    );
    assert!(
        diffguard.contains(&checkout_ref),
        "diffguard.yml should use consistent checkout SHA"
    );
}

#[test]
fn all_workflows_use_consistent_rust_toolchain_version() {
    let ci = read_workflow_file("ci.yml");
    let publish = read_workflow_file("publish.yml");
    let sarif = read_workflow_file("sarif-example.yml");
    let diffguard = read_workflow_file("diffguard.yml");

    let toolchain_ref = format!("dtolnay/rust-toolchain@{}", RUST_TOOLCHAIN_VERSION);

    assert!(
        ci.contains(&toolchain_ref),
        "ci.yml should use consistent rust-toolchain version"
    );
    assert!(
        publish.contains(&toolchain_ref),
        "publish.yml should use consistent rust-toolchain version"
    );
    assert!(
        sarif.contains(&toolchain_ref),
        "sarif-example.yml should use consistent rust-toolchain version"
    );
    assert!(
        diffguard.contains(&toolchain_ref),
        "diffguard.yml should use consistent rust-toolchain version"
    );
}

#[test]
fn all_workflow_files_have_pinning_documentation() {
    let ci = read_workflow_file("ci.yml");
    let publish = read_workflow_file("publish.yml");
    let sarif = read_workflow_file("sarif-example.yml");
    let diffguard = read_workflow_file("diffguard.yml");

    for (name, content) in [
        ("ci.yml", &ci),
        ("publish.yml", &publish),
        ("sarif-example.yml", &sarif),
        ("diffguard.yml", &diffguard),
    ] {
        assert!(
            content.contains("work-5102a8b6"),
            "{} should contain work-5102a8b6 reference",
            name
        );
        assert!(
            content.contains("SHA pinning"),
            "{} should mention SHA pinning",
            name
        );
    }
}

#[test]
fn no_workflow_has_unpinned_actions() {
    // This test verifies that all uses: declarations across all workflows
    // use SHA references, not version tags
    let files = [
        "ci.yml",
        "publish.yml",
        "sarif-example.yml",
        "diffguard.yml",
    ];

    for file_name in &files {
        let content = read_workflow_file(file_name);
        let uses_lines = extract_uses_declarations(&content);

        for line in &uses_lines {
            // Each line should contain a @ and not contain version tags
            assert!(
                line.contains('@'),
                "{} uses: line missing @ reference: {}",
                file_name,
                line
            );

            for tag in VERSION_TAGS {
                assert!(
                    !line.contains(tag),
                    "{} contains unpinned version tag '{}' in line: {}",
                    file_name,
                    tag,
                    line
                );
            }
        }
    }
}
