//! Tests verifying that `render_gitlab_quality_json` has proper error documentation.
//!
//! These tests validate the `clippy::missing_errors_doc` lint compliance for
//! the `render_gitlab_quality_json` function in `gitlab_quality.rs:86`.

use std::path::Path;
use std::process::Command;

/// Test that `render_gitlab_quality_json` has an `# Errors` section in its doc comment.
#[test]
fn test_render_gitlab_quality_json_has_errors_section() {
    let output = Command::new("cargo")
        .args(["clippy", "-p", "diffguard-core", "--", "-W", "clippy::missing_errors_doc"])
        .current_dir(std::env::current_dir().unwrap())
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    let has_missing_errors_warning = combined.contains("gitlab_quality.rs:86")
        && (combined.contains("missing_errors_doc")
            || combined.contains("missing `# Errors` section"));

    assert!(
        !has_missing_errors_warning,
        "render_gitlab_quality_json at gitlab_quality.rs:86 should have an `# Errors` section"
    );
}

/// Test that the `# Errors` section documents `serde_json::Error`.
#[test]
fn test_render_gitlab_quality_json_errors_section_documents_serde_json_error() {
    use std::fs;

    let source_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gitlab_quality.rs");
    let source = fs::read_to_string(&source_path).expect("gitlab_quality.rs should be readable");

    let lines: Vec<&str> = source.lines().collect();
    let mut in_doc_comment = false;
    let mut found_errors_section = false;
    let mut found_serde_json_error = false;

    for line in lines.iter().skip(84) {
        let trimmed = line.trim();
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            in_doc_comment = true;
            if trimmed.contains("# Errors") {
                found_errors_section = true;
            }
            if trimmed.contains("serde_json::Error") || trimmed.contains("serde_json.Error") {
                found_serde_json_error = true;
            }
        } else if in_doc_comment && !trimmed.is_empty() && !trimmed.starts_with("///") {
            break;
        }
    }

    assert!(found_errors_section, "Should have an `# Errors` section");
    assert!(found_serde_json_error, "Should document serde_json::Error");
}
