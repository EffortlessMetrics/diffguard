//! Tests verifying that `render_gitlab_quality_json` has proper error documentation.
//!
//! These tests validate the `clippy::missing_errors_doc` lint compliance for
//! the `render_gitlab_quality_json` function in `gitlab_quality.rs:86`.

use std::process::Command;

/// Test that `render_gitlab_quality_json` has an `# Errors` section in its doc comment.
///
/// This test verifies that the function's doc comment includes proper error
/// documentation to satisfy the `clippy::missing_errors_doc` lint.
///
/// The function signature is:
/// ```ignore
/// pub fn render_gitlab_quality_json(receipt: &CheckReceipt) -> Result<String, serde_json::Error>
/// ```
///
/// The doc comment must include an `# Errors` section documenting `serde_json::Error`.
#[test]
fn test_render_gitlab_quality_json_has_errors_section() {
    // Run clippy with the missing_errors_doc lint enabled
    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "diffguard-core",
            "--",
            "-W",
            "clippy::missing_errors_doc",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("cargo clippy should execute");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}{}", stdout, stderr);

    // Check that there are NO warnings about missing_errors_doc for gitlab_quality.rs:86
    // The warning format is:
    //   warning: docs for function returning `Result` missing `# Errors` section
    //     --> crates/diffguard-core/src/gitlab_quality.rs:86:1
    // The "gitlab_quality.rs:86" and "missing_errors_doc" may appear on different lines
    // but they're part of the same warning block.
    let has_missing_errors_warning = combined.contains("gitlab_quality.rs:86")
        && (combined.contains("missing_errors_doc")
            || combined.contains("missing `# Errors` section"));

    // The test passes when there is NO warning (meaning the Errors section exists)
    // The test fails when there IS a warning (meaning the Errors section is missing)
    assert!(
        !has_missing_errors_warning,
        "render_gitlab_quality_json at gitlab_quality.rs:86 should have an `# Errors` section \
         in its doc comment to satisfy clippy::missing_errors_doc. \
         The function returns Result<String, serde_json::Error> and must document this error type. \
         Expected the doc comment to include:\n    /// # Errors\n    ///\n    /// Returns [`serde_json::Error`] if serialization fails.\n\n\
         Clippy output:\n{}",
        combined
    );
}

/// Test that the `# Errors` section in `render_gitlab_quality_json` documents `serde_json::Error`.
///
/// This is a secondary verification that the Errors section exists AND properly
/// documents the error type.
#[test]
fn test_render_gitlab_quality_json_errors_section_documents_serde_json_error() {
    use std::fs;

    let source_path = "/home/hermes/repos/diffguard/crates/diffguard-core/src/gitlab_quality.rs";
    let source = fs::read_to_string(source_path).expect("gitlab_quality.rs should be readable");

    // Find the function and its doc comment
    let lines: Vec<&str> = source.lines().collect();

    // Look for the function starting at line 85 (1-indexed)
    // Skip to line 84 (0-indexed) to avoid breaking on module-level doc comments
    let mut in_doc_comment = false;
    let mut found_errors_section = false;
    let mut found_serde_json_error = false;

    for line in lines.iter().skip(84) {
        let trimmed = line.trim();

        // Doc comment starts
        if trimmed.starts_with("///") || trimmed.starts_with("//!") {
            in_doc_comment = true;
            if trimmed.contains("# Errors") {
                found_errors_section = true;
            }
            if trimmed.contains("serde_json::Error") || trimmed.contains("serde_json.Error") {
                found_serde_json_error = true;
            }
        }
        // Non-doc line while in doc comment (blank lines are ok)
        else if in_doc_comment && !trimmed.is_empty() && !trimmed.starts_with("///") {
            // End of doc comment
            break;
        }
    }

    // First check: the function must have an Errors section
    assert!(
        found_errors_section,
        "render_gitlab_quality_json should have an `# Errors` section in its doc comment \
         (found at gitlab_quality.rs:86). The section should document the serde_json::Error \
         that is returned when JSON serialization fails."
    );

    // Second check: the Errors section should mention serde_json::Error
    assert!(
        found_serde_json_error,
        "The `# Errors` section for render_gitlab_quality_json should document `serde_json::Error` \
         as the error type returned when serialization fails."
    );
}
