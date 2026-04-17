//! Red tests for work-6d427bb9: Add `# Panics` documentation to `ConfigFile::built_in()`
//!
//! These tests verify that `ConfigFile::built_in()` has proper `# Panics` documentation
//! in its doc comment, describing when the function can panic.
//!
//! The function can panic via `.expect()` on line 251 if:
//! - `rules/built_in.json` is not valid UTF-8
//! - `rules/built_in.json` does not parse as valid JSON
//! - The parsed JSON does not match the `ConfigFile` structure
//!
//! **Before fix**: Doc comment lacks `# Panics` section
//! **After fix**: Doc comment includes `# Panics` section describing when it panics

/// Test that `ConfigFile::built_in()` doc comment contains a `# Panics` section.
///
/// Rust's convention for documenting panics is the `# Panics` section in the doc comment.
/// This test verifies the section exists by checking for "# Panics" in the doc comment
/// lines immediately preceding `pub fn built_in()`.
///
/// This test will FAIL before the fix (when `# Panics` is missing) and
/// PASS after code-builder adds `# Panics` documentation to the doc comment.
#[test]
fn config_file_built_in_has_panics_section_in_doc_comment() {
    // Read the source file at compile time via include_str!
    let source = include_str!("../src/lib.rs");

    // Split into lines
    let lines: Vec<&str> = source.lines().collect();

    // Find the line containing "pub fn built_in()"
    let impl_block_start = lines
        .iter()
        .position(|l| l.contains("impl ConfigFile {"))
        .expect("impl ConfigFile { not found in source");

    let fn_line_idx = lines[impl_block_start..]
        .iter()
        .position(|l| l.contains("pub fn built_in()"))
        .expect("pub fn built_in() not found in impl ConfigFile block");

    // Convert to absolute index
    let fn_line_abs = impl_block_start + fn_line_idx;

    // Collect all doc comment lines above this function (lines starting with "///")
    // These should be the doc comment for built_in()
    let mut doc_lines: Vec<&str> = Vec::new();
    for i in (0..fn_line_abs).rev() {
        let line = lines[i].trim_start();
        if line.starts_with("///") {
            doc_lines.push(line);
        } else if line.starts_with("#[must_use]") || line.is_empty() {
            // Skip attribute and blank lines within doc comment block
            continue;
        } else {
            // Found non-doc-comment line, stop
            break;
        }
    }

    // Reverse to get them in correct order (top to bottom)
    doc_lines.reverse();

    // Join all doc lines to search for "# Panics"
    let doc_text = doc_lines.join("\n");

    assert!(
        doc_text.contains("# Panics"),
        "\
Doc comment for 'ConfigFile::built_in()' is missing '# Panics' section.

Expected: The doc comment should contain a '# Panics' section describing when the function panics.

The function panics via .expect() on line 251 if:
  - rules/built_in.json is not valid UTF-8
  - rules/built_in.json does not parse as valid JSON
  - The parsed JSON does not match the ConfigFile structure

Current doc comment lines found:
{}

ACTUAL DOC COMMENT:
{}

The fix: Add a '# Panics' section to the doc comment above 'pub fn built_in()'.
Example:
    /// # Panics
    ///
    /// Panics if `rules/built_in.json` is not valid UTF-8, does not parse as valid JSON,
    /// or does not match the `ConfigFile` structure.
",
        doc_lines.len(),
        doc_text
    );
}

/// Test that the `# Panics` section in the doc comment mentions JSON parsing.
///
/// The panics happen specifically because of the `.expect()` call on the `serde_json::from_str`
/// result. The documentation should mention this.
#[test]
fn config_file_built_in_panics_section_mentions_json_parsing() {
    // Read the source file at compile time via include_str!
    let source = include_str!("../src/lib.rs");

    // Split into lines
    let lines: Vec<&str> = source.lines().collect();

    // Find the line containing "pub fn built_in()"
    let impl_block_start = lines
        .iter()
        .position(|l| l.contains("impl ConfigFile {"))
        .expect("impl ConfigFile { not found in source");

    let fn_line_idx = lines[impl_block_start..]
        .iter()
        .position(|l| l.contains("pub fn built_in()"))
        .expect("pub fn built_in() not found in impl ConfigFile block");

    // Convert to absolute index
    let fn_line_abs = impl_block_start + fn_line_idx;

    // Collect all doc comment lines above this function
    let mut doc_lines: Vec<&str> = Vec::new();
    for i in (0..fn_line_abs).rev() {
        let line = lines[i].trim_start();
        if line.starts_with("///") {
            doc_lines.push(line);
        } else if line.starts_with("#[must_use]") || line.is_empty() {
            continue;
        } else {
            break;
        }
    }

    doc_lines.reverse();
    let doc_text = doc_lines.join("\n");

    // First check that # Panics exists
    if !doc_text.contains("# Panics") {
        panic!(
            "Doc comment is missing '# Panics' section entirely.\n\n\
            The fix: Add a '# Panics' section to the doc comment above 'pub fn built_in()'."
        );
    }

    // Now check that it mentions JSON parsing
    let has_json_mention =
        doc_text.to_lowercase().contains("json") || doc_text.to_lowercase().contains("pars");

    assert!(
        has_json_mention,
        "\
'# Panics' section is present but does not mention JSON parsing.

The function panics because of '.expect()' on serde_json::from_str() result.
The '# Panics' section should mention that it panics when JSON is invalid or unparseable.

Current doc comment:
{}

The fix: Update the '# Panics' section to mention JSON parsing.
Example:
    /// # Panics
    ///
    /// Panics if `rules/built_in.json` is not valid UTF-8, does not parse as valid JSON,
    /// or does not match the `ConfigFile` structure.
",
        doc_text
    );
}

/// Test that the doc comment for `built_in()` is non-trivial (has real documentation).
///
/// The function has important behavior (loads embedded JSON) and the doc comment
/// should reflect this with at least a few lines of documentation plus the # Panics section.
#[test]
fn config_file_built_in_doc_comment_is_substantial() {
    let source = include_str!("../src/lib.rs");
    let lines: Vec<&str> = source.lines().collect();

    let impl_block_start = lines
        .iter()
        .position(|l| l.contains("impl ConfigFile {"))
        .expect("impl ConfigFile { not found in source");

    let fn_line_idx = lines[impl_block_start..]
        .iter()
        .position(|l| l.contains("pub fn built_in()"))
        .expect("pub fn built_in() not found in impl ConfigFile block");

    let fn_line_abs = impl_block_start + fn_line_idx;

    // Count doc comment lines (///)
    let mut doc_line_count = 0;
    for i in (0..fn_line_abs).rev() {
        let line = lines[i].trim_start();
        if line.starts_with("///") {
            doc_line_count += 1;
        } else if line.starts_with("#[must_use]") || line.is_empty() {
            continue;
        } else {
            break;
        }
    }

    // A substantial doc comment should have at least:
    // - 3 lines for the main description (title + body)
    // - 2 lines for # Panics header + at least one description line
    // Total: at least 5 lines
    assert!(
        doc_line_count >= 5,
        "\
Doc comment for 'ConfigFile::built_in()' is too short (only {} lines).

A complete doc comment should have:
  - Title line: 'Returns the built-in configuration with default rules.'
  - Body: Description of how rules are loaded
  - # Panics section: Describes when the function panics

Expected at least 5 doc comment lines, got {}.

Current doc comment lines:
{}
",
        doc_line_count,
        doc_line_count,
        "TODO: list actual lines"
    );
}
