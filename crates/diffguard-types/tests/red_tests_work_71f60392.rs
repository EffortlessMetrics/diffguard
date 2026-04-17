//! Red tests for work-71f60392: `ConfigFile::built_in()` has `#[must_use]` but no `# Panics` docs
//!
//! These tests verify that `ConfigFile::built_in()` documents its panic conditions,
//! as required by Rust API Guidelines C409:
//!
//! > If a function has the `#[must_use]` attribute, it MUST have a `# Panics`
//! > section in its doc comment explaining when it panics.
//!
//! **Before fix**: `ConfigFile::built_in()` at line 244-252 has `#[must_use]` but
//!                the doc comment lacks a `# Panics` section
//! **After fix**:  The doc comment above `pub fn built_in()` should include a
//!                `# Panics` section explaining that it panics if the embedded
//!                JSON is malformed (e.g., "Panics if `built_in.json` is malformed")

/// Collect doc comment lines above a function by searching backwards from its line index.
///
/// Returns the doc lines in correct order (top to bottom).
fn collect_doc_lines_above<'a>(lines: &'a [&'a str], fn_line_abs: usize) -> Vec<&'a str> {
    let mut doc_lines: Vec<&str> = Vec::new();
    let mut check_idx = fn_line_abs;

    while check_idx > 0 {
        check_idx -= 1;
        let line = lines[check_idx].trim();

        // Check for empty line that separates doc from code
        if line.is_empty() && !doc_lines.is_empty() && check_idx > 0 {
            let prev_line = lines[check_idx - 1].trim();
            if !prev_line.is_empty() && !prev_line.starts_with("///") {
                // Empty line separates doc from code
                break;
            }
        }

        if line.starts_with("///") {
            doc_lines.push(line);
        } else if line.starts_with("//!") {
            // Module-level doc, skip rest of search
            break;
        } else if !line.is_empty() && !line.starts_with("#[") {
            // Found non-doc, non-attribute content - we're past the doc
            break;
        }
    }

    doc_lines.reverse();
    doc_lines
}

/// Test that `ConfigFile::built_in()` doc comment contains a `# Panics` section.
///
/// Rust API Guidelines C409 requires that any function with `#[must_use]`
/// MUST have a `# Panics` section explaining when it panics.
///
/// This test will FAIL before the fix (when the Panics section is missing) and
/// PASS after code-builder adds the appropriate `# Panics` documentation.
#[test]
fn config_file_built_in_doc_comment_has_panics_section() {
    // Read the source file at compile time via include_str!
    let source = include_str!("../src/lib.rs");

    // Split into lines and find the doc comment for `pub fn built_in()`
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
    let doc_lines = collect_doc_lines_above(&lines, fn_line_abs);

    // Join all doc lines into a single string for analysis
    let doc_text = doc_lines.join("\n");

    // Verify that the doc comment contains "# Panics"
    assert!(
        doc_text.contains("# Panics"),
        "\
ConfigFile::built_in() doc comment is MISSING '# Panics' section.

Rust API Guidelines C409 requires that any function with `#[must_use]`
MUST have a '# Panics' section explaining when it panics.

Current doc comment for built_in():
---
{}

Expected: The doc comment should contain a '# Panics' section explaining
that built_in() panics if the embedded 'built_in.json' is malformed.

The fix: Add a '# Panics' section to the doc comment above 'pub fn built_in()'
in 'crates/diffguard-types/src/lib.rs', e.g.:
    /// # Panics
    ///
    /// Panics if `rules/built_in.json` is malformed or cannot be parsed
    /// as valid ConfigFile JSON.
",
        doc_text
    );
}

/// Test that `ConfigFile::built_in()` doc comment's `# Panics` section
/// mentions that it can panic on malformed JSON.
///
/// The `.expect()` call on line 251 can panic if `serde_json::from_str`
/// fails. The Panics section should document this condition.
#[test]
fn config_file_built_in_panics_section_mentions_json_parsing() {
    // Read the source file at compile time via include_str!
    let source = include_str!("../src/lib.rs");

    // Split into lines and find the doc comment for `pub fn built_in()`
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
    let doc_lines = collect_doc_lines_above(&lines, fn_line_abs);

    // Join all doc lines
    let doc_text = doc_lines.join("\n");

    // Extract the content after "# Panics"
    let panics_start = doc_text
        .find("# Panics")
        .expect("Should have found '# Panics' section (previous test should have caught this)");

    let panics_section = &doc_text[panics_start..];

    // The Panics section should mention JSON, parsing, or the expect message
    let mentions_json_parsing = panics_section.contains("JSON")
        || panics_section.contains("json")
        || panics_section.contains("parse")
        || panics_section.contains("malformed")
        || panics_section.contains("invalid");

    assert!(
        mentions_json_parsing,
        "\
ConfigFile::built_in() '# Panics' section does NOT mention JSON parsing.

The '# Panics' section should explain that the function panics when
the embedded 'built_in.json' is malformed and cannot be parsed.

Current '# Panics' section:
---
{}

Expected: The Panics section should mention that it panics if the JSON
is malformed, e.g., 'Panics if built_in.json cannot be parsed as JSON'.

The fix: Update the '# Panics' section in the doc comment above
'pub fn built_in()' to explicitly mention JSON parsing failure.
",
        panics_section
    );
}

/// Test that `ConfigFile::built_in()` has `#[must_use]` AND `# Panics` together.
///
/// Per Rust API Guidelines C409: if a function has `#[must_use]`,
/// it MUST have `# Panics` to document any panic conditions.
/// Both attributes work together to warn users about discarding
/// important values that could also fail.
#[test]
fn config_file_built_in_has_must_use_and_panics_together() {
    let source = include_str!("../src/lib.rs");
    let lines: Vec<&str> = source.lines().collect();

    // Find the impl block and function
    let impl_block_start = lines
        .iter()
        .position(|l| l.contains("impl ConfigFile {"))
        .expect("impl ConfigFile { not found in source");

    let fn_line_idx = lines[impl_block_start..]
        .iter()
        .position(|l| l.contains("pub fn built_in()"))
        .expect("pub fn built_in() not found in impl ConfigFile block");

    let fn_line_abs = impl_block_start + fn_line_idx;

    // Step 1: Verify #[must_use] exists above the function
    let mut check_idx = fn_line_abs;
    let mut has_must_use = false;

    while check_idx > impl_block_start {
        check_idx -= 1;
        let line = lines[check_idx].trim();
        if line == "#[must_use]" {
            has_must_use = true;
            break;
        }
        if !line.is_empty() && !line.starts_with("///") && !line.starts_with("#[") {
            break;
        }
    }

    assert!(
        has_must_use,
        "ConfigFile::built_in() is missing #[must_use] attribute.\n\n\
         Per Rust API Guidelines C409, functions with #[must_use] MUST have # Panics."
    );

    // Step 2: Collect doc comment lines and verify # Panics exists
    let doc_lines = collect_doc_lines_above(&lines, fn_line_abs);
    let doc_text = doc_lines.join("\n");

    let has_panics = doc_text.contains("# Panics");

    assert!(
        has_panics,
        "ConfigFile::built_in() has #[must_use] but is MISSING '# Panics' section.\n\n\
         Per Rust API Guidelines C409:\n         'If a function has the #[must_use] attribute, it MUST have a # Panics\n          section in its doc comment explaining when it panics.'\n\n\
         Current doc comment:\n         ---\n         {}\n         ---\n\n\
         The fix: Add a '# Panics' section to the doc comment above\n         'pub fn built_in()' explaining when it panics (e.g., when\n         the embedded JSON is malformed).",
        doc_text
    );
}
