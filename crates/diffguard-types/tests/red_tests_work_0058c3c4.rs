//! Red tests for work-0058c3c4: Add `#[must_use]` to `ConfigFile::built_in()`
//!
//! These tests verify that `ConfigFile::built_in()` has the `#[must_use]` attribute,
//! consistent with the existing pattern on `Severity::as_str`, `Scope::as_str`, and
//! `FailOn::as_str` methods.
//!
//! **Before fix**: `ConfigFile::built_in()` at line 248 lacks `#[must_use]`
//! **After fix**: `#[must_use]` present on line directly above `pub fn built_in()`

/// Test that `ConfigFile::built_in()` has `#[must_use]` attribute directly above it.
///
/// The `#[must_use]` attribute signals that the return value carries semantic
/// significance and should not be silently discarded. This test verifies the
/// attribute is present by checking the line immediately preceding `pub fn built_in()`.
///
/// This test will FAIL before the fix (when the attribute is missing) and
/// PASS after code-builder adds `#[must_use]` above `pub fn built_in()`.
#[test]
fn config_file_built_in_has_must_use_attribute() {
    // Read the source file at compile time via include_str!
    let source = include_str!("../src/lib.rs");

    // Split into lines and find the line containing "pub fn built_in()"
    let lines: Vec<&str> = source.lines().collect();

    // Find the line index of "pub fn built_in()" within the ConfigFile impl block
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

    // The line immediately before should be #[must_use] (allowing for blank lines)
    // We search backwards from fn_line_idx to find the first non-empty line
    let mut check_idx = fn_line_abs - 1;
    while check_idx > impl_block_start {
        let line = lines[check_idx].trim();
        if line.is_empty() {
            check_idx -= 1;
            continue;
        }
        if line == "#[must_use]" {
            // Found it! The attribute is on the line directly above (modulo blank lines)
            return;
        }
        // Found something other than #[must_use] - fail
        break;
    }

    // If we get here, #[must_use] was not found on the line above pub fn built_in()
    panic!(
        "\
#[must_use] attribute is MISSING above 'pub fn built_in()'.

Expected: the line(s) directly above 'pub fn built_in()' should contain '#[must_use]'

The fix: add '#[must_use]' on the line directly above 'pub fn built_in()' in \
'crates/diffguard-types/src/lib.rs', matching the pattern used by \
Severity::as_str (line 52), Scope::as_str (line 72), and FailOn::as_str (line 92)."
    );
}

/// Test that there are exactly 4 `#[must_use]` attributes in lib.rs.
///
/// Three are already present (lines 52, 72, 92 for as_str methods).
/// After the fix, a fourth should appear above ConfigFile::built_in().
#[test]
fn must_use_attribute_count_is_four() {
    let source = include_str!("../src/lib.rs");

    let count = source.matches("#[must_use]").count();

    assert_eq!(
        count, 4,
        "Expected exactly 4 #[must_use] attributes in lib.rs \
         (lines 52, 72, 92 for as_str methods + line 248 for built_in()), \
         but found {}. \
         After adding #[must_use] above ConfigFile::built_in(), this count \
         should become 4.",
        count
    );
}

/// Test that `ConfigFile::built_in()` return value is semantically meaningful.
///
/// This test documents the expected behavior: the built_in() method returns
/// a complete ConfigFile with 36 rules loaded from embedded JSON.
/// Discarding this value silently would be a bug, which is why
/// `#[must_use]` is needed.
#[test]
fn built_in_returns_config_with_36_rules() {
    use diffguard_types::ConfigFile;

    // This line exercises ConfigFile::built_in() - the return value IS used
    // (assigned to cfg), so even with #[must_use] there is no warning.
    let cfg = ConfigFile::built_in();

    assert_eq!(
        cfg.rule.len(),
        36,
        "ConfigFile::built_in() should return exactly 36 rules, got {}",
        cfg.rule.len()
    );
}
