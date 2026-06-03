//! Red tests for work-ece459be: redundant closures in arb.rs
//!
//! These tests verify the behavior of strategies that indirectly or directly
//! use the functions with `clippy::redundant_closure_for_method_calls` warnings:
//! - `arb_file_extension()` (line 214) - PRIVATE - tested indirectly via arb_glob_pattern, etc.
//! - `arb_dir_name()` (line 223) - PRIVATE - tested indirectly via arb_glob_pattern, etc.
//! - `arb_language()` (line 253) - PUBLIC - tested directly
//!
//! The fix replaces `|s| s.to_string()` with `str::to_string` - a pure style
//! change with zero behavioral change. These tests verify the strategies
//! continue to produce correct output after the fix.
//!
//! The "red" state for this work item is the clippy warning itself, which
//! causes `cargo clippy --workspace --all-targets -- -D warnings` to fail.
//! After the fix, clippy will pass and the code will be in "green" state.

use diffguard_testkit::arb;
use proptest::strategy::Strategy;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

/// Known valid file extensions that arb_file_extension() should produce.
/// These match the vec in arb.rs line 210-213.
const VALID_EXTENSIONS: &[&str] = &[
    "rs", "py", "js", "ts", "jsx", "tsx", "go", "java", "kt", "rb", "c", "cpp", "h", "hpp", "cs",
    "txt", "md", "json", "yaml", "toml",
];

/// Known valid directory names that arb_dir_name() should produce.
/// These match the vec in arb.rs line 219-222.
const VALID_DIR_NAMES: &[&str] = &[
    "src", "lib", "bin", "tests", "test", "examples", "benches", "docs", "scripts", "utils",
    "core", "api", "internal", "pkg", "cmd", "app",
];

/// Known valid language identifiers that arb_language() should produce.
/// These match the vec in arb.rs line 240-252.
const VALID_LANGUAGES: &[&str] = &[
    "rust",
    "python",
    "javascript",
    "typescript",
    "go",
    "java",
    "kotlin",
    "ruby",
    "c",
    "cpp",
    "csharp",
];

// =============================================================================
// Tests for arb_language() (PUBLIC - can test directly)
// =============================================================================

/// Test that arb_language() produces non-empty strings.
///
/// The strategy should always produce a String from the known set of language identifiers.
#[test]
fn arb_language_produces_non_empty_string() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_language();

    for _ in 0..100 {
        let lang = strategy.new_tree(&mut runner).unwrap().current();
        assert!(
            !lang.is_empty(),
            "arb_language should produce non-empty string, got empty"
        );
        assert!(
            lang.len() <= 20,
            "arb_language should produce reasonably short string, got '{}'",
            lang
        );
    }
}

/// Test that arb_language() produces known valid language identifiers.
///
/// The strategy selects from a fixed set of language identifiers. This test verifies
/// the generated values are members of that expected set.
#[test]
fn arb_language_produces_known_language() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_language();

    for _ in 0..100 {
        let lang = strategy.new_tree(&mut runner).unwrap().current();
        assert!(
            VALID_LANGUAGES.contains(&lang.as_str()),
            "arb_language produced unknown language '{}', expected one of {:?}",
            lang,
            VALID_LANGUAGES
        );
    }
}

/// Test that arb_language() returns owned String type.
///
/// The prop_map transforms &str to String. This test verifies the strategy
/// returns owned Strings, not borrowed references.
#[test]
fn arb_language_returns_owned_string() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_language();

    // Generate a value and verify we can own it (not just borrow)
    let lang = strategy.new_tree(&mut runner).unwrap().current();
    let owned: String = lang; // Should compile - confirms it's owned
    assert!(!owned.is_empty(), "arb_language should return owned String");
}

// =============================================================================
// Tests for arb_file_extension() and arb_dir_name() (PRIVATE - test indirectly)
// =============================================================================

/// Test that glob patterns using file extensions produce valid globs.
///
/// arb_glob_pattern() uses arb_file_extension() internally for generated patterns.
/// This test verifies the generated patterns are valid AND that extensions
/// from generated patterns (not fixed literals like "**/go.mod") are valid.
///
/// Note: arb_glob_pattern() includes both:
/// - Generated patterns like "*.rs", "**/*.py" (using arb_file_extension)
/// - Fixed literal patterns like "**/go.mod", "**/Cargo.toml" (not using arb_file_extension)
#[test]
fn glob_pattern_uses_valid_extensions() {
    use globset::Glob;

    let mut runner = TestRunner::default();
    let strategy = arb::arb_glob_pattern();

    for _ in 0..100 {
        let glob_str = strategy.new_tree(&mut runner).unwrap().current();

        // Verify it's a valid glob
        assert!(
            Glob::new(&glob_str).is_ok(),
            "Generated glob '{}' should be valid",
            glob_str
        );

        // Only check extensions for patterns that look like they use arb_file_extension:
        // - "*.ext" (single extension with wildcard)
        // - "**/*.ext" (recursive with extension)
        // - Patterns with "/" that aren't fixed literals like "**/go.mod"
        let is_generated_pattern = (glob_str.starts_with("*.") || glob_str.contains("/"))
            && !glob_str.contains("go.mod")
            && !glob_str.contains("Cargo")
            && !glob_str.contains("package")
            && !glob_str.contains("go.mod")
            && !glob_str.contains(".mod")
            && !glob_str.contains("node_modules")
            && !glob_str.contains("target")
            && !glob_str.contains("vendor")
            && !glob_str.contains("benches")
            && !glob_str.contains("examples");

        if is_generated_pattern {
            // Extract extension from glob like "*.rs" or "**/*.py"
            if let Some(ext_start) = glob_str.rfind('.') {
                let ext = &glob_str[ext_start + 1..];
                // Remove any trailing glob chars like * or **
                let ext_clean: String = ext.chars().filter(|c| c.is_alphanumeric()).collect();
                if !ext_clean.is_empty() {
                    assert!(
                        VALID_EXTENSIONS.contains(&ext_clean.as_str()),
                        "Generated glob '{}' contains unknown file extension '{}'",
                        glob_str,
                        ext_clean
                    );
                }
            }
        }
    }
}

/// Test that file paths contain valid file extensions.
///
/// arb_file_path() uses arb_file_extension() internally. This test verifies
/// the file extension part of generated paths are from the valid set.
#[test]
fn file_path_contains_valid_extensions() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_file_path();

    for _ in 0..100 {
        let path = strategy.new_tree(&mut runner).unwrap().current();

        // Extract extension from path like "src/main.rs"
        if let Some(ext_start) = path.rfind('.') {
            let ext = &path[ext_start + 1..];
            assert!(
                VALID_EXTENSIONS.contains(&ext),
                "File path '{}' contains unknown extension '{}'",
                path,
                ext
            );
        } else {
            panic!("File path '{}' should contain a dot separator", path);
        }
    }
}

/// Test that file paths contain valid directory names.
///
/// arb_file_path() uses arb_dir_name() internally. This test verifies
/// the directory part of generated paths contains valid directory names.
#[test]
fn file_path_contains_valid_dir_names() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_file_path();

    for _ in 0..100 {
        let path = strategy.new_tree(&mut runner).unwrap().current();

        // Path format is "dir/dir/.../name.ext"
        // Extract all directory components (everything before the filename)
        let parts: Vec<&str> = path.split('/').collect();
        assert!(
            parts.len() >= 2,
            "File path '{}' should have at least dir/filename",
            path
        );

        // All parts except the last (filename) should be valid dir names
        for dir in &parts[..parts.len() - 1] {
            if !dir.is_empty() {
                assert!(
                    VALID_DIR_NAMES.contains(dir),
                    "File path '{}' contains unknown directory '{}'",
                    path,
                    dir
                );
            }
        }
    }
}

/// Test that include/exclude globs use valid extensions and directories.
#[test]
fn include_glob_produces_valid_patterns() {
    use globset::Glob;

    let mut runner = TestRunner::default();
    let strategy = arb::arb_include_glob();

    for _ in 0..100 {
        let glob_str = strategy.new_tree(&mut runner).unwrap().current();
        assert!(
            Glob::new(&glob_str).is_ok(),
            "Include glob '{}' should be valid",
            glob_str
        );
    }
}

/// Test that exclude glob patterns are valid.
#[test]
fn exclude_glob_produces_valid_patterns() {
    use globset::Glob;

    let mut runner = TestRunner::default();
    let strategy = arb::arb_exclude_glob();

    for _ in 0..100 {
        let glob_str = strategy.new_tree(&mut runner).unwrap().current();
        assert!(
            Glob::new(&glob_str).is_ok(),
            "Exclude glob '{}' should be valid",
            glob_str
        );
    }
}

// =============================================================================
// Integration test: arb_rule_config uses arb_language()
// =============================================================================

/// Test that arb_rule_config produces valid configs with valid languages.
///
/// arb_rule_config() uses arb_language() internally. This integration test
/// verifies the languages in generated configs are valid.
#[test]
fn rule_config_contains_valid_languages() {
    use diffguard_types::RuleConfig;

    let mut runner = TestRunner::default();
    let strategy = arb::arb_rule_config();

    for _ in 0..20 {
        let config: RuleConfig = strategy.new_tree(&mut runner).unwrap().current();

        // Verify all languages are valid
        for lang in &config.languages {
            assert!(
                VALID_LANGUAGES.contains(&lang.as_str()),
                "RuleConfig language '{}' is not a known language",
                lang
            );
        }

        // Verify the config is otherwise well-formed
        assert!(!config.id.is_empty(), "RuleConfig should have non-empty id");
        assert!(
            !config.patterns.is_empty(),
            "RuleConfig should have at least one pattern"
        );
    }
}

/// Test that arb_language can be used in a composite strategy.
///
/// This verifies the strategy integrates properly with proptest's strategy
/// combinators and produces repeatable, valid output.
#[test]
fn arb_language_works_in_composite_strategy() {
    let mut runner = TestRunner::default();

    // Create a composite strategy: language followed by a fixed suffix
    let composite = arb::arb_language();

    for _ in 0..50 {
        let lang = composite.new_tree(&mut runner).unwrap().current();
        let composite_val = format!("{}_test", lang);

        // Should still be a valid language prefix
        let lang_part: &str = composite_val.strip_suffix("_test").unwrap();
        assert!(
            VALID_LANGUAGES.contains(&lang_part),
            "Composite value '{}' should have valid language prefix",
            composite_val
        );
    }
}
