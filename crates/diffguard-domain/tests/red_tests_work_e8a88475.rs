//! Red tests for work-e8a88475: #[must_use] on preprocess.rs factory/constructor methods
//!
//! These tests verify that `#[must_use]` attribute is present on 6 functions in
//! `crates/diffguard-domain/src/preprocess.rs` that return `Self` values representing
//! configuration or state that must not be silently dropped.
//!
//! The target functions are:
//! 1. PreprocessOptions::none() - factory method
//! 2. PreprocessOptions::comments_only() - factory method
//! 3. PreprocessOptions::strings_only() - factory method
//! 4. PreprocessOptions::comments_and_strings() - factory method
//! 5. Preprocessor::new(opts: PreprocessOptions) -> Self - constructor
//! 6. Preprocessor::with_language(opts: PreprocessOptions, lang: Language) -> Self - constructor
//!
//! ## How these tests work
//! These tests use `include_str!` to read the source file and verify that
//! `#[must_use]` appears immediately before each target function declaration.
//! This is a compile-time check that ensures the attribute is present.
//!
//! ## Expected behavior
//! - BEFORE fix: Tests FAIL because #[must_use] is not present on those functions
//! - AFTER fix: Tests PASS because #[must_use] is correctly placed



/// Load the preprocess.rs source file for inspection.
/// We use include_str! to get the raw source at compile time.
const PREPROCESS_SOURCE: &str = include_str!("../src/preprocess.rs");

/// Helper to find a function declaration and verify #[must_use] appears immediately before it.
/// Returns the line number of the function if #[must_use] is found, or None if not found.
fn find_must_use_before_function(source: &str, fn_signature: &str) -> Option<(bool, usize)> {
    let lines: Vec<&str> = source.lines().collect();
    
    for (i, line) in lines.iter().enumerate() {
        if line.contains(fn_signature) {
            // Check if the previous non-empty line has #[must_use]
            // We need to go back and skip empty lines and comments
            let mut check_idx = i;
            while check_idx > 0 {
                check_idx -= 1;
                let prev_line = lines[check_idx].trim();
                if prev_line.is_empty() {
                    continue;
                }
                if prev_line.starts_with("//") {
                    continue;
                }
                if prev_line.starts_with("/*") || prev_line.starts_with("*/") || prev_line.starts_with("*") {
                    continue;
                }
                // Found a meaningful previous line
                let has_must_use = prev_line == "#[must_use]";
                return Some((has_must_use, i + 1)); // 1-indexed line number
            }
            // Function is at start of file or only preceded by comments/empty lines
            return Some((false, i + 1));
        }
    }
    None
}

/// Test that PreprocessOptions::none() has #[must_use]
#[test]
fn preprocess_options_none_has_must_use() {
    let result = find_must_use_before_function(PREPROCESS_SOURCE, "pub fn none() -> Self");
    assert!(
        result.is_some(),
        "Could not find 'pub fn none() -> Self' in preprocess.rs"
    );
    
    let (has_must_use, line_num) = result.unwrap();
    assert!(
        has_must_use,
        "PreprocessOptions::none() at line {} does NOT have #[must_use] attribute. \
         The function returns Self representing configuration that must not be dropped. \
         Expected #[must_use] to appear on the line immediately before the function declaration.",
        line_num
    );
}

/// Test that PreprocessOptions::comments_only() has #[must_use]
#[test]
fn preprocess_options_comments_only_has_must_use() {
    let result = find_must_use_before_function(PREPROCESS_SOURCE, "pub fn comments_only() -> Self");
    assert!(
        result.is_some(),
        "Could not find 'pub fn comments_only() -> Self' in preprocess.rs"
    );
    
    let (has_must_use, line_num) = result.unwrap();
    assert!(
        has_must_use,
        "PreprocessOptions::comments_only() at line {} does NOT have #[must_use] attribute. \
         The function returns Self representing configuration that must not be dropped. \
         Expected #[must_use] to appear on the line immediately before the function declaration.",
        line_num
    );
}

/// Test that PreprocessOptions::strings_only() has #[must_use]
#[test]
fn preprocess_options_strings_only_has_must_use() {
    let result = find_must_use_before_function(PREPROCESS_SOURCE, "pub fn strings_only() -> Self");
    assert!(
        result.is_some(),
        "Could not find 'pub fn strings_only() -> Self' in preprocess.rs"
    );
    
    let (has_must_use, line_num) = result.unwrap();
    assert!(
        has_must_use,
        "PreprocessOptions::strings_only() at line {} does NOT have #[must_use] attribute. \
         The function returns Self representing configuration that must not be dropped. \
         Expected #[must_use] to appear on the line immediately before the function declaration.",
        line_num
    );
}

/// Test that PreprocessOptions::comments_and_strings() has #[must_use]
#[test]
fn preprocess_options_comments_and_strings_has_must_use() {
    let result = find_must_use_before_function(PREPROCESS_SOURCE, "pub fn comments_and_strings() -> Self");
    assert!(
        result.is_some(),
        "Could not find 'pub fn comments_and_strings() -> Self' in preprocess.rs"
    );
    
    let (has_must_use, line_num) = result.unwrap();
    assert!(
        has_must_use,
        "PreprocessOptions::comments_and_strings() at line {} does NOT have #[must_use] attribute. \
         The function returns Self representing configuration that must not be dropped. \
         Expected #[must_use] to appear on the line immediately before the function declaration.",
        line_num
    );
}

/// Test that Preprocessor::new() has #[must_use]
#[test]
fn preprocessor_new_has_must_use() {
    let result = find_must_use_before_function(PREPROCESS_SOURCE, "pub fn new(opts: PreprocessOptions) -> Self");
    assert!(
        result.is_some(),
        "Could not find 'pub fn new(opts: PreprocessOptions) -> Self' in preprocess.rs"
    );
    
    let (has_must_use, line_num) = result.unwrap();
    assert!(
        has_must_use,
        "Preprocessor::new() at line {} does NOT have #[must_use] attribute. \
         The function returns Self representing preprocessor state that must not be dropped. \
         Expected #[must_use] to appear on the line immediately before the function declaration.",
        line_num
    );
}

/// Test that Preprocessor::with_language() has #[must_use]
#[test]
fn preprocessor_with_language_has_must_use() {
    let result = find_must_use_before_function(PREPROCESS_SOURCE, "pub fn with_language(opts: PreprocessOptions, lang: Language) -> Self");
    assert!(
        result.is_some(),
        "Could not find 'pub fn with_language(opts: PreprocessOptions, lang: Language) -> Self' in preprocess.rs"
    );
    
    let (has_must_use, line_num) = result.unwrap();
    assert!(
        has_must_use,
        "Preprocessor::with_language() at line {} does NOT have #[must_use] attribute. \
         The function returns Self representing preprocessor state that must not be dropped. \
         Expected #[must_use] to appear on the line immediately before the function declaration.",
        line_num
    );
}

/// Verification test: Ensure there are exactly 6 #[must_use] attributes in preprocess.rs
/// This verifies scope is limited to the 6 specified functions and no more are added.
#[test]
fn exactly_six_must_use_attributes_in_preprocess() {
    let must_use_count = PREPROCESS_SOURCE
        .lines()
        .filter(|line| line.trim() == "#[must_use]")
        .count();
    
    assert_eq!(
        must_use_count, 6,
        "Expected exactly 6 #[must_use] attributes in preprocess.rs, but found {}. \
         The scope of this issue is limited to 6 specific functions. \
         If more #[must_use] attributes are needed, that should be a separate issue.",
        must_use_count
    );
}