//! Red tests for work-fd603479: redundant match arm removal in string_syntax()
//!
//! Issue #470 reports a `clippy::identical_match_arms` lint warning at `preprocess.rs:107`,
//! where `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle` is claimed
//! to be redundant because the wildcard `_ => StringSyntax::CStyle` already covers JSON.
//!
//! These tests verify the source code structure AFTER the fix:
//! - `Language::Json` should NOT be in the explicit match arm with YAML/TOML
//! - `Language::Json` should be handled by the wildcard `_ => StringSyntax::CStyle`
//! - `Language::Yaml` and `Language::Toml` should remain in the explicit match arm
//!
//! These tests FAIL before the fix (Json IS in explicit arm) and PASS after the fix (Json removed).

use std::fs;
use std::path::Path;

/// Test that the source code does NOT contain `Language::Json` in the explicit
/// match arm with YAML and TOML in the string_syntax() function.
///
/// BEFORE FIX: This test FAILS because line 107 has:
///   Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
///
/// AFTER FIX: This test PASSES because line 107 has:
///   Language::Yaml | Language::Toml => StringSyntax::CStyle,
/// and `Language::Json` is handled by the wildcard.
#[test]
fn json_not_in_explicit_yaml_toml_arm_in_source() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("preprocess.rs");

    let source_content =
        fs::read_to_string(&source_path).expect("Failed to read preprocess.rs source file");

    // This regex matches the problematic pattern WITH Json in the explicit arm
    // It matches: Language::Yaml | Language::Toml | Language::Json =>
    let json_in_explicit_pattern =
        regex::Regex::new(r"Language::Yaml\s*\|\s*Language::Toml\s*\|\s*Language::Json\s*=>")
            .expect("Invalid regex pattern");

    // This assertion FAILS before fix (Json IS in explicit arm) and PASSES after fix
    assert!(
        !json_in_explicit_pattern.is_match(&source_content),
        "Language::Json should NOT be in the explicit match arm with Yaml/Toml.\n\
         The explicit arm should be: Language::Yaml | Language::Toml => StringSyntax::CStyle,\n\
         and Language::Json should be handled by the wildcard _ => StringSyntax::CStyle"
    );
}

/// Test that the source code DOES contain the correct explicit arm for YAML and TOML.
///
/// This verifies that YAML and TOML remain explicit (NOT removed) after the JSON fix.
///
/// BEFORE FIX: This test FAILS because the explicit arm includes Json:
///   Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle
///
/// AFTER FIX: This test PASSES because the explicit arm is:
///   Language::Yaml | Language::Toml => StringSyntax::CStyle
#[test]
fn yaml_toml_explicit_arm_present_in_source() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("preprocess.rs");

    let source_content =
        fs::read_to_string(&source_path).expect("Failed to read preprocess.rs source file");

    // After fix, the explicit arm should be:
    //   Language::Yaml | Language::Toml => StringSyntax::CStyle
    // (without Json)
    let yaml_toml_explicit_pattern =
        regex::Regex::new(r"Language::Yaml\s*\|\s*Language::Toml\s*=>\s*StringSyntax::CStyle")
            .expect("Invalid regex pattern");

    assert!(
        yaml_toml_explicit_pattern.is_match(&source_content),
        "Language::Yaml | Language::Toml should have an explicit match arm.\n\
         This arm should NOT include Language::Json (that's handled by wildcard)"
    );
}

/// Verify that the comment above the YAML/TOML/JSON arm has been updated.
///
/// After the fix, the comment should only mention YAML and TOML, not JSON.
///
/// BEFORE FIX: This test FAILS because the comment says "YAML/TOML/JSON"
///
/// AFTER FIX: This test PASSES because the comment says "YAML/TOML"
#[test]
fn comment_mentions_only_yaml_toml_not_json() {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("preprocess.rs");

    let source_content =
        fs::read_to_string(&source_path).expect("Failed to read preprocess.rs source file");

    // The comment should NOT mention JSON in the YAML/TOML/JSON line
    // After fix, it should say something like "YAML/TOML strings are C-style-like"
    let json_mentioned_with_yaml_toml =
        regex::Regex::new(r"//\s*[^\n]*YAML/TOML/JSON[^\n]*").expect("Invalid regex pattern");

    assert!(
        !json_mentioned_with_yaml_toml.is_match(&source_content),
        "The comment above the explicit arm should mention only YAML/TOML, not JSON.\n\
         JSON is handled by the wildcard and shouldn't be grouped with YAML/TOML in comments."
    );
}
