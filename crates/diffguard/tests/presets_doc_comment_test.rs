//! Tests for RustQuality preset documentation accuracy.
//!
//! These tests verify that the RustQuality preset's doc comment and description()
//! use namespaced rule IDs (rust.no_unwrap, rust.no_dbg, rust.no_todo, rust.no_println)
//! that match the actual generated TOML rule IDs, rather than shorthand names
//! (no_unwrap, no_dbg, no_todo, no_print) that don't exist in the generated output.

use diffguard::Preset;

/// Tests that the description() method uses namespaced rule IDs.
/// The description should mention "rust.no_unwrap", "rust.no_dbg", "rust.no_todo",
/// and "rust.no_println" to match the actual generated TOML rules.
#[test]
fn test_rust_quality_description_uses_namespaced_rule_ids() {
    let desc = Preset::RustQuality.description();

    // Should contain namespaced rule IDs that match actual generated rules
    assert!(
        desc.contains("rust.no_unwrap"),
        "description should contain 'rust.no_unwrap' to match generated TOML, got: {}",
        desc
    );
    assert!(
        desc.contains("rust.no_dbg"),
        "description should contain 'rust.no_dbg' to match generated TOML, got: {}",
        desc
    );
    assert!(
        desc.contains("rust.no_todo"),
        "description should contain 'rust.no_todo' to match generated TOML, got: {}",
        desc
    );
    assert!(
        desc.contains("rust.no_println"),
        "description should contain 'rust.no_println' to match generated TOML, got: {}",
        desc
    );

    // Should NOT contain shorthand names that don't exist as rule IDs
    // "no_todo" is not a valid rule ID - it should be "rust.no_todo"
    assert!(
        !desc.contains("no_todo"),
        "description should not contain shorthand 'no_todo' (should be 'rust.no_todo'), got: {}",
        desc
    );
    // "no_print" is not a valid rule ID - it should be "rust.no_println"
    assert!(
        !desc.contains("no_print"),
        "description should not contain shorthand 'no_print' (should be 'rust.no_println'), got: {}",
        desc
    );
}

/// Tests that the doc comment on the RustQuality enum variant uses namespaced rule IDs.
/// The doc comment at line 13 of presets.rs should mention "rust.no_unwrap",
/// "rust.no_dbg", "rust.no_todo", and "rust.no_println" to match the actual
/// generated TOML rule IDs.
#[test]
fn test_rust_quality_doc_comment_uses_namespaced_rule_ids() {
    // Read the source file to inspect the doc comment
    let source = include_str!("../src/presets.rs");
    let lines: Vec<&str> = source.lines().collect();

    // Find the RustQuality variant and its preceding doc comment
    // Line 13 has the doc comment, line 14 has the variant
    // Based on: /// Rust best practices (no_unwrap, no_dbg, no_todo, no_print)
    //            RustQuality,
    let mut doc_comment_line: Option<&str> = None;
    let mut found_rust_quality_variant = false;

    for (i, line) in lines.iter().enumerate() {
        // Look for the RustQuality variant (not generate_rust_quality function)
        if line.trim() == "RustQuality,"
            || line.trim_start().starts_with("RustQuality") && line.contains("::")
        {
            // The doc comment should be the previous non-empty line
            if i > 0 {
                let prev_line = lines[i - 1].trim();
                if prev_line.starts_with("///") || prev_line.starts_with("//!") {
                    doc_comment_line = Some(prev_line);
                }
            }
            found_rust_quality_variant = true;
            break;
        }
    }

    assert!(
        found_rust_quality_variant,
        "Should find RustQuality variant in source"
    );

    let doc_comment = doc_comment_line
        .expect("RustQuality should have a doc comment (/// ...) on the preceding line");

    // The doc comment should contain namespaced rule IDs that match generated TOML
    assert!(
        doc_comment.contains("rust.no_unwrap"),
        "doc comment should contain 'rust.no_unwrap' to match generated TOML, got: {}",
        doc_comment
    );
    assert!(
        doc_comment.contains("rust.no_dbg"),
        "doc comment should contain 'rust.no_dbg' to match generated TOML, got: {}",
        doc_comment
    );
    assert!(
        doc_comment.contains("rust.no_todo"),
        "doc comment should contain 'rust.no_todo' to match generated TOML, got: {}",
        doc_comment
    );
    assert!(
        doc_comment.contains("rust.no_println"),
        "doc comment should contain 'rust.no_println' to match generated TOML, got: {}",
        doc_comment
    );

    // Should NOT contain shorthand names
    assert!(
        !doc_comment.contains("no_todo"),
        "doc comment should not contain shorthand 'no_todo' (should be 'rust.no_todo'), got: {}",
        doc_comment
    );
    assert!(
        !doc_comment.contains("no_print"),
        "doc comment should not contain shorthand 'no_print' (should be 'rust.no_println'), got: {}",
        doc_comment
    );
}

/// Tests that the generated TOML for RustQuality preset contains exactly the
/// expected rule IDs - this verifies the "No behavioral change" acceptance criterion.
/// The generated TOML should still produce 6 rules with the rust.* namespace.
#[test]
fn test_rust_quality_generates_correct_rule_ids() {
    use diffguard_types::ConfigFile;

    let content = Preset::RustQuality.generate();
    let config: ConfigFile =
        toml::from_str(&content).expect("RustQuality preset should generate valid TOML");

    // Verify all 6 expected rules are present with correct IDs
    let rule_ids: Vec<&str> = config.rule.iter().map(|r| r.id.as_str()).collect();

    assert!(
        rule_ids.contains(&"rust.no_unwrap"),
        "Generated TOML should contain 'rust.no_unwrap', got: {:?}",
        rule_ids
    );
    assert!(
        rule_ids.contains(&"rust.no_expect"),
        "Generated TOML should contain 'rust.no_expect', got: {:?}",
        rule_ids
    );
    assert!(
        rule_ids.contains(&"rust.no_dbg"),
        "Generated TOML should contain 'rust.no_dbg', got: {:?}",
        rule_ids
    );
    assert!(
        rule_ids.contains(&"rust.no_println"),
        "Generated TOML should contain 'rust.no_println', got: {:?}",
        rule_ids
    );
    assert!(
        rule_ids.contains(&"rust.no_todo"),
        "Generated TOML should contain 'rust.no_todo', got: {:?}",
        rule_ids
    );
    assert!(
        rule_ids.contains(&"rust.no_unimplemented"),
        "Generated TOML should contain 'rust.no_unimplemented', got: {:?}",
        rule_ids
    );

    // Verify count - should be exactly 6 rules
    assert_eq!(
        rule_ids.len(),
        6,
        "RustQuality should generate exactly 6 rules, got: {:?}",
        rule_ids
    );
}
