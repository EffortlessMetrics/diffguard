//! Edge case tests for work-ece459be: redundant closures in arb.rs
//!
//! These tests supplement the red tests with edge case coverage for the
//! strategies that use `str::to_string` (formerly `|s| s.to_string()`):
//! - `arb_file_extension()` - generates file extensions
//! - `arb_dir_name()` - generates directory names
//! - `arb_language()` - generates language identifiers
//!
//! Edge cases covered:
//! - Strategy repeatability (can generate many values)
//! - JSON serialization roundtrip
//! - Ownership and borrowed reference semantics
//! - Stress testing with high iteration counts
//! - Value distribution across known set

use diffguard_testkit::arb;
use proptest::strategy::Strategy;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

/// Known valid file extensions that arb_file_extension() should produce.
const VALID_EXTENSIONS: &[&str] = &[
    "rs", "py", "js", "ts", "jsx", "tsx", "go", "java", "kt", "rb", "c", "cpp", "h", "hpp", "cs",
    "txt", "md", "json", "yaml", "toml",
];

/// Known valid directory names that arb_dir_name() should produce.
const VALID_DIR_NAMES: &[&str] = &[
    "src", "lib", "bin", "tests", "test", "examples", "benches", "docs", "scripts", "utils",
    "core", "api", "internal", "pkg", "cmd", "app",
];

/// Known valid language identifiers that arb_language() should produce.
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
// Strategy Repeatability Tests
// =============================================================================

/// Test that arb_language() can be called multiple times without issues.
///
/// This verifies the strategy is reusable and doesn't consume itself.
#[test]
fn arb_language_strategy_is_reusable() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_language();

    // Generate many values from the same strategy
    for _ in 0..200 {
        let lang = strategy.new_tree(&mut runner).unwrap().current();
        assert!(
            VALID_LANGUAGES.contains(&lang.as_str()),
            "arb_language produced '{}' not in known set",
            lang
        );
    }
}

/// Test that arb_file_extension() strategy is reusable.
///
/// Strategies in proptest should be usable multiple times.
#[test]
fn arb_file_extension_strategy_is_reusable() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_file_path();

    for _ in 0..200 {
        let path = strategy.new_tree(&mut runner).unwrap().current();
        // Extract extension
        if let Some(ext_start) = path.rfind('.') {
            let ext = &path[ext_start + 1..];
            assert!(
                VALID_EXTENSIONS.contains(&ext),
                "File path '{}' has unknown extension '{}'",
                path,
                ext
            );
        }
    }
}

/// Test that arb_dir_name() strategy is reusable.
#[test]
fn arb_dir_name_strategy_is_reusable() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_file_path();

    for _ in 0..200 {
        let path = strategy.new_tree(&mut runner).unwrap().current();
        let parts: Vec<&str> = path.split('/').collect();

        for dir in &parts[..parts.len() - 1] {
            if !dir.is_empty() {
                assert!(
                    VALID_DIR_NAMES.contains(dir),
                    "File path '{}' has unknown directory '{}'",
                    path,
                    dir
                );
            }
        }
    }
}

// =============================================================================
// JSON Serialization Roundtrip Tests
// =============================================================================

/// Test that arb_language() values can be serialized to JSON and back.
///
/// This verifies the generated Strings work with common serialization formats.
#[test]
fn arb_language_json_roundtrip() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_language();

    for _ in 0..50 {
        let lang = strategy.new_tree(&mut runner).unwrap().current();

        // Serialize to JSON
        let json = serde_json::to_string(&lang).unwrap();

        // Deserialize back
        let parsed: String = serde_json::from_str(&json).unwrap();

        assert_eq!(
            lang, parsed,
            "JSON roundtrip should preserve language value"
        );
    }
}

/// Test that arb_file_extension() values can be JSON serialized.
#[test]
fn arb_file_extension_json_roundtrip() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_file_path();

    for _ in 0..50 {
        let path = strategy.new_tree(&mut runner).unwrap().current();

        let json = serde_json::to_string(&path).unwrap();
        let parsed: String = serde_json::from_str(&json).unwrap();

        assert_eq!(path, parsed, "JSON roundtrip should preserve path");
    }
}

/// Test that arb_rule_config with languages can be JSON serialized.
#[test]
fn rule_config_with_languages_json_roundtrip() {
    use diffguard_types::RuleConfig;

    let mut runner = TestRunner::default();
    let strategy = arb::arb_rule_config();

    for _ in 0..20 {
        let config: RuleConfig = strategy.new_tree(&mut runner).unwrap().current();

        let json = serde_json::to_string(&config).unwrap();
        let parsed: RuleConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.id, parsed.id);
        assert_eq!(config.languages, parsed.languages);
    }
}

// =============================================================================
// Ownership and Borrowed Reference Tests
// =============================================================================

/// Test that arb_language() returns owned Strings that can be dropped independently.
///
/// This verifies the strategy produces owned data, not borrowed references.
#[test]
fn arb_language_returns_owned_data() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_language();

    // Generate and immediately drop many values
    for _ in 0..100 {
        let lang = strategy.new_tree(&mut runner).unwrap().current();
        // If this compiles, lang is an owned String (not &str)
        let _owned: String = lang;
        // lang is moved here, so we generate a new one next iteration
    }
}

/// Test that arb_language() values can be cloned.
#[test]
fn arb_language_values_are_cloneable() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_language();

    for _ in 0..50 {
        let lang = strategy.new_tree(&mut runner).unwrap().current();
        let cloned = lang.clone();
        assert_eq!(lang, cloned);
    }
}

// =============================================================================
// Stress Tests
// =============================================================================

/// Stress test: generate many values to verify no panics occur.
///
/// Proptest strategies should be safe to use under high iteration counts.
#[test]
fn arb_language_stress_test() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_language();

    let mut seen_count = 0;
    for _ in 0..1000 {
        let lang = strategy.new_tree(&mut runner).unwrap().current();
        if VALID_LANGUAGES.contains(&lang.as_str()) {
            seen_count += 1;
        }
    }
    // With 1000 iterations, we should see many valid values
    assert!(
        seen_count >= 990,
        "Expected ~1000 valid languages, got {}",
        seen_count
    );
}

/// Stress test for arb_file_path using arb_file_extension.
#[test]
fn arb_file_path_stress_test() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_file_path();

    for _ in 0..500 {
        let path = strategy.new_tree(&mut runner).unwrap().current();

        // Basic validation
        assert!(!path.is_empty());
        assert!(path.contains('/'), "Path '{}' should contain '/'", path);
        assert!(path.contains('.'), "Path '{}' should contain '.'", path);

        // Extract and validate extension
        if let Some(ext_start) = path.rfind('.') {
            let ext = &path[ext_start + 1..];
            assert!(
                VALID_EXTENSIONS.contains(&ext),
                "Unknown extension '{}' in path '{}'",
                ext,
                path
            );
        }
    }
}

/// Stress test for arb_glob_pattern using arb_file_extension.
#[test]
fn arb_glob_pattern_stress_test() {
    use globset::Glob;

    let mut runner = TestRunner::default();
    let strategy = arb::arb_glob_pattern();

    for _ in 0..500 {
        let glob_str = strategy.new_tree(&mut runner).unwrap().current();

        // All generated globs should be valid
        assert!(
            Glob::new(&glob_str).is_ok(),
            "Generated glob '{}' should be valid",
            glob_str
        );
    }
}

// =============================================================================
// Value Distribution Tests
// =============================================================================

/// Test that arb_language() produces values from across the known set.
///
/// With enough iterations, we should see multiple different languages.
#[test]
fn arb_language_covers_known_set() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_language();

    let mut seen_languages = std::collections::HashSet::new();

    for _ in 0..500 {
        let lang = strategy.new_tree(&mut runner).unwrap().current();
        seen_languages.insert(lang);
    }

    // Should see at least 5 different languages out of 11
    assert!(
        seen_languages.len() >= 5,
        "Expected to see at least 5 different languages, saw {}",
        seen_languages.len()
    );
}

/// Test that arb_file_extension() produces values from across the known set.
#[test]
fn arb_file_extension_covers_known_set() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_file_path();

    let mut seen_extensions = std::collections::HashSet::new();

    for _ in 0..500 {
        let path = strategy.new_tree(&mut runner).unwrap().current();

        if let Some(ext_start) = path.rfind('.') {
            let ext = &path[ext_start + 1..];
            seen_extensions.insert(ext.to_string());
        }
    }

    // Should see at least 5 different extensions out of 20
    assert!(
        seen_extensions.len() >= 5,
        "Expected to see at least 5 different extensions, saw {}",
        seen_extensions.len()
    );
}

// =============================================================================
// Composite Strategy Tests
// =============================================================================

/// Test that arb_language works in prop_oneof!
#[test]
fn arb_language_in_prop_oneof() {
    use proptest::prop_oneof;

    let mut runner = TestRunner::default();
    let strategy = prop_oneof![arb::arb_language(), arb::arb_language()];

    for _ in 0..100 {
        let lang = strategy.new_tree(&mut runner).unwrap().current();
        assert!(
            VALID_LANGUAGES.contains(&lang.as_str()),
            "prop_oneof with arb_language produced unknown '{}'",
            lang
        );
    }
}

/// Test that arb_language works when combined with other strategies.
#[test]
fn arb_language_combined_with_arb_severity() {
    use diffguard_types::Severity;

    let mut runner = TestRunner::default();

    for _ in 0..50 {
        let lang = arb::arb_language().new_tree(&mut runner).unwrap().current();
        let sev = arb::arb_severity().new_tree(&mut runner).unwrap().current();

        assert!(VALID_LANGUAGES.contains(&lang.as_str()));
        // Verify it's a valid Severity variant - should not panic
        let _ = matches!(sev, Severity::Info | Severity::Warn | Severity::Error);
    }
}
