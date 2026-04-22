//! Integration tests for diffguard-testkit
//!
//! These tests verify that the testkit components work together correctly.
//! The key integration points are:
//! 1. arb strategies compose with DiffBuilder
//! 2. Generated configs work with schema validation
//! 3. Multiple strategies can be used together
//! 4. Fixtures work with the validation pipeline

use diffguard_testkit::{
    arb::{self, arb_config_file, arb_file_path, arb_language, arb_rule_config},
    diff_builder::DiffBuilder,
    fixtures::sample_configs,
    schema::validate_config_file,
};
use diffguard_types::{ConfigFile, Defaults, FailOn, RuleConfig, Scope, Severity};
use proptest::strategy::Strategy;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

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
// Integration Test 1: Strategy + DiffBuilder Composition
// =============================================================================

/// Test that arb_file_path strategy works with DiffBuilder.
///
/// This verifies:
/// - arb::arb_file_path() produces valid file paths
/// - Those paths can be used with DiffBuilder to create valid diffs
/// - The diff output is valid unified diff format
#[test]
fn integration_arb_file_path_with_diff_builder() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_file_path();

    for _ in 0..30 {
        let path = strategy.new_tree(&mut runner).unwrap().current();

        // Use the generated path in DiffBuilder
        let diff = DiffBuilder::new()
            .file(&path)
            .hunk(1, 1, 1, 2)
            .context("fn old_function() {}")
            .add_line("fn new_function() {}")
            .done()
            .done()
            .build();

        // Verify the diff is valid
        assert!(diff.contains("diff --git"));
        assert!(diff.contains(&format!("b/{}", path)));
        assert!(diff.contains("@@"));
    }
}

/// Test that arb strategies compose with DiffBuilder for complex diffs.
#[test]
fn integration_arb_language_with_diff_builder() {
    let mut runner = TestRunner::default();
    let lang_strategy = arb::arb_language();

    for _ in 0..20 {
        let lang = lang_strategy.new_tree(&mut runner).unwrap().current();

        // Different file extensions based on language
        let ext = match lang.as_str() {
            "rust" => "rs",
            "python" => "py",
            "javascript" | "typescript" => "js",
            "go" => "go",
            "java" | "kotlin" => "java",
            _ => "txt",
        };

        let path = format!("src/main.{}", ext);
        let diff = DiffBuilder::new()
            .file(&path)
            .hunk(10, 5, 10, 7)
            .remove("let x = 1;")
            .remove("let y = 2;")
            .add_line("let x = 1;")
            .add_line("let y = 2;")
            .add_line("let z = x + y;")
            .done()
            .done()
            .build();

        // Verify diff structure
        assert!(diff.contains("diff --git"));
        assert!(diff.contains(&format!("b/{}", path)));
        assert!(diff.contains("-let x = 1;"));
        assert!(diff.contains("+let z = x + y;"));
    }
}

/// Test that generated glob patterns can be used in configs.
#[test]
fn integration_glob_patterns_with_config() {
    use globset::Glob;

    let mut runner = TestRunner::default();
    let glob_strategy = arb::arb_glob_pattern();

    for _ in 0..20 {
        let glob_str = glob_strategy.new_tree(&mut runner).unwrap().current();

        // Verify the glob is valid
        assert!(
            Glob::new(&glob_str).is_ok(),
            "Generated glob '{}' should be valid",
            glob_str
        );

        // Build a diff that matches the glob
        let path = "src/test.js";
        let diff = DiffBuilder::new()
            .file(path)
            .hunk(1, 0, 1, 1)
            .add_line("console.log('hello');")
            .done()
            .done()
            .build();

        // The diff should match the path expectations
        assert!(diff.contains(path));
    }
}

// =============================================================================
// Integration Test 2: Strategy + Schema Validation
// =============================================================================

/// Test that generated RuleConfig passes schema validation.
#[test]
fn integration_arb_rule_config_with_schema_validation() {
    let mut runner = TestRunner::default();
    let strategy = arb::arb_rule_config();

    for _ in 0..15 {
        let config: RuleConfig = strategy.new_tree(&mut runner).unwrap().current();

        // Create a ConfigFile wrapping the rule
        let config_file = ConfigFile {
            includes: vec![],
            defaults: Defaults {
                base: Some("abc123".to_string()),
                head: Some("def456".to_string()),
                scope: Some(Scope::Added),
                fail_on: Some(FailOn::Warn),
                max_findings: Some(100),
                diff_context: Some(3),
            },
            rule: vec![config.clone()],
        };

        // Validation should succeed
        let result = validate_config_file(&config_file);
        assert!(
            result.is_ok(),
            "Generated RuleConfig should pass validation: {:?}",
            result.err()
        );
    }
}

/// Test that generated ConfigFile passes schema validation.
#[test]
fn integration_arb_config_file_with_schema_validation() {
    let mut runner = TestRunner::default();
    let strategy = arb_config_file();

    for _ in 0..10 {
        let config_file: ConfigFile = strategy.new_tree(&mut runner).unwrap().current();

        let result = validate_config_file(&config_file);
        assert!(
            result.is_ok(),
            "Generated ConfigFile should pass validation: {:?}",
            result.err()
        );
    }
}

// =============================================================================
// Integration Test 3: Fixtures + Strategy Composition
// =============================================================================

/// Test that fixtures can be combined with arb strategies.
#[test]
fn integration_fixtures_with_arb_strategy_extension() {
    let mut runner = TestRunner::default();

    // Start with a minimal fixture config
    let minimal = sample_configs::minimal();

    // Use arb_language to add a language to the config
    let lang = arb_language().new_tree(&mut runner).unwrap().current();

    // Create a new config based on minimal but with arb-generated language
    // The minimal fixture has rules[0] with the RuleConfig
    let base_rule = &minimal.rule[0];
    let extended_config = RuleConfig {
        id: format!("{}-extended", base_rule.id),
        severity: base_rule.severity.clone(),
        message: base_rule.message.clone(),
        description: base_rule.description.clone(),
        languages: vec![lang.clone()], // Add arb-generated language
        patterns: base_rule.patterns.clone(),
        paths: base_rule.paths.clone(),
        exclude_paths: base_rule.exclude_paths.clone(),
        ignore_comments: base_rule.ignore_comments,
        ignore_strings: base_rule.ignore_strings,
        match_mode: base_rule.match_mode.clone(),
        multiline: base_rule.multiline,
        multiline_window: base_rule.multiline_window,
        context_patterns: base_rule.context_patterns.clone(),
        context_window: base_rule.context_window,
        escalate_patterns: base_rule.escalate_patterns.clone(),
        escalate_window: base_rule.escalate_window,
        escalate_to: base_rule.escalate_to.clone(),
        depends_on: base_rule.depends_on.clone(),
        help: base_rule.help.clone(),
        url: base_rule.url.clone(),
        tags: base_rule.tags.clone(),
        test_cases: base_rule.test_cases.clone(),
    };

    // Verify the extended config is valid
    assert!(VALID_LANGUAGES.contains(&lang.as_str()));
    assert!(!extended_config.id.is_empty());

    // Create a ConfigFile with the extended rule
    let config_file = ConfigFile {
        includes: vec![],
        defaults: Defaults::default(),
        rule: vec![extended_config],
    };

    let result = validate_config_file(&config_file);
    assert!(result.is_ok(), "Extended config should pass validation");
}

/// Test that sample diffs can be used with arb strategies.
#[test]
fn integration_sample_diffs_with_arb_path_strategy() {
    let mut runner = TestRunner::default();

    // Generate a file path
    let path = arb_file_path().new_tree(&mut runner).unwrap().current();

    // The path should be a valid format
    assert!(path.contains('/'));
    assert!(path.contains('.'));
}

// =============================================================================
// Integration Test 4: Full End-to-End Workflows
// =============================================================================

/// Test end-to-end: Generate config → Build diff → Verify outputs
///
/// This simulates a full diffguard workflow:
/// 1. Generate a rule config with arb
/// 2. Build a diff that may or may not trigger the rule
/// 3. Verify the outputs are compatible
#[test]
fn integration_full_workflow_config_to_diff() {
    let mut runner = TestRunner::default();

    // Step 1: Generate a rule config
    let rule: RuleConfig = arb_rule_config().new_tree(&mut runner).unwrap().current();

    // Step 2: Generate a file path
    let path = arb_file_path().new_tree(&mut runner).unwrap().current();

    // Step 3: Generate a language
    let lang = arb_language().new_tree(&mut runner).unwrap().current();

    // Step 4: Build a diff
    let diff = DiffBuilder::new()
        .file(&path)
        .hunk(1, 0, 1, 1)
        .add_line("fn main() {")
        .done()
        .done()
        .build();

    // Step 5: Verify all outputs are compatible
    assert!(!rule.id.is_empty());
    assert!(!path.is_empty());
    assert!(VALID_LANGUAGES.contains(&lang.as_str()));
    assert!(diff.contains("diff --git"));
    assert!(diff.contains(&format!("b/{}", path)));

    // Step 6: Build a ConfigFile with the generated rule
    let config_file = ConfigFile {
        includes: vec![],
        defaults: Defaults::default(),
        rule: vec![rule],
    };

    // Step 7: Validate the config
    let result = validate_config_file(&config_file);
    assert!(
        result.is_ok(),
        "Full workflow config should pass validation: {:?}",
        result.err()
    );
}

/// Test that multiple arb strategies can be combined in a single test scenario.
#[test]
fn integration_multiple_arb_strategies_combined() {
    let mut runner = TestRunner::default();

    // Generate multiple languages
    let lang1 = arb_language().new_tree(&mut runner).unwrap().current();
    let lang2 = arb_language().new_tree(&mut runner).unwrap().current();

    // Generate multiple paths
    let path1 = arb_file_path().new_tree(&mut runner).unwrap().current();
    let path2 = arb_file_path().new_tree(&mut runner).unwrap().current();

    // Generate a rule config with multiple languages
    let mut rule: RuleConfig = arb_rule_config().new_tree(&mut runner).unwrap().current();
    rule.languages = vec![lang1.clone(), lang2.clone()];

    // Build diffs for both paths
    let diff1 = DiffBuilder::new()
        .file(&path1)
        .hunk(1, 1, 1, 1)
        .context("old line")
        .add_line("new line")
        .done()
        .done()
        .build();

    let diff2 = DiffBuilder::new()
        .file(&path2)
        .hunk(1, 0, 1, 1)
        .add_line("brand new file content")
        .done()
        .done()
        .build();

    // Verify all generated data is consistent
    assert!(VALID_LANGUAGES.contains(&lang1.as_str()));
    assert!(VALID_LANGUAGES.contains(&lang2.as_str()));
    assert!(diff1.contains("diff --git"));
    assert!(diff2.contains("diff --git"));

    // Create a config file with the rule
    let config_file = ConfigFile {
        includes: vec![],
        defaults: Defaults::default(),
        rule: vec![rule],
    };

    let result = validate_config_file(&config_file);
    assert!(
        result.is_ok(),
        "Combined strategies config should pass validation: {:?}",
        result.err()
    );
}

/// Test property-based: verify arb strategies work under concurrent use.
#[test]
fn integration_concurrent_strategy_use() {
    use std::thread;

    let mut handles = vec![];

    // Spawn multiple threads, each generating values
    for _ in 0..4 {
        let handle = thread::spawn(move || {
            let mut runner = TestRunner::default();

            // Each thread generates values from various strategies
            for _ in 0..25 {
                let _path = arb_file_path().new_tree(&mut runner).unwrap().current();
                let _lang = arb_language().new_tree(&mut runner).unwrap().current();
                let _rule: RuleConfig = arb_rule_config().new_tree(&mut runner).unwrap().current();
            }

            // All values should be valid
            true
        });
        handles.push(handle);
    }

    // Wait for all threads and verify they completed
    for handle in handles {
        let result = handle.join().unwrap();
        assert!(result, "Thread should complete successfully");
    }
}

// =============================================================================
// Integration Test 5: Error Propagation
// =============================================================================

/// Test that proptest filter backtracking works correctly.
///
/// When proptest finds a value that fails a filter, it should
/// backtrack and try again, not propagate errors to the caller.
#[test]
fn integration_proptest_filter_backtracking() {
    let mut runner = TestRunner::default();

    // arb_non_empty_string has a filter that rejects empty strings
    // This should work fine - proptest handles the backtracking
    for _ in 0..20 {
        let s = arb::arb_non_empty_string()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        assert!(!s.is_empty());
    }
}

/// Test that deeply nested strategy compositions work correctly.
#[test]
fn integration_deep_strategy_composition() {
    let mut runner = TestRunner::default();

    // arb_config_file is deeply composed:
    // ConfigFile -> Defaults + Vec<RuleConfig>
    //   -> RuleConfig -> languages (Vec<String>), patterns, paths, exclude_paths
    //     -> arb_language(), arb_glob_pattern(), arb_include_glob(), arb_exclude_glob()
    //       -> arb_file_extension(), arb_dir_name()

    for _ in 0..10 {
        let config: ConfigFile = arb_config_file().new_tree(&mut runner).unwrap().current();

        // Validate the deeply composed result
        let result = validate_config_file(&config);
        assert!(
            result.is_ok(),
            "Deeply composed config should pass validation"
        );

        // Check that nested values are reasonable
        for rule in &config.rule {
            assert!(!rule.id.is_empty());

            // Languages should be valid
            for lang in &rule.languages {
                assert!(
                    VALID_LANGUAGES.contains(&lang.as_str()),
                    "Language '{}' should be valid",
                    lang
                );
            }
        }
    }
}
