//! BDD tests for config file loading behavior.
//!
//! Verifies that custom diffguard.toml files are properly loaded and applied.

use super::test_repo::TestRepo;

/// Scenario: Custom config with stricter rules.
///
/// Given: A custom diffguard.toml with a rule that flags "TODO"
/// When: A diff adds a line containing "TODO"
/// Then: The custom rule is applied and a finding is reported
#[test]
fn given_custom_config_when_check_then_custom_rules_applied() {
    // Given: A repository with a custom config
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[defaults]
fail_on = "error"

[[rule]]
id = "custom.no_todo"
severity = "error"
message = "TODOs must be resolved before merging"
patterns = ["\\bTODO\\b"]
paths = ["**/*.rs"]
"#,
    );

    // When: A diff adds a TODO comment
    repo.write_file(
        "src/lib.rs",
        "// TODO: implement this properly\npub fn f() {}\n",
    );
    let head_sha = repo.commit("add TODO");

    // Then: The custom rule triggers
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("custom.no_todo"));
}

/// Scenario: Custom config overrides built-in rules.
///
/// Given: A custom config that overrides rust.no_unwrap to be "warn" instead of "error"
/// When: A diff adds unwrap()
/// Then: The finding has severity "warn" and exit code is 0 (default fail_on=error)
#[test]
fn given_custom_config_overrides_builtin_when_check_then_override_applied() {
    // Given: A custom config that changes unwrap to warning
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[defaults]
fail_on = "error"

[[rule]]
id = "rust.no_unwrap"
severity = "warn"
message = "Prefer ? over unwrap (warning only)"
languages = ["rust"]
patterns = ["\\.unwrap\\("]
paths = ["**/*.rs"]
"#,
    );

    // When: A diff adds unwrap()
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    let head_sha = repo.commit("add unwrap");

    // Then: Finding has warn severity, exit code is 0 (only errors cause exit 2)
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(0); // warn doesn't fail with fail_on=error

    let receipt = result.parse_receipt();
    assert_eq!(receipt.warn_count(), 1);
    assert_eq!(receipt.error_count(), 0);
}

/// Scenario: Config with --no-default-rules flag.
///
/// Given: A custom config with only one rule
/// When: Running with --no-default-rules
/// Then: Only the custom rule is applied, not built-ins
#[test]
fn given_no_default_rules_flag_when_check_then_only_custom_rules() {
    // Given: A custom config with only a custom rule
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "custom.marker"
severity = "warn"
message = "Found marker"
patterns = ["CUSTOM_MARKER"]
paths = ["**/*.rs"]
"#,
    );

    // Add code with unwrap AND the custom marker
    repo.write_file(
        "src/lib.rs",
        "// CUSTOM_MARKER\npub fn f() -> u32 { Some(1).unwrap() }\n",
    );
    let head_sha = repo.commit("add code");

    // When: Running with --no-default-rules
    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);

    let receipt = result.parse_receipt();

    // Then: Only custom rule fires, not the built-in unwrap rule
    assert!(
        receipt.has_finding_with_rule("custom.marker"),
        "Custom rule should fire"
    );
    assert!(
        !receipt.has_finding_with_rule("rust.no_unwrap"),
        "Built-in unwrap rule should NOT fire with --no-default-rules"
    );
}

/// Scenario: Config file at custom path.
///
/// Given: A config file at a non-standard path
/// When: Running with --config pointing to that path
/// Then: The config is loaded and applied
#[test]
fn given_custom_config_path_when_check_then_loaded() {
    // Given: A config at a custom path
    let repo = TestRepo::new();

    repo.write_file(
        "configs/strict.toml",
        r#"
[[rule]]
id = "custom.strict"
severity = "error"
message = "Found STRICT marker"
patterns = ["STRICT_MARKER"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file("src/lib.rs", "// STRICT_MARKER\npub fn f() {}\n");
    let head_sha = repo.commit("add marker");

    // When: Running with --config pointing to custom path and --no-default-rules
    let result = repo.run_check_with_args(
        &head_sha,
        &["--config", "configs/strict.toml", "--no-default-rules"],
    );

    // Then: The custom config is applied
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("custom.strict"));
}

/// Scenario: Default config file is auto-discovered.
///
/// Given: A diffguard.toml in the repo root
/// When: Running without --config flag
/// Then: The config is automatically loaded
#[test]
fn given_default_config_file_when_check_then_auto_loaded() {
    // Given: A diffguard.toml in the repo root
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "auto.discovered"
severity = "error"
message = "Auto-discovered config works"
patterns = ["AUTO_DISCOVERY_TEST"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file("src/lib.rs", "// AUTO_DISCOVERY_TEST\npub fn f() {}\n");
    let head_sha = repo.commit("add test marker");

    // When: Running without --config flag
    let result = repo.run_check(&head_sha);

    // Then: The config is automatically loaded
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_with_rule("auto.discovered"));
}

/// Scenario: Config with path filtering.
///
/// Given: A config that only applies to src/core/**
/// When: Files in src/core and src/utils are changed
/// Then: Only findings in src/core are reported
#[test]
fn given_config_with_path_filter_when_check_then_filter_applied() {
    // Given: A config with path filtering
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "core.no_debug"
severity = "error"
message = "No debug in core"
patterns = ["DEBUG_CALL"]
paths = ["src/core/**/*.rs"]
"#,
    );

    // Add violations in both paths
    repo.write_file("src/core/lib.rs", "// DEBUG_CALL in core\n");
    repo.write_file("src/utils/lib.rs", "// DEBUG_CALL in utils\n");
    let head_sha = repo.commit("add debug calls");

    // When: Running check
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();

    // Then: Only core finding is reported
    assert!(receipt.has_finding_at("src/core/lib.rs", 1));
    assert!(!receipt.has_finding_at("src/utils/lib.rs", 1));
}

/// Scenario: Config with exclude_paths.
///
/// Given: A config that excludes test files
/// When: Test and non-test files have violations
/// Then: Only non-test files are flagged
#[test]
fn given_config_with_exclude_paths_when_check_then_excludes_applied() {
    // Given: A config that excludes tests
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "no.marker"
severity = "error"
message = "Found marker"
patterns = ["MARKER"]
paths = ["**/*.rs"]
exclude_paths = ["**/tests/**"]
"#,
    );

    // Add violations in both paths
    repo.write_file("src/lib.rs", "// MARKER in src\n");
    repo.write_file("src/tests/test_lib.rs", "// MARKER in tests\n");
    let head_sha = repo.commit("add markers");

    // When: Running check
    let result = repo.run_check(&head_sha);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();

    // Then: Only src finding is reported
    assert!(receipt.has_finding_at("src/lib.rs", 1));
    assert!(!receipt.has_finding_at("src/tests/test_lib.rs", 1));
}

/// Scenario: Invalid config file produces error.
///
/// Given: An invalid TOML config file
/// When: diffguard check runs
/// Then: Exit code is 1 (tool error)
#[test]
fn given_invalid_config_when_check_then_tool_error() {
    // Given: An invalid config file
    let repo = TestRepo::new();

    repo.write_config("this is not valid [[[ toml syntax");

    repo.write_file("src/lib.rs", "pub fn f() {}\n");
    let head_sha = repo.commit("add code");

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Exit code is 1 (tool error)
    result.assert_exit_code(1);
}
