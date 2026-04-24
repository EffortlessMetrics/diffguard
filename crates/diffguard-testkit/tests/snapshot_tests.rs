//! Snapshot tests for diffguard-testkit outputs.
//!
//! These tests capture the current output format of key functions so that
//! any changes to the output format are detected immediately.
//!
//! The primary concern with this crate is that `MatchMode::default()` (which
//! equals `MatchMode::Any`) is correctly serialized in ConfigFile JSON.
//!
//! NOTE: MatchMode::Any is the default and is skip_serialized when serializing
//! to JSON because it's the implicit default. This is intentional - users don't
//! need to specify `match_mode: any` explicitly.

use diffguard_testkit::diff_builder::DiffBuilder;
use diffguard_testkit::fixtures::{sample_configs, sample_diffs};
use insta::assert_json_snapshot;

// =============================================================================
// ConfigFile JSON serialization snapshots
// =============================================================================

#[test]
fn snapshot_empty_config_json() {
    let config = sample_configs::empty();
    let json = serde_json::to_value(&config).expect("should serialize");
    assert_json_snapshot!("empty_config", json);
}

#[test]
fn snapshot_minimal_config_json() {
    let config = sample_configs::minimal();
    let json = serde_json::to_value(&config).expect("should serialize");
    // match_mode is skip_serialized when it's the default (MatchMode::Any)
    assert_json_snapshot!("minimal_config", json);
}

#[test]
fn snapshot_rust_focused_config_json() {
    let config = sample_configs::rust_focused();
    let json = serde_json::to_value(&config).expect("should serialize");
    // match_mode is skip_serialized when it's the default (MatchMode::Any)
    assert_json_snapshot!("rust_focused_config", json);
}

#[test]
fn snapshot_javascript_focused_config_json() {
    let config = sample_configs::javascript_focused();
    let json = serde_json::to_value(&config).expect("should serialize");
    assert_json_snapshot!("javascript_focused_config", json);
}

#[test]
fn snapshot_python_focused_config_json() {
    let config = sample_configs::python_focused();
    let json = serde_json::to_value(&config).expect("should serialize");
    assert_json_snapshot!("python_focused_config", json);
}

#[test]
fn snapshot_multi_language_config_json() {
    let config = sample_configs::multi_language();
    let json = serde_json::to_value(&config).expect("should serialize");
    assert_json_snapshot!("multi_language_config", json);
}

#[test]
fn snapshot_all_severities_config_json() {
    let config = sample_configs::all_severities();
    let json = serde_json::to_value(&config).expect("should serialize");
    assert_json_snapshot!("all_severities_config", json);
}

// =============================================================================
// Sample diff string snapshots
// =============================================================================

#[test]
fn snapshot_simple_addition_diff() {
    let diff = sample_diffs::simple_addition();
    assert_json_snapshot!("simple_addition_diff", diff);
}

#[test]
fn snapshot_simple_change_diff() {
    let diff = sample_diffs::simple_change();
    assert_json_snapshot!("simple_change_diff", diff);
}

#[test]
fn snapshot_multiple_files_diff() {
    let diff = sample_diffs::multiple_files();
    assert_json_snapshot!("multiple_files_diff", diff);
}

#[test]
fn snapshot_multiple_hunks_diff() {
    let diff = sample_diffs::multiple_hunks();
    assert_json_snapshot!("multiple_hunks_diff", diff);
}

#[test]
fn snapshot_binary_file_diff() {
    let diff = sample_diffs::binary_file();
    assert_json_snapshot!("binary_file_diff", diff);
}

#[test]
fn snapshot_deleted_file_diff() {
    let diff = sample_diffs::deleted_file();
    assert_json_snapshot!("deleted_file_diff", diff);
}

#[test]
fn snapshot_renamed_file_diff() {
    let diff = sample_diffs::renamed_file();
    assert_json_snapshot!("renamed_file_diff", diff);
}

// =============================================================================
// DiffBuilder output snapshots
// =============================================================================

#[test]
fn snapshot_diff_builder_simple_addition() {
    let diff = DiffBuilder::new()
        .file("src/lib.rs")
        .hunk(1, 1, 1, 2)
        .context("fn existing() {}")
        .add_line("fn new_function() {}")
        .done()
        .done()
        .build();
    assert_json_snapshot!("diff_builder_simple_addition", diff);
}

#[test]
fn snapshot_diff_builder_multiple_hunks() {
    let diff = DiffBuilder::new()
        .file("src/lib.rs")
        .hunk(1, 1, 1, 2)
        .context("fn first() {}")
        .add_line("fn after_first() {}")
        .done()
        .hunk(10, 1, 10, 2)
        .context("fn tenth() {}")
        .add_line("fn after_tenth() {}")
        .done()
        .done()
        .build();
    assert_json_snapshot!("diff_builder_multiple_hunks", diff);
}

#[test]
fn snapshot_diff_builder_with_changes() {
    let diff = DiffBuilder::new()
        .file("src/lib.rs")
        .hunk(1, 1, 1, 1)
        .remove("fn old_function() {}")
        .add_line("fn new_function() {}")
        .done()
        .done()
        .build();
    assert_json_snapshot!("diff_builder_with_changes", diff);
}

// =============================================================================
// Schema validation snapshots
// =============================================================================

#[test]
fn snapshot_schema_validation_error_format() {
    // Create an invalid config that will fail validation
    use serde_json::json;

    // This config is missing required fields
    let invalid_json = json!({
        "includes": [],
        "defaults": {},
        "rule": [{
            "id": "bad.rule",
            // missing required fields
        }]
    });

    let result = diffguard_testkit::schema::validate_config_json(&invalid_json);
    let error_msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => "unexpected success".to_string(),
    };

    // Just verify the error format contains expected text
    assert!(
        error_msg.contains("Schema validation failed"),
        "Error message should contain 'Schema validation failed'"
    );
}

// =============================================================================
// MatchMode::default() serialization verification
//
// NOTE: MatchMode::Any is the default and is skip_serialized in JSON because
// it's the implicit default. When a user doesn't specify match_mode, it
// defaults to Any implicitly.
// =============================================================================

#[test]
fn verify_match_mode_default_serializes_to_any() {
    use diffguard_types::MatchMode;
    use serde_json::json;

    let match_mode = MatchMode::default();
    let json_val = serde_json::to_value(match_mode).expect("should serialize");

    // MatchMode::default() = MatchMode::Any which serializes to "any" (lowercase)
    assert_eq!(
        json_val,
        json!("any"),
        "MatchMode::default() should serialize to 'any'"
    );
}

#[test]
fn verify_match_mode_absent_serializes_correctly() {
    use diffguard_types::MatchMode;
    use serde_json::json;

    let match_mode = MatchMode::Absent;
    let json_val = serde_json::to_value(match_mode).expect("should serialize");

    // MatchMode::Absent should serialize to "absent"
    assert_eq!(
        json_val,
        json!("absent"),
        "MatchMode::Absent should serialize to 'absent'"
    );
}

#[test]
fn verify_minimal_config_skips_match_mode_when_default() {
    // When match_mode is the default (MatchMode::Any), it is skip_serialized
    // This is intentional - the default doesn't need to be explicitly specified
    let config = sample_configs::minimal();
    let json_val = serde_json::to_value(&config).expect("should serialize");

    // The match_mode field should NOT be present because it's the default
    let rule = &json_val["rule"][0];
    assert!(
        rule.get("match_mode").is_none(),
        "match_mode should be skip_serialized when it's the default (MatchMode::Any)"
    );
}

#[test]
fn verify_explicit_match_mode_in_config() {
    // Create a config with explicit MatchMode::Absent to verify it serializes
    use diffguard_types::{ConfigFile, MatchMode, RuleConfig, Severity};
    use serde_json::json;

    let config = ConfigFile {
        includes: vec![],
        defaults: diffguard_types::Defaults::default(),
        rule: vec![RuleConfig {
            id: "test.rule".to_string(),
            severity: Severity::Warn,
            message: "Test rule".to_string(),
            description: String::new(),
            languages: vec![],
            patterns: vec!["test".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: MatchMode::Absent, // Explicitly set to Absent
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        }],
    };

    let json_val = serde_json::to_value(&config).expect("should serialize");
    let match_mode = &json_val["rule"][0]["match_mode"];

    // When explicitly set to Absent, it should serialize as "absent"
    assert_eq!(
        match_mode,
        &json!("absent"),
        "Explicit match_mode: Absent should serialize as 'absent'"
    );
}
