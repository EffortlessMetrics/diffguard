//! BDD tests for per-directory `.diffguard.toml` overrides.

use super::test_repo::TestRepo;

/// Scenario: A directory override disables a rule in that subtree.
#[test]
fn given_directory_rule_disable_when_check_then_subtree_is_skipped() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "custom.no_unwrap"
severity = "error"
message = "No unwrap"
patterns = ["\\.unwrap\\("]
paths = ["**/*.rs"]
ignore_comments = true
ignore_strings = true
"#,
    );

    repo.write_file(
        "src/generated/.diffguard.toml",
        r#"
[[rule]]
id = "custom.no_unwrap"
enabled = false
"#,
    );

    repo.write_file("src/lib.rs", "pub fn a() { let _ = Some(1).unwrap(); }\n");
    repo.write_file(
        "src/generated/lib.rs",
        "pub fn b() { let _ = Some(2).unwrap(); }\n",
    );
    let head_sha = repo.commit("add unwraps with generated override");

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_at("src/lib.rs", 1));
    assert!(!receipt.has_finding_at("src/generated/lib.rs", 1));
    assert_eq!(receipt.error_count(), 1);
}

/// Scenario: A directory override changes severity for that subtree.
#[test]
fn given_directory_severity_override_when_check_then_effective_severity_changes() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[defaults]
fail_on = "warn"

[[rule]]
id = "custom.no_unwrap"
severity = "error"
message = "No unwrap"
patterns = ["\\.unwrap\\("]
paths = ["**/*.rs"]
ignore_comments = true
ignore_strings = true
"#,
    );

    repo.write_file(
        "src/legacy/.diffguard.toml",
        r#"
[[rule]]
id = "custom.no_unwrap"
severity = "warn"
"#,
    );

    repo.write_file(
        "src/legacy/lib.rs",
        "pub fn legacy() { let _ = Some(1).unwrap(); }\n",
    );
    let head_sha = repo.commit("legacy unwrap");

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(3);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_at("src/legacy/lib.rs", 1));
    assert_eq!(receipt.warn_count(), 1);
    assert_eq!(receipt.error_count(), 0);
}

/// Scenario: Child overrides can re-enable rules disabled by a parent override.
#[test]
fn given_parent_disable_and_child_enable_when_check_then_child_override_wins() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[defaults]
fail_on = "warn"

[[rule]]
id = "custom.no_unwrap"
severity = "error"
message = "No unwrap"
patterns = ["\\.unwrap\\("]
paths = ["**/*.rs"]
ignore_comments = true
ignore_strings = true
"#,
    );

    repo.write_file(
        ".diffguard.toml",
        r#"
[[rule]]
id = "custom.no_unwrap"
enabled = false
"#,
    );

    repo.write_file(
        "src/legacy/.diffguard.toml",
        r#"
[[rule]]
id = "custom.no_unwrap"
enabled = true
severity = "warn"
"#,
    );

    repo.write_file(
        "src/new/lib.rs",
        "pub fn new_fn() { let _ = Some(1).unwrap(); }\n",
    );
    repo.write_file(
        "src/legacy/lib.rs",
        "pub fn legacy_fn() { let _ = Some(2).unwrap(); }\n",
    );
    let head_sha = repo.commit("parent disable child enable");

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules"]);
    result.assert_exit_code(3);

    let receipt = result.parse_receipt();
    assert!(!receipt.has_finding_at("src/new/lib.rs", 1));
    assert!(receipt.has_finding_at("src/legacy/lib.rs", 1));
    assert_eq!(receipt.warn_count(), 1);
    assert_eq!(receipt.error_count(), 0);
}
