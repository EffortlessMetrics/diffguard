//! BDD tests for --fail-on behavior.
//!
//! Verifies warn-fail and never-fail policies.

use super::test_repo::TestRepo;

/// Scenario: warn findings fail when --fail-on warn is set.
///
/// Given: A config with a warn-only rule
/// When: Running check with --fail-on warn
/// Then: Exit code is 3 (warn-fail)
#[test]
fn given_warn_findings_when_fail_on_warn_then_exit_3() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "custom.warn"
severity = "warn"
message = "Warn rule"
patterns = ["WARN_ME"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file("src/lib.rs", "WARN_ME\n");
    let head_sha = repo.commit("add warn marker");

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules", "--fail-on", "warn"]);
    result.assert_exit_code(3);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.warn_count(), 1);
    assert_eq!(receipt.error_count(), 0);
}

/// Scenario: errors do not fail when --fail-on never is set.
///
/// Given: A config with an error rule
/// When: Running check with --fail-on never
/// Then: Exit code is 0 even with errors
#[test]
fn given_error_findings_when_fail_on_never_then_exit_0() {
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "custom.error"
severity = "error"
message = "Error rule"
patterns = ["ERROR_ME"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file("src/lib.rs", "ERROR_ME\n");
    let head_sha = repo.commit("add error marker");

    let result = repo.run_check_with_args(&head_sha, &["--no-default-rules", "--fail-on", "never"]);
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(receipt.error_count(), 1);
}
