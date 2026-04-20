//! Integration tests for Checkstyle XML output via CLI.
//!
//! These tests verify that the Checkstyle output correctly maps severity levels
//! and that the CLI correctly writes the checkstyle file when requested.

use super::test_repo::{DiffguardResult, TestRepo};

// =============================================================================
// Checkstyle Severity Mapping Integration Tests
// =============================================================================

/// Helper to run diffguard check with checkstyle output enabled.
#[allow(dead_code)]
fn run_check_with_checkstyle(
    head_sha: &str,
    extra_args: &[&str],
) -> (TestRepo, DiffguardResult, String) {
    let repo = TestRepo::new();
    let checkstyle_path = "artifacts/diffguard/report.checkstyle.xml";

    let mut cmd = assert_cmd::Command::cargo_bin("diffguard").expect("diffguard binary");
    cmd.current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(&repo.base_sha)
        .arg("--head")
        .arg(head_sha)
        .arg("--checkstyle")
        .arg(checkstyle_path);

    for arg in extra_args {
        cmd.arg(arg);
    }

    let output = cmd.output().expect("run diffguard");
    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let checkstyle_content = if std::path::Path::new(repo.path())
        .join(checkstyle_path)
        .exists()
    {
        std::fs::read_to_string(repo.path().join(checkstyle_path)).expect("read checkstyle")
    } else {
        String::new()
    };

    let result = DiffguardResult {
        exit_code,
        stdout,
        stderr,
        receipt: None,
        output_path: repo.path().join("artifacts/diffguard/report.json"),
    };

    (repo, result, checkstyle_content)
}

/// Helper to run diffguard check with checkstyle and receipt output.
#[allow(dead_code)]
fn run_check_with_checkstyle_and_receipt(
    head_sha: &str,
    config: &str,
) -> (TestRepo, DiffguardResult, String, String) {
    let repo = TestRepo::new();
    repo.write_config(config);
    let checkstyle_path = "artifacts/diffguard/report.checkstyle.xml";
    let receipt_path = "artifacts/diffguard/report.json";

    let mut cmd = assert_cmd::Command::cargo_bin("diffguard").expect("diffguard binary");
    cmd.current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(&repo.base_sha)
        .arg("--head")
        .arg(head_sha)
        .arg("--checkstyle")
        .arg(checkstyle_path)
        .arg("--out")
        .arg(receipt_path);

    let output = cmd.output().expect("run diffguard");
    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let checkstyle_content =
        std::fs::read_to_string(repo.path().join(checkstyle_path)).expect("read checkstyle");
    let receipt_content =
        std::fs::read_to_string(repo.path().join(receipt_path)).expect("read receipt");

    let result = DiffguardResult {
        exit_code,
        stdout,
        stderr,
        receipt: Some(receipt_content.clone()),
        output_path: repo.path().join(receipt_path),
    };

    (repo, result, checkstyle_content, receipt_content)
}

// =============================================================================
// Test Scenarios
// =============================================================================

/// Scenario: Info severity findings produce severity="info" in Checkstyle XML.
///
/// Given: A rule with severity = "info" that matches content in the diff
/// When: diffguard check is run with --checkstyle flag
/// Then: The generated Checkstyle XML contains severity="info" (not "warning")
#[test]
fn given_info_severity_finding_when_check_then_checkstyle_has_severity_info() {
    let repo = TestRepo::new();
    let checkstyle_path = "artifacts/diffguard/report.checkstyle.xml";

    // Write a config with an info-severity rule
    repo.write_config(
        r#"
[[rule]]
id = "test.todo_comment"
severity = "info"
message = "TODO comment found"
patterns = ["TODO"]
paths = ["**/*.rs"]
"#,
    );

    // Create a commit with TODO content
    repo.write_file(
        "src/lib.rs",
        "// TODO: refactor this later\npub fn f() {}\n",
    );
    let head_sha = repo.commit("add todo comment");

    let mut cmd = assert_cmd::Command::cargo_bin("diffguard").expect("diffguard binary");
    cmd.current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(&repo.base_sha)
        .arg("--head")
        .arg(&head_sha)
        .arg("--checkstyle")
        .arg(checkstyle_path)
        .arg("--no-default-rules"); // Disable built-in rules to test only custom rule

    let output = cmd.output().expect("run diffguard");
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "checkstyle info test should pass"
    );

    let checkstyle =
        std::fs::read_to_string(repo.path().join(checkstyle_path)).expect("read checkstyle");

    // Debug: print the checkstyle output if test fails
    if checkstyle.contains(r#"severity="warning""#) {
        eprintln!("DEBUG: Checkstyle output:\n{}", checkstyle);
    }

    // Info should map to "info" in Checkstyle
    assert!(
        checkstyle.contains(r#"severity="info""#),
        "Checkstyle XML should contain severity=\"info\", but got:\n{}",
        checkstyle
    );
    assert!(
        !checkstyle.contains(r#"severity="warning""#),
        "Checkstyle XML should NOT contain severity=\"warning\" for info findings, but got:\n{}",
        checkstyle
    );
}

/// Scenario: Warning severity findings produce severity="warning" in Checkstyle XML.
///
/// Given: A rule with severity = "warn" that matches content in the diff
/// When: diffguard check is run with --checkstyle flag
/// Then: The generated Checkstyle XML contains severity="warning"
#[test]
fn given_warn_severity_finding_when_check_then_checkstyle_has_severity_warning() {
    let repo = TestRepo::new();
    let checkstyle_path = "artifacts/diffguard/report.checkstyle.xml";

    // Write a config with a warn-severity rule
    repo.write_config(
        r#"
[[rule]]
id = "test.print_statement"
severity = "warn"
message = "Print statement detected"
patterns = ["println!"]
paths = ["**/*.rs"]
"#,
    );

    // Create a commit with println
    repo.write_file("src/lib.rs", "pub fn f() { println!(\"hello\"); }\n");
    let head_sha = repo.commit("add print statement");

    let mut cmd = assert_cmd::Command::cargo_bin("diffguard").expect("diffguard binary");
    cmd.current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(&repo.base_sha)
        .arg("--head")
        .arg(&head_sha)
        .arg("--checkstyle")
        .arg(checkstyle_path);

    let output = cmd.output().expect("run diffguard");
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "checkstyle warn test should pass"
    );

    let checkstyle =
        std::fs::read_to_string(repo.path().join(checkstyle_path)).expect("read checkstyle");

    // Warn should map to "warning" in Checkstyle
    assert!(
        checkstyle.contains(r#"severity="warning""#),
        "Checkstyle XML should contain severity=\"warning\", but got:\n{}",
        checkstyle
    );
}

/// Scenario: Error severity findings produce severity="error" in Checkstyle XML.
///
/// Given: A rule with severity = "error" that matches content in the diff
/// When: diffguard check is run with --checkstyle flag
/// Then: The generated Checkstyle XML contains severity="error"
#[test]
fn given_error_severity_finding_when_check_then_checkstyle_has_severity_error() {
    let repo = TestRepo::new();
    let checkstyle_path = "artifacts/diffguard/report.checkstyle.xml";

    // Write a config with an error-severity rule
    repo.write_config(
        r#"
[[rule]]
id = "test.no_unwrap"
severity = "error"
message = "unwrap() call detected"
patterns = [".unwrap()"]
paths = ["**/*.rs"]
"#,
    );

    // Create a commit with unwrap
    repo.write_file(
        "src/lib.rs",
        "pub fn f() -> Option<u32> { Some(1).unwrap() }\n",
    );
    let head_sha = repo.commit("add unwrap");

    let mut cmd = assert_cmd::Command::cargo_bin("diffguard").expect("diffguard binary");
    cmd.current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(&repo.base_sha)
        .arg("--head")
        .arg(&head_sha)
        .arg("--checkstyle")
        .arg(checkstyle_path);

    let output = cmd.output().expect("run diffguard");
    // Error findings should cause exit code 2 (policy fail)
    assert_eq!(
        output.status.code().unwrap_or(-1),
        2,
        "error findings should cause fail"
    );

    let checkstyle =
        std::fs::read_to_string(repo.path().join(checkstyle_path)).expect("read checkstyle");

    // Error should map to "error" in Checkstyle
    assert!(
        checkstyle.contains(r#"severity="error""#),
        "Checkstyle XML should contain severity=\"error\", but got:\n{}",
        checkstyle
    );
}

/// Scenario: Mixed severity findings produce correct severity strings in Checkstyle.
///
/// Given: Rules with different severity levels that all match content in the diff
/// When: diffguard check is run with --checkstyle flag
/// Then: Each finding has the correct severity attribute in the Checkstyle XML
#[test]
fn given_mixed_severity_findings_when_check_then_each_has_correct_severity() {
    let repo = TestRepo::new();
    let checkstyle_path = "artifacts/diffguard/report.checkstyle.xml";

    // Write a config with multiple rules of different severities
    repo.write_config(
        r#"
[[rule]]
id = "test.info_rule"
severity = "info"
message = "Info message"
patterns = ["INFO_MARKER"]
paths = ["**/*.rs"]

[[rule]]
id = "test.warn_rule"
severity = "warn"
message = "Warn message"
patterns = ["WARN_MARKER"]
paths = ["**/*.rs"]

[[rule]]
id = "test.error_rule"
severity = "error"
message = "Error message"
patterns = ["ERROR_MARKER"]
paths = ["**/*.rs"]
"#,
    );

    // Create a commit with content that triggers all three rules
    repo.write_file(
        "src/lib.rs",
        "// INFO_MARKER here\n// WARN_MARKER here\n// ERROR_MARKER here\npub fn f() {}\n",
    );
    let head_sha = repo.commit("add markers");

    let mut cmd = assert_cmd::Command::cargo_bin("diffguard").expect("diffguard binary");
    cmd.current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(&repo.base_sha)
        .arg("--head")
        .arg(&head_sha)
        .arg("--checkstyle")
        .arg(checkstyle_path);

    let output = cmd.output().expect("run diffguard");
    // With error findings, exit code should be 2
    assert_eq!(
        output.status.code().unwrap_or(-1),
        2,
        "error findings should cause fail"
    );

    let checkstyle =
        std::fs::read_to_string(repo.path().join(checkstyle_path)).expect("read checkstyle");

    // All three severity levels should be present with correct values
    assert!(
        checkstyle.contains(r#"severity="info""#),
        "Checkstyle should contain severity=\"info\", got:\n{}",
        checkstyle
    );
    assert!(
        checkstyle.contains(r#"severity="warning""#),
        "Checkstyle should contain severity=\"warning\", got:\n{}",
        checkstyle
    );
    assert!(
        checkstyle.contains(r#"severity="error""#),
        "Checkstyle should contain severity=\"error\", got:\n{}",
        checkstyle
    );

    // Verify info is NOT confused with warning
    // The info finding should have source="test.info_rule" and severity="info"
    assert!(
        checkstyle.contains(r#"source="test.info_rule""#),
        "Checkstyle should contain source=\"test.info_rule\""
    );
}

/// Scenario: Checkstyle XML is well-formed with proper structure.
///
/// Given: A valid diff with findings
/// When: diffguard check is run with --checkstyle flag
/// Then: The generated XML has proper XML declaration and closing tags
#[test]
fn given_findings_when_checkstyle_generated_then_xml_is_well_formed() {
    let repo = TestRepo::new();
    let checkstyle_path = "artifacts/diffguard/report.checkstyle.xml";

    repo.write_config(
        r#"
[[rule]]
id = "test.rule"
severity = "error"
message = "Test finding"
patterns = ["TEST_FINDING"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file("src/lib.rs", "// TEST_FINDING\npub fn f() {}\n");
    let head_sha = repo.commit("add test finding");

    let mut cmd = assert_cmd::Command::cargo_bin("diffguard").expect("diffguard binary");
    cmd.current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(&repo.base_sha)
        .arg("--head")
        .arg(&head_sha)
        .arg("--checkstyle")
        .arg(checkstyle_path);

    let output = cmd.output().expect("run diffguard");
    assert_eq!(output.status.code().unwrap_or(-1), 2);

    let checkstyle =
        std::fs::read_to_string(repo.path().join(checkstyle_path)).expect("read checkstyle");

    // Verify XML structure
    assert!(
        checkstyle.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
        "Checkstyle should start with XML declaration"
    );
    assert!(
        checkstyle.contains("<checkstyle version=\"5.0\">"),
        "Checkstyle should contain root element"
    );
    assert!(
        checkstyle.contains("</checkstyle>"),
        "Checkstyle should close root element"
    );
    assert!(
        checkstyle.contains("<file name="),
        "Checkstyle should contain file elements"
    );
    assert!(
        checkstyle.contains("<error"),
        "Checkstyle should contain error elements"
    );
}

/// Scenario: Checkstyle output is created even when no findings (empty output).
///
/// Given: A clean diff with no policy violations
/// When: diffguard check is run with --checkstyle flag
/// Then: The checkstyle file is created with valid XML structure (no findings)
#[test]
fn given_no_findings_when_checkstyle_generated_then_file_is_created_with_structure() {
    let repo = TestRepo::new();
    let checkstyle_path = "artifacts/diffguard/report.checkstyle.xml";

    // Use a rule that won't match anything
    repo.write_config(
        r#"
[[rule]]
id = "test.rule"
severity = "error"
message = "Should not match"
patterns = ["THIS_WILL_NOT_MATCH_ANYTHING"]
paths = ["**/*.rs"]
"#,
    );

    // Clean commit that won't trigger any rules
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { 42 }\n");
    let head_sha = repo.commit("clean commit");

    let mut cmd = assert_cmd::Command::cargo_bin("diffguard").expect("diffguard binary");
    cmd.current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(&repo.base_sha)
        .arg("--head")
        .arg(&head_sha)
        .arg("--checkstyle")
        .arg(checkstyle_path);

    let output = cmd.output().expect("run diffguard");
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "clean diff should exit 0"
    );

    // File should exist
    assert!(
        repo.path().join(checkstyle_path).exists(),
        "checkstyle file should be created even with no findings"
    );

    let checkstyle =
        std::fs::read_to_string(repo.path().join(checkstyle_path)).expect("read checkstyle");

    // Should still have valid XML structure
    assert!(
        checkstyle.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
        "Checkstyle should have XML declaration"
    );
    assert!(
        checkstyle.contains("<checkstyle version=\"5.0\">"),
        "Checkstyle should have root element"
    );
    assert!(
        checkstyle.contains("</checkstyle>"),
        "Checkstyle should close root element"
    );
    // No <error> elements should be present when there are no findings
    assert!(
        !checkstyle.contains("<error"),
        "Checkstyle should not contain error elements when no findings"
    );
}

/// Scenario: Checkstyle output uses correct XML escaping for special characters.
///
/// Given: A finding with special characters in message or path
/// When: diffguard check is run with --checkstyle flag
/// Then: Special characters are properly XML-escaped in the output
#[test]
fn given_finding_with_special_chars_when_checkstyle_generated_then_chars_are_escaped() {
    let repo = TestRepo::new();
    let checkstyle_path = "artifacts/diffguard/report.checkstyle.xml";

    // Rule with special characters in ID
    repo.write_config(
        r#"
[[rule]]
id = "test.rule<>&\"'"
severity = "error"
message = "Message with <brackets> & \"quotes\""
patterns = ["SPECIAL"]
paths = ["**/*.rs"]
"#,
    );

    repo.write_file("src/lib.rs", "// SPECIAL content\npub fn f() {}\n");
    let head_sha = repo.commit("add special chars");

    let mut cmd = assert_cmd::Command::cargo_bin("diffguard").expect("diffguard binary");
    cmd.current_dir(repo.path())
        .arg("check")
        .arg("--base")
        .arg(&repo.base_sha)
        .arg("--head")
        .arg(&head_sha)
        .arg("--checkstyle")
        .arg(checkstyle_path);

    let output = cmd.output().expect("run diffguard");
    assert_eq!(output.status.code().unwrap_or(-1), 2);

    let checkstyle =
        std::fs::read_to_string(repo.path().join(checkstyle_path)).expect("read checkstyle");

    // Verify XML escaping is applied
    assert!(
        checkstyle.contains("&lt;"),
        "Checkstyle should escape < as &lt;"
    );
    assert!(
        checkstyle.contains("&gt;"),
        "Checkstyle should escape > as &gt;"
    );
    assert!(
        checkstyle.contains("&amp;"),
        "Checkstyle should escape & as &amp;"
    );
    assert!(
        checkstyle.contains("&quot;"),
        "Checkstyle should escape \" as &quot;"
    );
    assert!(
        checkstyle.contains("&apos;"),
        "Checkstyle should escape ' as &apos;"
    );

    // Verify unescaped characters do not appear
    assert!(
        !checkstyle.contains(" <brackets>"),
        "Unescaped <brackets> should not appear"
    );
    assert!(
        !checkstyle.contains(" test.rule<>&"),
        "Unescaped rule ID should not appear"
    );
}
