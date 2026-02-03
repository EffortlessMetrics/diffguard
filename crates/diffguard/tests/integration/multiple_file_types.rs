//! BDD tests for multiple file types behavior.
//!
//! Verifies that diffguard applies language-specific rules correctly
//! when a diff contains files of different types.

use super::test_repo::TestRepo;

/// Scenario: Diff with .rs, .py, .js files applies correct rules.
///
/// Given: A diff with Rust, Python, and JavaScript files
/// When: Each file has language-specific violations
/// Then: Language-specific rules apply correctly to each
#[test]
fn given_multi_language_diff_when_check_then_language_rules_apply() {
    // Given: A repository
    let repo = TestRepo::new();

    // Add files with language-specific violations
    // Rust: unwrap() -> error
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");

    // Python: print() -> warn
    repo.write_file("src/main.py", "print('debug')\n");

    // JavaScript: console.log() -> warn
    repo.write_file("src/app.js", "console.log('debug');\n");

    let head_sha = repo.commit("add multi-language code");

    // When: Running check with built-in rules
    let result = repo.run_check(&head_sha);

    // Then: Exit code should be 2 (Rust unwrap is error)
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();

    // Verify Rust rule fired
    assert!(
        receipt.has_finding_with_rule("rust.no_unwrap"),
        "Rust unwrap rule should fire"
    );

    // Verify Python rule fired
    assert!(
        receipt.has_finding_with_rule("python.no_print"),
        "Python print rule should fire"
    );

    // Verify JavaScript rule fired
    assert!(
        receipt.has_finding_with_rule("js.no_console"),
        "JavaScript console rule should fire"
    );
}

/// Scenario: Language filter prevents cross-application.
///
/// Given: A Rust file containing "console.log" as a string
/// When: diffguard check runs
/// Then: The js.no_console rule does NOT match (language filter)
#[test]
fn given_rust_file_with_js_pattern_when_check_then_js_rule_not_applied() {
    // Given: A Rust file with a JavaScript-like pattern
    let repo = TestRepo::new();

    repo.write_file(
        "src/lib.rs",
        r#"pub fn explain() -> &'static str {
    "In JavaScript, you would use console.log() for debugging"
}
"#,
    );
    let head_sha = repo.commit("add rust file with js mention");

    // When: Running check
    let result = repo.run_check(&head_sha);

    let receipt = result.parse_receipt();

    // Then: The JS rule should NOT fire on .rs files
    // (It's also in a string, so ignore_strings would mask it,
    // but the language filter is the primary reason)
    assert!(
        !receipt.has_finding_with_rule("js.no_console"),
        "JS console rule should NOT fire on Rust files"
    );
}

/// Scenario: TypeScript files match JavaScript rules.
///
/// Given: A .ts file with console.log
/// When: diffguard check runs
/// Then: The js.no_console rule fires (TypeScript is included)
#[test]
fn given_typescript_file_when_check_then_js_rules_apply() {
    // Given: A TypeScript file
    let repo = TestRepo::new();

    repo.write_file("src/app.ts", "console.log('TypeScript debug');\n");
    let head_sha = repo.commit("add TypeScript file");

    // When: Running check
    let result = repo.run_check(&head_sha);

    let receipt = result.parse_receipt();

    // Then: JS rules fire on .ts files
    assert!(
        receipt.has_finding_with_rule("js.no_console"),
        "JS console rule should fire on TypeScript files"
    );
}

/// Scenario: JSX and TSX files match JavaScript rules.
///
/// Given: .jsx and .tsx files with console.log
/// When: diffguard check runs
/// Then: The js.no_console rule fires on both
#[test]
fn given_jsx_tsx_files_when_check_then_js_rules_apply() {
    // Given: JSX and TSX files
    let repo = TestRepo::new();

    repo.write_file("src/Component.jsx", "console.log('JSX debug');\n");
    repo.write_file("src/App.tsx", "console.log('TSX debug');\n");
    let head_sha = repo.commit("add React files");

    // When: Running check
    let result = repo.run_check(&head_sha);

    let receipt = result.parse_receipt();

    // Then: JS rules fire on .jsx and .tsx
    let rule_ids = receipt.finding_rule_ids();
    let console_findings: Vec<_> = rule_ids
        .iter()
        .filter(|id| *id == "js.no_console")
        .collect();

    assert_eq!(
        console_findings.len(),
        2,
        "Should have 2 console.log findings (jsx + tsx)"
    );
}

/// Scenario: Go files match Go rules.
///
/// Given: A .go file with fmt.Println
/// When: diffguard check runs
/// Then: The go.no_fmt_print rule fires
#[test]
fn given_go_file_when_check_then_go_rules_apply() {
    // Given: A Go file
    let repo = TestRepo::new();

    repo.write_file(
        "src/main.go",
        r#"package main

import "fmt"

func main() {
    fmt.Println("debug")
}
"#,
    );
    let head_sha = repo.commit("add Go file");

    // When: Running check
    let result = repo.run_check(&head_sha);

    let receipt = result.parse_receipt();

    // Then: Go rules fire
    assert!(
        receipt.has_finding_with_rule("go.no_fmt_print"),
        "Go fmt.Println rule should fire"
    );
}

/// Scenario: Unknown file extension uses catch-all rules.
///
/// Given: A config with a rule that has no language filter
/// When: A file with unknown extension is added
/// Then: The catch-all rule applies
#[test]
fn given_unknown_extension_when_check_then_catchall_rules_apply() {
    // Given: A config with a catch-all rule
    let repo = TestRepo::new();

    repo.write_config(
        r#"
[[rule]]
id = "all.no_fixme"
severity = "warn"
message = "Resolve FIXMEs before merging"
patterns = ["\\bFIXME\\b"]
# No languages filter = applies to all
paths = ["**/*"]
"#,
    );

    // Add a file with unknown extension
    repo.write_file("notes.txt", "FIXME: review this\n");
    repo.write_file("src/lib.rs", "// FIXME: implement\n");
    let head_sha = repo.commit("add FIXME comments");

    // When: Running check
    let result = repo.run_check(&head_sha);

    let receipt = result.parse_receipt();

    // Then: Both files match the catch-all rule
    assert!(
        receipt.has_finding_at("notes.txt", 1),
        "FIXME in .txt should be flagged"
    );
    assert!(
        receipt.has_finding_at("src/lib.rs", 1),
        "FIXME in .rs should be flagged"
    );
}

/// Scenario: Python debugger statements are detected.
///
/// Given: A Python file with pdb usage
/// When: diffguard check runs
/// Then: The python.no_pdb rule fires (error severity)
#[test]
fn given_python_pdb_when_check_then_error() {
    // Given: A Python file with debugger
    let repo = TestRepo::new();

    repo.write_file(
        "src/debug.py",
        r#"import pdb
pdb.set_trace()
"#,
    );
    let head_sha = repo.commit("add Python debugger");

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Exit code 2 (error)
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(
        receipt.has_finding_with_rule("python.no_pdb"),
        "Python pdb rule should fire"
    );
}

/// Scenario: JavaScript debugger statement is detected.
///
/// Given: A JavaScript file with debugger statement
/// When: diffguard check runs
/// Then: The js.no_debugger rule fires (error severity)
#[test]
fn given_js_debugger_when_check_then_error() {
    // Given: A JavaScript file with debugger
    let repo = TestRepo::new();

    repo.write_file(
        "src/app.js",
        r#"function buggy() {
    debugger;
    return 42;
}
"#,
    );
    let head_sha = repo.commit("add JS debugger");

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Exit code 2 (error)
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(
        receipt.has_finding_with_rule("js.no_debugger"),
        "JS debugger rule should fire"
    );
}

/// Scenario: Files in test directories are excluded by default.
///
/// Given: Built-in rules exclude **/tests/**
/// When: A test file has violations
/// Then: No findings are reported for test files
#[test]
fn given_test_file_when_check_then_excluded_by_default() {
    // Given: A test file with violations
    let repo = TestRepo::new();

    // Built-in rust.no_unwrap excludes **/tests/**
    repo.write_file("src/tests/test_lib.rs", "fn test() { Some(1).unwrap(); }\n");
    let head_sha = repo.commit("add test file with unwrap");

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: No findings (test files are excluded)
    result.assert_exit_code(0);

    let receipt = result.parse_receipt();
    assert_eq!(
        receipt.findings_count(),
        0,
        "Test files should be excluded from unwrap rule"
    );
}

/// Scenario: Mixed findings across languages have correct severities.
///
/// Given: Rust error + Python warning + JS warning
/// When: diffguard check runs
/// Then: Counts correctly reflect 1 error and 2 warnings
#[test]
fn given_mixed_severities_across_languages_when_check_then_correct_counts() {
    // Given: Files with different severity violations
    let repo = TestRepo::new();

    // Rust unwrap = error
    repo.write_file("src/lib.rs", "pub fn f() -> u32 { Some(1).unwrap() }\n");
    // Python print = warn
    repo.write_file("src/main.py", "print('debug')\n");
    // JS console.log = warn
    repo.write_file("src/app.js", "console.log('debug');\n");

    let head_sha = repo.commit("add mixed violations");

    // When: Running check
    let result = repo.run_check(&head_sha);

    // Then: Exit code 2 (errors present)
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert_eq!(
        receipt.error_count(),
        1,
        "Should have 1 error (Rust unwrap)"
    );
    assert_eq!(
        receipt.warn_count(),
        2,
        "Should have 2 warnings (Python print + JS console)"
    );
}
