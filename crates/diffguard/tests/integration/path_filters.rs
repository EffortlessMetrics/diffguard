//! BDD tests for CLI --paths filtering.
//!
//! Verifies that diffguard only scans files matching the provided glob filters.

use super::test_repo::TestRepo;

/// Scenario: --paths restricts scanning to matching files.
///
/// Given: Two files with violations
/// When: Running check with --paths matching only one file
/// Then: Only the matching file produces findings
#[test]
fn given_paths_filter_when_check_then_only_matching_files_scanned() {
    let repo = TestRepo::new();

    repo.write_file(
        "src/keep.rs",
        "pub fn keep() -> u32 { Some(1).unwrap() }\n",
    );
    repo.write_file(
        "src/skip.rs",
        "pub fn skip() -> u32 { Some(2).unwrap() }\n",
    );
    let head_sha = repo.commit("add two violations");

    let result = repo.run_check_with_args(&head_sha, &["--paths", "src/keep.rs"]);
    result.assert_exit_code(2);

    let receipt = result.parse_receipt();
    assert!(receipt.has_finding_at("src/keep.rs", 1));
    assert!(!receipt.has_finding_at("src/skip.rs", 1));
    assert_eq!(receipt.findings_count(), 1);
}
