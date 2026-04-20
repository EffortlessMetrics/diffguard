// Green edge case tests for work-5168d1f9: from_utf8_lossy().into_owned() refactor
// LSP server crate

/// Test that into_owned() produces identical results to to_string() for Cow<str> in LSP context
#[test]
fn test_into_owned_matches_to_string_for_lsp_git_output() {
    // Simulate git diff output (valid UTF-8)
    let git_diff_output = b"diff --git a/src/main.rs b/src/main.rs\nindex abc1234..def5678 100644\n--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1,3 +1,4 @@\n fn main() {\n+    println!(\"Hello\");\n }";
    let cow = String::from_utf8_lossy(git_diff_output);
    let via_into_owned: String = cow.into_owned();
    let cow2 = String::from_utf8_lossy(git_diff_output);
    let via_to_string = cow2.to_string();

    assert_eq!(via_into_owned, via_to_string);
}

#[test]
fn test_into_owned_handles_binary_in_diff() {
    // LSP may receive binary data in diff output (invalid UTF-8)
    // Note: bytes 0x01-0x7F are valid UTF-8 (ASCII range), so we need
    // bytes 0x80-0xBF (continuation bytes without start) or 0xC0-0xFF to be invalid
    let binary_output = b"Binary \x80\x81\xbf\xC0\xFF file content";
    let cow = String::from_utf8_lossy(binary_output);
    let result: String = cow.into_owned();

    // Should contain replacement characters for invalid UTF-8 sequences
    assert!(
        result.contains('\u{FFFD}'),
        "Expected replacement char in: {:?}",
        result
    );
    // Should preserve valid ASCII characters
    assert!(result.contains("Binary"));
    assert!(result.contains("file content"));
}

#[test]
fn test_into_owned_empty_lsp_response() {
    let empty_output = b"";
    let cow = String::from_utf8_lossy(empty_output);
    let result: String = cow.into_owned();
    assert_eq!(result, "");
}

#[test]
fn test_into_owned_unicode_in_diff_paths() {
    // File paths with unicode characters
    let path_output = "diff --git a/src/ファイル.rs b/src/ファイル.rs".as_bytes();
    let cow = String::from_utf8_lossy(path_output);
    let result: String = cow.into_owned();
    assert_eq!(result, "diff --git a/src/ファイル.rs b/src/ファイル.rs");
}

#[test]
fn test_into_owned_preserves_error_messages() {
    // Git error output may contain various characters
    let error_output = b"fatal: not a git repository (or any of the parent directories): .git\nError: repository not found";
    let cow = String::from_utf8_lossy(error_output);
    let result: String = cow.into_owned();
    assert!(result.contains("fatal"));
    assert!(result.contains("Error"));
}
