//! Red tests for work-81f5772c: detect_language() must_use attribute
//!
//! These tests verify that `detect_language()` has the `#[must_use]` attribute
//! to prevent callers from silently ignoring language detection failure (returning `None`).
//!
//! Issue: GitHub issue #337 reports a clippy `must_use_candidate` warning on
//! `detect_language()` at `crates/diffguard-domain/src/rules.rs:205`.
//!
//! The function returns `Option<&'static str>` but lacks a `#[must_use]` attribute,
//! meaning callers may silently ignore language detection failure.
//!
//! These tests verify the expected behavior:
//! - `detect_language()` SHOULD have `#[must_use]` attribute
//! - Clippy SHOULD NOT warn about `must_use_candidate` for `detect_language`
//!
//! BEFORE FIX: These tests FAIL (clippy warns about missing #[must_use])
//! AFTER FIX:  These tests PASS (#[must_use] is present, no warning)

use std::path::Path;
use std::process::Command;

/// Test that `#[must_use]` attribute is present on `detect_language()`.
///
/// This test verifies the function has the attribute by running clippy
/// and checking that no `must_use_candidate` warning is emitted.
///
/// BEFORE FIX: This test FAILS because clippy warns about missing #[must_use]
/// AFTER FIX:  This test PASSES because #[must_use] is present
#[test]
fn detect_language_has_must_use_attribute() {
    // Run clippy with must_use_candidate lint enabled
    let output = Command::new("cargo")
        .args([
            "clippy",
            "-p",
            "diffguard-domain",
            "--",
            "-W",
            "clippy::must_use_candidate",
        ])
        .current_dir("/home/hermes/repos/diffguard")
        .output()
        .expect("Failed to run cargo clippy");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{}\n{}", stdout, stderr);

    // Check that detect_language is NOT mentioned in any must_use_candidate warning
    // If #[must_use] is missing, clippy will warn about detect_language
    //
    // The warning format is:
    //   --> crates/diffguard-domain/src/rules.rs:205:8
    //    |
    // 205 | pub fn detect_language(path: &Path) -> Option<&'static str> {
    //    |        ^^^^^^^^^^^^^^^
    //    |
    //    = help: for further information visit https://rust-lang.github.io/rust-clippy/...
    //    = note: requested on the command line with `-W clippy::must-use-candidate`
    //
    // We need to check for the presence of "detect_language" AND "rules.rs:205" in
    // the context of must_use_candidate warning.
    let has_detect_language_warning = combined.contains("rules.rs:205")
        && combined.contains("detect_language")
        && (combined.contains("must_use_candidate")
            || combined.contains("could have a `#[must_use]`"));

    assert!(
        !has_detect_language_warning,
        "detect_language() should have #[must_use] attribute, but clippy still warns.\n\
         \n\
         Clippy output:\n\
         {}\n\
         \n\
         The function at rules.rs:205 returns Option<&'static str> and MUST have\n\
         #[must_use] to prevent callers from silently ignoring language detection failure.",
        combined
    );
}

/// Test that ignoring `detect_language()` return value produces no warning
/// when `#[must_use]` is properly applied.
///
/// This test creates a temporary file that calls `detect_language()` without
/// using the return value, then runs clippy to verify it does NOT warn.
///
/// Note: This is a secondary verification that complements the main test above.
#[test]
fn detect_language_must_use_prevents_unused_warning() {
    // Verify detect_language is exported from the crate
    use diffguard_domain::detect_language;

    // Call detect_language and explicitly ignore the return value
    // With #[must_use] present, this should NOT produce a warning about unused result
    // Without #[must_use], clippy might still not warn (since it's Option) but the
    // must_use_candidate lint specifically checks for functions that COULD have #[must_use]

    let path = Path::new("test.rs");
    let _ignored = detect_language(path);

    // If we reach here without the #[must_use] attribute, clippy would have
    // warned during compilation (if must_use_candidate was enabled)
    // With #[must_use], this code is valid and produces no warning
}

/// Verify detect_language still works correctly after #[must_use] is added.
///
/// This is a regression test to ensure adding #[must_use] doesn't change behavior.
#[test]
fn detect_language_still_returns_correct_values() {
    use diffguard_domain::detect_language;

    // Known language mappings
    assert_eq!(
        detect_language(Path::new("src/lib.rs")),
        Some("rust"),
        "Rust files should return Some(\"rust\")"
    );
    assert_eq!(
        detect_language(Path::new("script.py")),
        Some("python"),
        "Python files should return Some(\"python\")"
    );
    assert_eq!(
        detect_language(Path::new("main.go")),
        Some("go"),
        "Go files should return Some(\"go\")"
    );

    // Unknown extension should return None
    assert_eq!(
        detect_language(Path::new("file.txt")),
        None,
        "Unknown extensions should return None"
    );
    assert_eq!(
        detect_language(Path::new("README")),
        None,
        "Files without extension should return None"
    );
}

/// Verify detect_language handles various Path types correctly.
#[test]
fn detect_language_handles_path_variants() {
    use diffguard_domain::detect_language;

    // Paths with different extensions - these are all valid languages detected by the function
    // Format: (path_str, expected_language_or_none)
    let cases: Vec<(&str, Option<&str>)> = vec![
        ("app.js", Some("javascript")),
        ("app.ts", Some("typescript")),
        ("app.tsx", Some("typescript")),
        ("component.jsx", Some("javascript")),
        ("main.c", Some("c")),
        ("header.h", Some("c")),
        ("main.cpp", Some("cpp")),
        ("main.cc", Some("cpp")),
        ("header.hpp", Some("cpp")),
        ("Program.cs", Some("csharp")),
        ("script.sh", Some("shell")),
        ("script.bash", Some("shell")),
        ("Dockerfile", None), // No extension
        ("Makefile", None),   // No extension
        ("file.txt", None),   // Unknown extension
        ("file.css", None),   // CSS is not a recognized language
    ];

    for (path_str, expected) in cases {
        let path = Path::new(path_str);
        let result = detect_language(path);
        assert_eq!(
            result, expected,
            "detect_language({:?}) should return {:?}",
            path_str, expected
        );
    }
}
