//! Tests for language detection and parsing behavior.
//!
//! These tests verify the correctness of the `detect_language` function and
//! language parsing logic in `evaluate.rs`. The underlying functions being
//! modified (`detect_language` and `Language::from_str`) have no behavioral
//! changes - the clippy refactor only affects code style.
//!
//! # Clippy Lints Being Fixed
//!
//! - `redundant_closure_for_method_calls` on line 116:
//!   `|lang| lang.to_ascii_lowercase()` → `str::to_ascii_lowercase`
//!
//! - `map_unwrap_or` on lines 134-136:
//!   `detect_language(path).map(...).unwrap_or(Language::Unknown)`
//!   → uses `map_or` instead

use std::path::Path;
use diffguard_domain::rules::detect_language;
use diffguard_domain::preprocess::Language;

/// Test that `detect_language` returns correct values for known file extensions.
#[test]
fn test_detect_language_rust() {
    assert_eq!(detect_language(Path::new("src/lib.rs")), Some("rust"));
    assert_eq!(detect_language(Path::new("src/main.rs")), Some("rust"));
    assert_eq!(detect_language(Path::new("tests/test.rs")), Some("rust"));
}

#[test]
fn test_detect_language_python() {
    assert_eq!(detect_language(Path::new("script.py")), Some("python"));
    assert_eq!(detect_language(Path::new("script.pyw")), Some("python"));
    assert_eq!(detect_language(Path::new("setup.py")), Some("python"));
}

#[test]
fn test_detect_language_javascript() {
    assert_eq!(detect_language(Path::new("app.js")), Some("javascript"));
    assert_eq!(detect_language(Path::new("module.mjs")), Some("javascript"));
    assert_eq!(detect_language(Path::new("module.cjs")), Some("javascript"));
    assert_eq!(detect_language(Path::new("component.jsx")), Some("javascript"));
}

#[test]
fn test_detect_language_typescript() {
    assert_eq!(detect_language(Path::new("app.ts")), Some("typescript"));
    assert_eq!(detect_language(Path::new("module.mts")), Some("typescript"));
    assert_eq!(detect_language(Path::new("module.cts")), Some("typescript"));
    assert_eq!(detect_language(Path::new("component.tsx")), Some("typescript"));
}

#[test]
fn test_detect_language_go() {
    assert_eq!(detect_language(Path::new("main.go")), Some("go"));
    assert_eq!(detect_language(Path::new("server.go")), Some("go"));
}

#[test]
fn test_detect_language_java() {
    assert_eq!(detect_language(Path::new("Main.java")), Some("java"));
    assert_eq!(detect_language(Path::new("Server.java")), Some("java"));
}

#[test]
fn test_detect_language_ruby() {
    assert_eq!(detect_language(Path::new("script.rb")), Some("ruby"));
    assert_eq!(detect_language(Path::new("task.rake")), Some("ruby"));
}

#[test]
fn test_detect_language_shell() {
    assert_eq!(detect_language(Path::new("script.sh")), Some("shell"));
    assert_eq!(detect_language(Path::new("script.bash")), Some("shell"));
    assert_eq!(detect_language(Path::new("script.zsh")), Some("shell"));
}

/// Test that `detect_language` returns `None` for unknown extensions.
#[test]
fn test_detect_language_unknown_extension() {
    assert_eq!(detect_language(Path::new("README")), None);
    assert_eq!(detect_language(Path::new("Makefile")), None);
    assert_eq!(detect_language(Path::new("Dockerfile")), None);
    assert_eq!(detect_language(Path::new("file.xyz")), None);
}

/// Test that language parsing falls back to `Unknown` for invalid language strings.
#[test]
fn test_language_parse_fallback_to_unknown() {
    use std::str::FromStr;

    // Valid languages
    assert_eq!(Language::from_str("rust"), Ok(Language::Rust));
    assert_eq!(Language::from_str("python"), Ok(Language::Python));
    assert_eq!(Language::from_str("javascript"), Ok(Language::JavaScript));

    // Case insensitive
    assert_eq!(Language::from_str("RUST"), Ok(Language::Rust));
    assert_eq!(Language::from_str("Python"), Ok(Language::Python));

    // Unknown languages fall back to Unknown (parsing always succeeds)
    assert_eq!(Language::from_str("cobol"), Ok(Language::Unknown));
    assert_eq!(Language::from_str("fortran"), Ok(Language::Unknown));
    assert_eq!(Language::from_str(""), Ok(Language::Unknown));
    assert_eq!(Language::from_str("notareallanguage"), Ok(Language::Unknown));
}

/// Test the combined behavior used in evaluate.rs lines 134-136:
/// `detect_language(path).map(|s| s.parse::<Language>().unwrap_or(Language::Unknown)).unwrap_or(Language::Unknown)`
#[test]
fn test_language_detection_and_parsing() {
    fn detect_and_parse(path: &Path) -> Language {
        detect_language(path)
            .map(|s| s.parse::<Language>().unwrap_or(Language::Unknown))
            .unwrap_or(Language::Unknown)
    }

    // Known extensions
    assert_eq!(detect_and_parse(Path::new("src/lib.rs")), Language::Rust);
    assert_eq!(detect_and_parse(Path::new("script.py")), Language::Python);
    assert_eq!(detect_and_parse(Path::new("app.js")), Language::JavaScript);

    // Unknown extensions
    assert_eq!(detect_and_parse(Path::new("README")), Language::Unknown);
    assert_eq!(detect_and_parse(Path::new("Makefile")), Language::Unknown);
}
