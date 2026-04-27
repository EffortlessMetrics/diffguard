//! Tests for HTML language detection in `detect_language()`.
//!
//! These tests define the CORRECT behavior: HTML extensions should return
//! `Some("html")`, NOT `Some("xml")`.
//!
//! This is a copy-paste bug where the XML match arm was never updated when
//! HTML extensions were added. The two-representation design is:
//! - `detect_language()` returns `"html"` for HTML files (for rule filtering)
//! - `Language::Xml` is used for preprocessing (HTML uses XML-style comments)
//!
//! These tests FAIL with the buggy code and PASS after the fix.

use diffguard_domain::detect_language;
use std::path::Path;

/// Test that `.html` extension returns `Some("html")` for rule filtering.
///
/// ACCEPTANCE CRITERIA AC1: `detect_language(Path::new("page.html"))` returns `Some("html")`
#[test]
fn test_detect_language_html_extension_returns_html() {
    let result = detect_language(Path::new("page.html"));
    assert_eq!(
        result,
        Some("html"),
        "Expected detect_language(Path::new(\"page.html\")) to return Some(\"html\"), but got {:?}.          HTML files should be detectable for rule filtering via languages = [\"html\"].",
        result
    );
}

/// Test that `.htm` extension returns `Some("html")` for rule filtering.
///
/// ACCEPTANCE CRITERIA AC2: `detect_language(Path::new("page.htm"))` returns `Some("html")`
#[test]
fn test_detect_language_htm_extension_returns_html() {
    let result = detect_language(Path::new("page.htm"));
    assert_eq!(
        result,
        Some("html"),
        "Expected detect_language(Path::new(\"page.htm\")) to return Some(\"html\"), but got {:?}.          HTML files should be detectable for rule filtering via languages = [\"html\"].",
        result
    );
}

/// Test that `.HTML` (uppercase) extension returns `Some("html")` case-insensitively.
#[test]
fn test_detect_language_html_uppercase_returns_html() {
    let result = detect_language(Path::new("page.HTML"));
    assert_eq!(
        result,
        Some("html"),
        "Expected detect_language(Path::new(\"page.HTML\")) to return Some(\"html\") (case-insensitive), but got {:?}.",
        result
    );
}

/// Test that `.HTM` (uppercase) extension returns `Some("html")` case-insensitively.
#[test]
fn test_detect_language_htm_uppercase_returns_html() {
    let result = detect_language(Path::new("page.HTM"));
    assert_eq!(
        result,
        Some("html"),
        "Expected detect_language(Path::new(\"page.HTM\")) to return Some(\"html\") (case-insensitive), but got {:?}.",
        result
    );
}

/// Test that HTML detection is distinct from XML detection.
///
/// This validates the two-representation design:
/// - `detect_language()` returns `"html"` for HTML files
/// - `detect_language()` returns `"xml"` for XML files
#[test]
fn test_detect_language_html_is_distinct_from_xml() {
    let html_result = detect_language(Path::new("page.html"));
    let xml_result = detect_language(Path::new("config.xml"));

    assert_eq!(
        html_result,
        Some("html"),
        "HTML should return Some(\"html\")"
    );
    assert_eq!(xml_result, Some("xml"), "XML should return Some(\"xml\")");
    assert_ne!(
        html_result, xml_result,
        "HTML and XML should be distinguishable for rule filtering.          Got html: {:?}, xml: {:?}",
        html_result, xml_result
    );
}

/// Test HTML with various path formats.
#[test]
fn test_detect_language_html_with_various_paths() {
    // Simple filename
    assert_eq!(detect_language(Path::new("index.html")), Some("html"));

    // With directory path
    assert_eq!(
        detect_language(Path::new("src/pages/home.html")),
        Some("html")
    );

    // With multiple directory levels
    assert_eq!(
        detect_language(Path::new("var/www/html/page.htm")),
        Some("html")
    );
}

/// Test that `.xhtml` still returns `Some("xml")` (XHTML is XML-based).
#[test]
fn test_detect_language_xhtml_returns_xml() {
    let result = detect_language(Path::new("page.xhtml"));
    assert_eq!(
        result,
        Some("xml"),
        "XHTML is XML-based and should return Some(\"xml\"), but got {:?}",
        result
    );
}
