//! Edge case tests for HTML language detection in `detect_language()`.
//!
//! These tests complement the existing unit tests in `clippy_refactor_test.rs`
//! by focusing specifically on edge cases for HTML/HTM extension detection.
//!
//! Coverage:
//! - Basic HTML detection (html, htm)
//! - Case insensitivity (HTML, HTM, HtMl)
//! - Paths with directories
//! - Paths with multiple extensions
//! - Distinction from XML/XHTML
//! - Empty and malformed paths

use diffguard_domain::detect_language;
use std::path::Path;

// ============================================================================
// Basic HTML Detection
// ============================================================================

/// Test that `.html` extension returns `Some("html")` for rule filtering.
#[test]
fn test_detect_language_html_basic() {
    assert_eq!(detect_language(Path::new("page.html")), Some("html"));
    assert_eq!(detect_language(Path::new("index.html")), Some("html"));
    assert_eq!(detect_language(Path::new("home.html")), Some("html"));
}

/// Test that `.htm` extension returns `Some("html")` for rule filtering.
#[test]
fn test_detect_language_htm_basic() {
    assert_eq!(detect_language(Path::new("page.htm")), Some("html"));
    assert_eq!(detect_language(Path::new("index.htm")), Some("html"));
    assert_eq!(detect_language(Path::new("home.htm")), Some("html"));
}

// ============================================================================
// Case Insensitivity
// ============================================================================

/// Test that `.HTML` (uppercase) extension returns `Some("html")` case-insensitively.
#[test]
fn test_detect_language_html_uppercase() {
    assert_eq!(detect_language(Path::new("page.HTML")), Some("html"));
    assert_eq!(detect_language(Path::new("page.HTML")), Some("html"));
    assert_eq!(detect_language(Path::new("INDEX.HTML")), Some("html"));
}

/// Test that `.HTM` (uppercase) extension returns `Some("html")` case-insensitively.
#[test]
fn test_detect_language_htm_uppercase() {
    assert_eq!(detect_language(Path::new("page.HTM")), Some("html"));
    assert_eq!(detect_language(Path::new("page.HTM")), Some("html"));
    assert_eq!(detect_language(Path::new("INDEX.HTM")), Some("html"));
}

/// Test mixed case variants.
#[test]
fn test_detect_language_html_mixed_case() {
    assert_eq!(detect_language(Path::new("page.Html")), Some("html"));
    assert_eq!(detect_language(Path::new("page.HtMl")), Some("html"));
    assert_eq!(detect_language(Path::new("page.HtM")), Some("html"));
    assert_eq!(detect_language(Path::new("page.html")), Some("html"));
}

// ============================================================================
// Paths with Directories
// ============================================================================

/// Test HTML detection with directory paths.
#[test]
fn test_detect_language_html_with_directories() {
    // Single directory level
    assert_eq!(
        detect_language(Path::new("src/pages/home.html")),
        Some("html")
    );
    assert_eq!(
        detect_language(Path::new("templates/index.htm")),
        Some("html")
    );

    // Multiple directory levels
    assert_eq!(
        detect_language(Path::new("var/www/html/page.html")),
        Some("html")
    );
    assert_eq!(
        detect_language(Path::new("home/user/sites/blog/index.htm")),
        Some("html")
    );

    // Directory with dots
    assert_eq!(
        detect_language(Path::new("project.v2/src/view.html")),
        Some("html")
    );
}

/// Test HTML detection with absolute paths.
#[test]
fn test_detect_language_html_absolute_path() {
    assert_eq!(
        detect_language(Path::new("/var/www/html/index.html")),
        Some("html")
    );
    assert_eq!(
        detect_language(Path::new("/home/user/documents/page.htm")),
        Some("html")
    );
}

// ============================================================================
// Multiple Extensions / Edge Cases
// ============================================================================

/// Test that files with multiple dots are handled correctly.
#[test]
fn test_detect_language_html_multiple_dots() {
    // File name with multiple dots
    assert_eq!(
        detect_language(Path::new("page.template.html")),
        Some("html")
    );
    assert_eq!(
        detect_language(Path::new("component.final.htm")),
        Some("html")
    );
    assert_eq!(detect_language(Path::new("view.backup.html")), Some("html"));
}

/// Test that similar-but-different extensions are NOT detected as HTML.
#[test]
fn test_detect_language_not_html() {
    // These should NOT return Some("html")
    assert_eq!(detect_language(Path::new("file.htmlx")), None);
    assert_eq!(detect_language(Path::new("file.html5")), None);
    assert_eq!(detect_language(Path::new("file.htmx")), None);
    assert_eq!(detect_language(Path::new("file.xhtml")), Some("xml")); // XHTML is XML
    assert_eq!(detect_language(Path::new("file.phtml")), Some("php")); // PHP variant
}

// ============================================================================
// XML/XHTML Distinction
// ============================================================================

/// Test that HTML is distinct from XML/XHTML.
#[test]
fn test_detect_language_html_distinct_from_xml() {
    // HTML returns "html"
    assert_eq!(detect_language(Path::new("page.html")), Some("html"));
    assert_eq!(detect_language(Path::new("page.htm")), Some("html"));

    // XML returns "xml"
    assert_eq!(detect_language(Path::new("config.xml")), Some("xml"));
    assert_eq!(detect_language(Path::new("data.xsl")), Some("xml"));
    assert_eq!(detect_language(Path::new("style.xslt")), Some("xml"));
    assert_eq!(detect_language(Path::new("schema.xsd")), Some("xml"));

    // XHTML returns "xml" (XML-based)
    assert_eq!(detect_language(Path::new("page.xhtml")), Some("xml"));
}

/// Test that SVG (XML-based) returns "xml" not "html".
#[test]
fn test_detect_language_svg_returns_xml() {
    assert_eq!(detect_language(Path::new("icon.svg")), Some("xml"));
    assert_eq!(detect_language(Path::new("graphic.SVG")), Some("xml"));
}

// ============================================================================
// Empty and Malformed Paths
// ============================================================================

/// Test that paths without extensions return None.
#[test]
fn test_detect_language_no_extension() {
    assert_eq!(detect_language(Path::new("README")), None);
    assert_eq!(detect_language(Path::new("Makefile")), None);
    assert_eq!(detect_language(Path::new("Dockerfile")), None);
    assert_eq!(detect_language(Path::new("filename")), None);
}

/// Test that paths with empty extension return None.
#[test]
fn test_detect_language_empty_extension() {
    assert_eq!(detect_language(Path::new("file.")), None);
    assert_eq!(detect_language(Path::new("dir/file.")), None);
}

/// Test that special characters in paths don't break detection.
#[test]
fn test_detect_language_html_special_chars_in_path() {
    // Spaces in directory names
    assert_eq!(
        detect_language(Path::new("my documents/page.html")),
        Some("html")
    );

    // Underscores and hyphens
    assert_eq!(
        detect_language(Path::new("my_folder/page-name.html")),
        Some("html")
    );
}

// ============================================================================
// Rule Filtering Integration
// ============================================================================

/// Test that HTML detection works correctly for rule filtering scenarios.
/// This simulates the use case from the bug report: `languages = ["html"]`
#[test]
fn test_detect_language_for_rule_filtering() {
    // Simulate rule filtering logic
    fn rule_applies_to_html(language: Option<&str>, rule_languages: &[&str]) -> bool {
        if rule_languages.is_empty() {
            return true; // Empty means apply to all
        }
        let Some(lang) = language else {
            return false;
        };
        rule_languages.contains(&lang)
    }

    // Rule with languages = ["html"] should apply to .html files
    assert!(rule_applies_to_html(
        detect_language(Path::new("page.html")),
        &["html"]
    ));
    assert!(rule_applies_to_html(
        detect_language(Path::new("page.htm")),
        &["html"]
    ));

    // Rule with languages = ["html"] should NOT apply to .xml files
    assert!(!rule_applies_to_html(
        detect_language(Path::new("config.xml")),
        &["html"]
    ));

    // Rule with languages = ["html"] should NOT apply to .xhtml files
    assert!(!rule_applies_to_html(
        detect_language(Path::new("page.xhtml")),
        &["html"]
    ));
}
