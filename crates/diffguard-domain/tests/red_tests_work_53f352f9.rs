//! Red tests for work-53f352f9: detect_language duplicate match arms
//!
//! Issue #306: detect_language had two adjacent match arms both returning Some("xml"):
//!   "xml" | "xsl" | "xslt" | "xsd" | "svg" | "xhtml" => Some("xml"),
//!   "html" | "htm" => Some("xml"),
//!
//! This triggered clippy's match_same_arms lint. The fix merged them:
//!   "xml" | "xsl" | "xslt" | "xsd" | "svg" | "xhtml" | "html" | "htm" => Some("xml"),
//!
//! These tests verify the CORRECT behavior: html/htm extensions map to "xml".

use diffguard_domain::rules::detect_language;
use std::path::Path;

/// Verifies that HTML files are detected as XML for preprocessing.
/// HTML is a well-formed SGML derivative that can be preprocessed as XML.
#[test]
fn test_detect_language_html_returns_xml() {
    let result = detect_language(Path::new("page.html"));
    assert_eq!(
        result,
        Some("xml"),
        "HTML files should be detected as 'xml' for preprocessing, but got {:?}",
        result
    );
}

/// Verifies that HTM files are detected as XML for preprocessing.
#[test]
fn test_detect_language_htm_returns_xml() {
    let result = detect_language(Path::new("page.htm"));
    assert_eq!(
        result,
        Some("xml"),
        "HTM files should be detected as 'xml' for preprocessing, but got {:?}",
        result
    );
}

/// Verifies that XHTML files are detected as XML.
#[test]
fn test_detect_language_xhtml_returns_xml() {
    let result = detect_language(Path::new("page.xhtml"));
    assert_eq!(
        result,
        Some("xml"),
        "XHTML files should be detected as 'xml', but got {:?}",
        result
    );
}

/// Verifies that SVG files are detected as XML.
#[test]
fn test_detect_language_svg_returns_xml() {
    let result = detect_language(Path::new("icon.svg"));
    assert_eq!(
        result,
        Some("xml"),
        "SVG files should be detected as 'xml', but got {:?}",
        result
    );
}

/// Verifies XML variant extensions map to "xml".
#[test]
fn test_detect_language_xml_variants_return_xml() {
    // Test all XML-related extensions that should map to "xml"
    let xml_exts = vec![
        ("config.xml", "xml"),
        ("style.xsl", "xml"),
        ("transform.xslt", "xml"),
        ("schema.xsd", "xml"),
    ];

    for (path_str, expected) in xml_exts {
        let result = detect_language(Path::new(path_str));
        let ext = Path::new(path_str)
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        assert_eq!(
            result,
            Some(expected),
            "Extension .{} should map to '{}', but got {:?}",
            ext,
            expected,
            result
        );
    }
}

/// Verifies that case-insensitive extension matching works for HTML/HTM.
#[test]
fn test_detect_language_html_case_insensitive() {
    // HTML extensions should work regardless of case
    let upper_result = detect_language(Path::new("page.HTML"));
    let lower_result = detect_language(Path::new("page.html"));
    assert_eq!(
        upper_result, lower_result,
        "HTML detection should be case-insensitive"
    );
    assert_eq!(
        lower_result,
        Some("xml"),
        "HTML should map to 'xml', got {:?}",
        lower_result
    );
}

/// Verifies that case-insensitive extension matching works for HTM.
#[test]
fn test_detect_language_htm_case_insensitive() {
    let upper_result = detect_language(Path::new("page.HTM"));
    let lower_result = detect_language(Path::new("page.htm"));
    assert_eq!(
        upper_result, lower_result,
        "HTM detection should be case-insensitive"
    );
    assert_eq!(
        lower_result,
        Some("xml"),
        "HTM should map to 'xml', got {:?}",
        lower_result
    );
}

/// Verifies that the merged match arm covers all XML-family extensions.
/// This test documents the expected behavior after the fix for issue #306.
#[test]
fn test_detect_language_all_xml_family_extensions() {
    // All these extensions should return Some("xml")
    let xml_family = vec!["xml", "xsl", "xslt", "xsd", "svg", "xhtml", "html", "htm"];

    for ext in xml_family {
        let path = format!("file.{}", ext);
        let result = detect_language(Path::new(&path));
        assert_eq!(
            result,
            Some("xml"),
            "Extension .{} should map to 'xml', but got {:?}",
            ext,
            result
        );
    }
}
