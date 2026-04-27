//! Snapshot tests for `detect_language()` HTML extension detection.
//!
//! These tests verify the output baseline for HTML file extension detection.
//! The bug (work-cd9db3ce) was that `.html` and `.htm` extensions incorrectly
//! returned `Some("xml")` instead of `Some("html")`.
//!
//! Snapshot tests capture current behavior so ANY change is immediately detected.

use diffguard_domain::detect_language;
use std::path::Path;

/// Snapshot test for detect_language with HTML extensions.
/// Captures the current output for .html and .htm files.
#[test]
fn test_detect_language_html_extensions() {
    use insta::assert_snapshot;

    let extensions = ["html", "htm"];

    let mut snapshot = String::new();
    for ext in extensions {
        let path_str = format!("page.{}", ext);
        let path = Path::new(&path_str);
        let result = detect_language(path);
        snapshot.push_str(&format!(".{ext}: {result:?}\n"));
    }
    assert_snapshot!("detect_language_html_extensions", snapshot);
}

/// Snapshot test for detect_language with XML family extensions.
/// These should return Some("xml") - captured as baseline.
#[test]
fn test_detect_language_xml_extensions() {
    use insta::assert_snapshot;

    let extensions = ["xml", "xsl", "xslt", "xsd", "svg", "xhtml"];

    let mut snapshot = String::new();
    for ext in extensions {
        let path_str = format!("document.{}", ext);
        let path = Path::new(&path_str);
        let result = detect_language(path);
        snapshot.push_str(&format!(".{ext}: {result:?}\n"));
    }
    assert_snapshot!("detect_language_xml_extensions", snapshot);
}

/// Snapshot test for detect_language case insensitivity.
/// Captures behavior for uppercase variants like .HTML and .HTM.
#[test]
fn test_detect_language_html_case_insensitive() {
    use insta::assert_snapshot;

    let cases = [
        ("page.html", "lowercase"),
        ("page.HTML", "uppercase"),
        ("page.Htm", "mixed case"),
        ("page.htm", "lowercase htm"),
        ("page.HTM", "uppercase htm"),
    ];

    let mut snapshot = String::new();
    for (path_str, description) in cases {
        let path = Path::new(path_str);
        let result = detect_language(path);
        snapshot.push_str(&format!("{description} ({path_str}): {result:?}\n"));
    }
    assert_snapshot!("detect_language_html_case_insensitive", snapshot);
}

/// Snapshot test for detect_language with various file paths.
/// Captures behavior for paths with directories and special characters.
#[test]
fn test_detect_language_html_paths() {
    use insta::assert_snapshot;

    let paths = [
        "page.html",
        "page.htm",
        "index.html",
        "templates/base.html",
        "src/html/layout.htm",
        "/absolute/path/to/page.html",
        "file.with.dots.html",
    ];

    let mut snapshot = String::new();
    for path_str in paths {
        let path = Path::new(path_str);
        let result = detect_language(path);
        snapshot.push_str(&format!("{path_str}: {result:?}\n"));
    }
    assert_snapshot!("detect_language_html_paths", snapshot);
}

/// Snapshot test comparing HTML vs XML discrimination.
/// This is the key invariant: html/htm must NOT equal xml family.
#[test]
fn test_detect_language_html_xml_discrimination() {
    use insta::assert_snapshot;

    let html_result = detect_language(Path::new("page.html"));
    let htm_result = detect_language(Path::new("page.htm"));
    let xml_result = detect_language(Path::new("document.xml"));
    let svg_result = detect_language(Path::new("image.svg"));

    let mut snapshot = String::new();
    snapshot.push_str(&format!("html (page.html): {html_result:?}\n"));
    snapshot.push_str(&format!("htm (page.htm): {htm_result:?}\n"));
    snapshot.push_str(&format!("xml (document.xml): {xml_result:?}\n"));
    snapshot.push_str(&format!("svg (image.svg): {svg_result:?}\n"));
    snapshot.push_str(&format!("\nhtml == xml: {}\n", html_result == xml_result));
    snapshot.push_str(&format!("htm == xml: {}\n", htm_result == xml_result));
    snapshot.push_str(&format!("html == htm: {}\n", html_result == htm_result));

    assert_snapshot!("detect_language_html_xml_discrimination", snapshot);
}
