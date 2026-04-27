//! Property test to verify HTML vs XML discrimination invariant
//!
//! This test verifies that `detect_language` returns DISTINCT values for
//! HTML extensions (html, htm) vs XML extensions (xml, xsl, xslt, xsd, svg, xhtml).
//!
//! This is a regression test for work-cd9db3ce: the bug was that html/htm
//! incorrectly returned Some("xml"), making HTML-specific rule filtering impossible.

use diffguard_domain::detect_language;
use std::path::Path;

const XML_EXTENSIONS: &[&str] = &["xml", "xsl", "xslt", "xsd", "svg", "xhtml"];
const HTML_EXTENSIONS: &[&str] = &["html", "htm"];

fn make_path(filename: &str) -> String {
    filename.to_string()
}

#[test]
fn html_and_xml_return_distinct_languages() {
    // For each HTML extension, verify it returns a different value from each XML extension
    for html_ext in HTML_EXTENSIONS {
        let html_filename = make_path(&format!("page.{}", html_ext));
        let html_path = Path::new(&html_filename);
        let html_lang = detect_language(html_path);

        assert!(
            html_lang.is_some(),
            "detect_language should return Some for .{}",
            html_ext
        );

        for xml_ext in XML_EXTENSIONS {
            let xml_filename = make_path(&format!("document.{}", xml_ext));
            let xml_path = Path::new(&xml_filename);
            let xml_lang = detect_language(xml_path);

            assert!(
                xml_lang.is_some(),
                "detect_language should return Some for .{}",
                xml_ext
            );

            assert_ne!(
                html_lang, xml_lang,
                "HTML extension '.{}' and XML extension '.{}' must return DISTINCT language identifiers. \
                 Got html_lang={:?}, xml_lang={:?}. \
                 This invariant ensures HTML-specific rule filtering works correctly.",
                html_ext, xml_ext, html_lang, xml_lang
            );
        }
    }
}

#[test]
fn html_returns_html_identifier() {
    // Specifically verify html/htm return "html", not "xml" or anything else
    for ext in HTML_EXTENSIONS {
        let filename = make_path(&format!("page.{}", ext));
        let path = Path::new(&filename);
        let lang = detect_language(path);

        assert_eq!(
            lang,
            Some("html"),
            "detect_language(Path::new(\"page.{}\")) must return Some(\"html\"), got {:?}",
            ext,
            lang
        );
    }
}

#[test]
fn xml_family_returns_xml_identifier() {
    // Verify all XML family extensions return "xml"
    for ext in XML_EXTENSIONS {
        let filename = make_path(&format!("document.{}", ext));
        let path = Path::new(&filename);
        let lang = detect_language(path);

        assert_eq!(
            lang,
            Some("xml"),
            "detect_language(Path::new(\"document.{}\")) must return Some(\"xml\"), got {:?}",
            ext,
            lang
        );
    }
}

#[test]
fn html_xml_case_insensitive() {
    // Case-insensitive versions should also be distinct
    for html_ext in HTML_EXTENSIONS {
        let html_lower_filename = make_path(&format!("page.{}", html_ext.to_lowercase()));
        let html_upper_filename = make_path(&format!("page.{}", html_ext.to_uppercase()));

        let html_lower_path = Path::new(&html_lower_filename);
        let html_upper_path = Path::new(&html_upper_filename);

        let html_lower_lang = detect_language(html_lower_path);
        let html_upper_lang = detect_language(html_upper_path);

        assert_eq!(
            html_lower_lang,
            Some("html"),
            "Lowercase .{} should return Some(\"html\")",
            html_ext
        );
        assert_eq!(
            html_upper_lang,
            Some("html"),
            "Uppercase .{} should return Some(\"html\")",
            html_ext.to_uppercase()
        );
    }

    for xml_ext in XML_EXTENSIONS {
        let xml_lower_filename = make_path(&format!("doc.{}", xml_ext.to_lowercase()));
        let xml_upper_filename = make_path(&format!("doc.{}", xml_ext.to_uppercase()));

        let xml_lower_path = Path::new(&xml_lower_filename);
        let xml_upper_path = Path::new(&xml_upper_filename);

        let xml_lower_lang = detect_language(xml_lower_path);
        let xml_upper_lang = detect_language(xml_upper_path);

        assert_eq!(
            xml_lower_lang,
            Some("xml"),
            "Lowercase .{} should return Some(\"xml\")",
            xml_ext
        );
        assert_eq!(
            xml_upper_lang,
            Some("xml"),
            "Uppercase .{} should return Some(\"xml\")",
            xml_ext.to_uppercase()
        );
    }
}
