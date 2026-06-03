//! Property-based tests for `detect_language` function
//!
//! Issue #306: detect_language had two adjacent match arms both returning Some("xml")
//! The fix merged them into a single match arm.
//!
//! This module tests the invariants that should hold after the fix:
//! 1. All XML-family extensions (xml, xsl, xslt, xsd, svg, xhtml) return Some("xml")
//! 2. HTML family extensions (html, htm) ALSO return Some("xml") - this was the duplicate
//! 3. Case insensitivity: all extensions work regardless of case
//! 4. Unknown extensions return None
//! 5. Extensions in OTHER arms do NOT return Some("xml") (e.g., js returns javascript, not xml)

use diffguard_domain::rules::detect_language;
use std::path::Path;

/// Property: All documented XML and HTML family extensions should return Some("xml")
/// This is the core invariant that was broken by duplicate arms and fixed by merging.
#[test]
fn property_xml_family_extensions_all_return_xml() {
    let xml_family = vec!["xml", "xsl", "xslt", "xsd", "svg", "xhtml", "html", "htm"];

    for ext in xml_family {
        let filename = format!("file.{}", ext);
        let path = Path::new(&filename);
        let result = detect_language(path);
        assert_eq!(
            result,
            Some("xml"),
            "Extension '{}' should return Some(\"xml\"), got {:?}",
            ext,
            result
        );
    }
}

/// Property: Case insensitivity - all extensions work regardless of case
/// Input: extension with random case variations
/// Expected: same result as lowercase version
#[test]
fn property_case_insensitivity_all_variations() {
    let test_cases = vec![
        // (extension, expected_result)
        ("rs", Some("rust")),
        ("py", Some("python")),
        ("pyw", Some("python")),
        ("js", Some("javascript")),
        ("mjs", Some("javascript")),
        ("cjs", Some("javascript")),
        ("jsx", Some("javascript")),
        ("ts", Some("typescript")),
        ("mts", Some("typescript")),
        ("cts", Some("typescript")),
        ("tsx", Some("typescript")),
        ("go", Some("go")),
        ("java", Some("java")),
        ("kt", Some("kotlin")),
        ("kts", Some("kotlin")),
        ("rb", Some("ruby")),
        ("rake", Some("ruby")),
        ("c", Some("c")),
        ("h", Some("c")),
        ("cpp", Some("cpp")),
        ("cc", Some("cpp")),
        ("cxx", Some("cpp")),
        ("hpp", Some("cpp")),
        ("hxx", Some("cpp")),
        ("hh", Some("cpp")),
        ("cs", Some("csharp")),
        ("sh", Some("shell")),
        ("bash", Some("shell")),
        ("zsh", Some("shell")),
        ("ksh", Some("shell")),
        ("fish", Some("shell")),
        ("swift", Some("swift")),
        ("scala", Some("scala")),
        ("sc", Some("scala")),
        ("sql", Some("sql")),
        ("xml", Some("xml")),
        ("xsl", Some("xml")),
        ("xslt", Some("xml")),
        ("xsd", Some("xml")),
        ("svg", Some("xml")),
        ("xhtml", Some("xml")),
        ("html", Some("xml")),
        ("htm", Some("xml")),
        ("php", Some("php")),
        ("phtml", Some("php")),
        ("php3", Some("php")),
        ("php4", Some("php")),
        ("php5", Some("php")),
        ("php7", Some("php")),
        ("phps", Some("php")),
        ("yaml", Some("yaml")),
        ("yml", Some("yaml")),
        ("toml", Some("toml")),
        ("json", Some("json")),
        ("jsonc", Some("json")),
        ("json5", Some("json")),
    ];

    for (ext, expected) in test_cases {
        // Test lowercase
        let filename_lower = format!("file.{}", ext.to_lowercase());
        let path_lower = Path::new(&filename_lower);
        let result_lower = detect_language(path_lower);
        assert_eq!(
            result_lower, expected,
            "Lowercase '{}' should return {:?}, got {:?}",
            ext, expected, result_lower
        );

        // Test uppercase
        let filename_upper = format!("file.{}", ext.to_uppercase());
        let path_upper = Path::new(&filename_upper);
        let result_upper = detect_language(path_upper);
        assert_eq!(
            result_upper,
            expected,
            "Uppercase '{}' should return {:?}, got {:?}",
            ext.to_uppercase(),
            expected,
            result_upper
        );

        // Test mixed case
        let ext_mixed: String = ext
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().to_string()
                } else {
                    c.to_lowercase().to_string()
                }
            })
            .collect();
        let filename_mixed = format!("file.{}", ext_mixed);
        let path_mixed = Path::new(&filename_mixed);
        let result_mixed = detect_language(path_mixed);
        assert_eq!(
            result_mixed, expected,
            "Mixed case '{}' should return {:?}, got {:?}",
            ext_mixed, expected, result_mixed
        );
    }
}

/// Property: Extensions NOT in the xml/html arm should NOT return Some("xml")
/// This ensures the merged arm doesn't accidentally catch other extensions.
#[test]
fn property_non_xml_extensions_do_not_return_xml() {
    let non_xml_cases = vec![
        ("rs", Some("rust")),
        ("py", Some("python")),
        ("js", Some("javascript")),
        ("ts", Some("typescript")),
        ("go", Some("go")),
        ("java", Some("java")),
        ("kt", Some("kotlin")),
        ("rb", Some("ruby")),
        ("c", Some("c")),
        ("cpp", Some("cpp")),
        ("cs", Some("csharp")),
        ("sh", Some("shell")),
        ("swift", Some("swift")),
        ("scala", Some("scala")),
        ("sql", Some("sql")),
        ("php", Some("php")),
        ("yaml", Some("yaml")),
        ("toml", Some("toml")),
        ("json", Some("json")),
    ];

    for (ext, expected) in non_xml_cases {
        let filename = format!("file.{}", ext);
        let path = Path::new(&filename);
        let result = detect_language(path);
        assert_ne!(
            result,
            Some("xml"),
            "Extension '{}' should NOT return Some(\"xml\"), got {:?}",
            ext,
            result
        );
        assert_eq!(
            result, expected,
            "Extension '{}' should return {:?}, got {:?}",
            ext, expected, result
        );
    }
}

/// Property: Unknown extensions return None (not Some other value)
#[test]
fn property_unknown_extensions_return_none() {
    let unknown_extensions = vec![
        "xyz", "abc", "123", "foo", "bar", "baz", "gz", "bz2", "zip", "tar", "rar", "css", "less",
        "scss", "sass", "md", "markdown", "rst", "txt", "text", "doc", "docx", "png", "jpg",
        "jpeg", "gif", "bmp", "ico", "mp3", "mp4", "avi", "mov", "wmv", "pdf", "ps", "eps",
    ];

    for ext in unknown_extensions {
        let filename = format!("file.{}", ext);
        let path = Path::new(&filename);
        let result = detect_language(path);
        assert_eq!(
            result, None,
            "Unknown extension '{}' should return None, got {:?}",
            ext, result
        );
    }
}

/// Property: Files without extensions always return None
#[test]
fn property_no_extension_returns_none() {
    let no_extension_paths = vec![
        "Makefile",
        "Dockerfile",
        "README",
        "README.md",
        "Vagrantfile",
        "Gemfile",
        ".gitignore",
        ".bashrc",
        ".env",
        "filename", // no dot at all
    ];

    for path_str in no_extension_paths {
        let path = Path::new(path_str);
        let result = detect_language(path);
        assert_eq!(
            result, None,
            "Path '{}' with no extension should return None, got {:?}",
            path_str, result
        );
    }
}

/// Property: Multiple dots - only the last extension matters
/// file.tar.gz should detect as gz (if gz supported) or None (if not)
/// We verify that the extension extraction works correctly with multiple dots.
#[test]
fn property_multiple_dots_uses_last_extension() {
    // gz, bz2, zip are not supported - should return None
    let multi_dot_unsupported = vec!["file.tar.gz", "archive.tar.bz2", "data.backup.zip"];

    for path_str in multi_dot_unsupported {
        let path = Path::new(path_str);
        let result = detect_language(path);
        assert_eq!(
            result, None,
            "Unsupported multi-dot extension '{}' should return None, got {:?}",
            path_str, result
        );
    }

    // jsonc, json5 ARE supported - should return Some("json")
    let multi_dot_supported = vec!["config.jsonc", "data.json5"];

    for path_str in multi_dot_supported {
        let path = Path::new(path_str);
        let result = detect_language(path);
        assert_eq!(
            result,
            Some("json"),
            "Supported multi-dot extension '{}' should return Some(\"json\"), got {:?}",
            path_str,
            result
        );
    }
}

/// Property: Paths with directories should still extract extension correctly
#[test]
fn property_paths_with_directories_work() {
    let paths = vec![
        ("src/main.rs", Some("rust")),
        ("lib/utils.js", Some("javascript")),
        ("web/page.html", Some("xml")),
        ("docs/README.md", None),
        ("./config.xml", Some("xml")),
        ("../src/main.kt", Some("kotlin")),
        ("~/projects/app.py", Some("python")),
    ];

    for (path_str, expected) in paths {
        let path = Path::new(path_str);
        let result = detect_language(path);
        assert_eq!(
            result, expected,
            "Path '{}' should return {:?}, got {:?}",
            path_str, expected, result
        );
    }
}

/// Property: The duplicate arms fix means html and htm are in the SAME arm as xml family
/// This test explicitly verifies that html/htm behave identically to xml/xsl/etc.
/// AFTER the fix: all should return Some("xml") from the merged arm
#[test]
fn property_html_htm_same_as_xml_family() {
    let xml_and_html = ["xml", "xsl", "xslt", "xsd", "svg", "xhtml", "html", "htm"];

    let results: Vec<_> = xml_and_html
        .iter()
        .map(|ext| {
            let filename = format!("file.{}", ext);
            let path = Path::new(&filename);
            detect_language(path)
        })
        .collect();

    // All should be Some("xml")
    for (ext, result) in xml_and_html.iter().zip(results.iter()) {
        assert_eq!(
            *result,
            Some("xml"),
            "Extension '{}' should return Some(\"xml\"), got {:?}",
            ext,
            result
        );
    }

    // And they should all be the SAME
    let first = results.first().unwrap();
    for (i, result) in results.iter().enumerate() {
        assert_eq!(
            *result, *first,
            "All xml-family extensions should return same value, but index {} differs",
            i
        );
    }
}
