//! Snapshot tests for `detect_language()` function behavior.
//!
//! This change merged duplicate match arms in `detect_language` that both returned
//! `Some("xml")` for XML-based extensions and HTML/HTM extensions.
//!
//! These snapshots verify the output baseline for all supported extensions.

use diffguard_domain::detect_language;
use std::path::Path;

/// Snapshot test for `detect_language` across all supported extensions.
/// This verifies that the merged match arm preserves the expected behavior.
#[test]
fn test_detect_language_all_extensions() {
    use insta::assert_snapshot;

    // All extensions that should return Some(language)
    let supported_extensions = [
        // Rust
        ("src/lib.rs", "rust"),
        // Python
        ("script.py", "python"),
        ("script.pyw", "python"),
        // JavaScript
        ("app.js", "javascript"),
        ("module.mjs", "javascript"),
        ("module.cjs", "javascript"),
        ("Component.jsx", "javascript"),
        // TypeScript
        ("app.ts", "typescript"),
        ("module.mts", "typescript"),
        ("module.cts", "typescript"),
        ("Component.tsx", "typescript"),
        // Go
        ("main.go", "go"),
        // Java
        ("Main.java", "java"),
        // Kotlin
        ("Main.kt", "kotlin"),
        ("build.kts", "kotlin"),
        // Ruby
        ("script.rb", "ruby"),
        // C
        ("main.c", "c"),
        ("header.h", "c"),
        // C++
        ("main.cpp", "cpp"),
        ("main.cc", "cpp"),
        ("main.cxx", "cpp"),
        ("header.hpp", "cpp"),
        ("header.hxx", "cpp"),
        ("header.hh", "cpp"),
        // C#
        ("Program.cs", "csharp"),
        // Shell
        ("script.sh", "shell"),
        ("script.bash", "shell"),
        ("script.zsh", "shell"),
        ("script.ksh", "shell"),
        ("script.fish", "shell"),
        // Swift
        ("main.swift", "swift"),
        // Scala
        ("Main.scala", "scala"),
        ("Main.sc", "scala"),
        // SQL
        ("query.sql", "sql"),
        // XML family (the fix being tested)
        ("document.xml", "xml"),
        ("transform.xsl", "xml"),
        ("transform.xslt", "xml"),
        ("schema.xsd", "xml"),
        ("image.svg", "xml"),
        ("page.xhtml", "xml"),
        ("page.html", "xml"),
        ("page.htm", "xml"),
        // PHP
        ("script.php", "php"),
        ("script.phtml", "php"),
        ("script.php3", "php"),
        ("script.php4", "php"),
        ("script.php5", "php"),
        ("script.php7", "php"),
        ("script.phps", "php"),
        // YAML
        ("config.yaml", "yaml"),
        ("config.yml", "yaml"),
        // TOML
        ("config.toml", "toml"),
        // JSON
        ("data.json", "json"),
        ("data.jsonc", "json"),
        ("data.json5", "json"),
    ];

    let mut snapshot = String::new();

    for (path_str, expected_lang) in supported_extensions {
        let path = Path::new(path_str);
        let result = detect_language(path);
        let result_str = match result {
            Some(lang) => format!("Some(\"{}\")", lang),
            None => "None".to_string(),
        };
        let status = if result == Some(expected_lang) {
            "✓"
        } else {
            "✗ MISMATCH"
        };
        snapshot.push_str(&format!(
            "{:30} => {:20} (expected \\\"{}\\\") {}\n",
            path_str, result_str, expected_lang, status
        ));
    }

    assert_snapshot!("detect_language_all_extensions", snapshot);
}

/// Snapshot test for unknown extensions returning None.
#[test]
fn test_detect_language_unknown_extensions() {
    use insta::assert_snapshot;

    let unknown_extensions = [
        "readme.md",
        "Makefile",
        "Dockerfile",
        "config",
        ".gitignore",
        ".env",
        "randomfile",
        "data.xml.bak",
        "document",
        "page.HTML",
        "page.HTM",
    ];

    let mut snapshot = String::new();

    for path_str in unknown_extensions {
        let path = Path::new(path_str);
        let result = detect_language(path);
        let result_str = match result {
            Some(lang) => format!("Some(\"{}\")", lang),
            None => "None".to_string(),
        };
        snapshot.push_str(&format!("{:30} => {}\n", path_str, result_str));
    }

    assert_snapshot!("detect_language_unknown_extensions", snapshot);
}

/// Snapshot test for case-insensitive extension handling.
/// Extensions should be matched case-insensitively.
#[test]
fn test_detect_language_case_insensitive() {
    use insta::assert_snapshot;

    let case_variations = [
        ("file.RS", "rust"),
        ("file.PY", "python"),
        ("file.JS", "javascript"),
        ("file.TS", "typescript"),
        ("file.GO", "go"),
        ("file.JAVA", "java"),
        ("file.KT", "kotlin"),
        ("file.XML", "xml"),
        ("file.HTML", "xml"),
        ("file.HTM", "xml"),
        ("file.JSON", "json"),
        ("file.YAML", "yaml"),
        ("file.YML", "yaml"),
    ];

    let mut snapshot = String::new();

    for (path_str, expected_lang) in case_variations {
        let path = Path::new(path_str);
        let result = detect_language(path);
        let result_str = match result {
            Some(lang) => format!("Some(\"{}\")", lang),
            None => "None".to_string(),
        };
        let status = if result == Some(expected_lang) {
            "✓"
        } else {
            "✗ MISMATCH"
        };
        snapshot.push_str(&format!(
            "{:30} => {:20} (expected \\\"{}\\\") {}\n",
            path_str, result_str, expected_lang, status
        ));
    }

    assert_snapshot!("detect_language_case_insensitive", snapshot);
}

/// Snapshot test specifically for the merged XML/HTML match arm.
/// This is the core fix - verifying HTML and HTM still map to "xml".
#[test]
fn test_detect_language_html_htm_xml() {
    use insta::assert_snapshot;

    let xml_family = [
        ("document.xml", "xml"),
        ("document.xsl", "xml"),
        ("document.xslt", "xml"),
        ("document.xsd", "xml"),
        ("image.svg", "xml"),
        ("page.xhtml", "xml"),
        ("page.html", "xml"),
        ("page.htm", "xml"),
    ];

    let mut snapshot = String::new();

    for (path_str, _expected_lang) in xml_family {
        let path = Path::new(path_str);
        let result = detect_language(path);
        let result_str = match result {
            Some(lang) => format!("Some(\"{}\")", lang),
            None => "None".to_string(),
        };
        snapshot.push_str(&format!("{:30} => {}\n", path_str, result_str));
    }

    assert_snapshot!("detect_language_html_htm_xml", snapshot);
}
