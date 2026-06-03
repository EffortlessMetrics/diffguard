//! Integration tests for work-53f352f9: detect_language duplicate match arms
//!
//! Issue #306: detect_language had two adjacent match arms both returning Some("xml")
//! for (xml, xsl, xslt, xsd, svg, xhtml) and (html, htm).
//!
//! These integration tests verify the component handoffs:
//! 1. detect_language -> CompiledRule::applies_to (HTML/HTM files match xml-language rules)
//! 2. detect_language -> evaluate_lines (HTML/HTM files are preprocessed as XML)
//! 3. Full flow: rule applies to HTML file -> evaluation produces findings
//!
//! The fix merged the two match arms into one: "xml" | "xsl" | ... | "html" | "htm"

use diffguard_domain::evaluate::{InputLine, evaluate_lines};
use diffguard_domain::preprocess::Language;
use diffguard_domain::rules::{compile_rules, detect_language};
use diffguard_types::RuleConfig;
use diffguard_types::Severity;
use std::path::Path;

/// Helper to create a RuleConfig for testing XML language rules
fn xml_rule(id: &str, patterns: Vec<&str>, paths: Vec<&str>) -> RuleConfig {
    RuleConfig {
        id: id.to_string(),
        description: String::new(),
        severity: Severity::Warn,
        message: "test pattern found".to_string(),
        languages: vec!["xml".to_string()],
        patterns: patterns.into_iter().map(|s| s.to_string()).collect(),
        paths: paths.into_iter().map(|s| s.to_string()).collect(),
        exclude_paths: vec![],
        ignore_comments: false,
        ignore_strings: false,
        match_mode: Default::default(),
        multiline: false,
        multiline_window: None,
        context_patterns: vec![],
        context_window: None,
        escalate_patterns: vec![],
        escalate_window: None,
        escalate_to: None,
        depends_on: vec![],
        help: None,
        url: None,
        tags: vec![],
        test_cases: vec![],
    }
}

/// Integration test: detect_language output feeds into CompiledRule::applies_to
///
/// Verifies the handoff: HTML/HTM files detect as "xml" → xml-language rule applies
#[test]
fn test_html_htm_files_match_xml_language_rules() {
    let cfg = xml_rule("xml-pattern", vec!["TODO"], vec!["**/*"]);
    let rules = compile_rules(&[cfg]).unwrap();

    // HTML files should match xml-language rules
    assert!(
        rules[0].applies_to(Path::new("page.html"), Some("xml")),
        "page.html (detected as xml) should match xml-language rule"
    );
    assert!(
        rules[0].applies_to(Path::new("page.htm"), Some("xml")),
        "page.htm (detected as xml) should match xml-language rule"
    );
    assert!(
        rules[0].applies_to(Path::new("src/page.html"), Some("xml")),
        "src/page.html (detected as xml) should match xml-language rule"
    );
    assert!(
        rules[0].applies_to(Path::new("dir/page.htm"), Some("xml")),
        "dir/page.htm (detected as xml) should match xml-language rule"
    );

    // Other XML family files should also match
    assert!(
        rules[0].applies_to(Path::new("config.xml"), Some("xml")),
        "config.xml should match xml-language rule"
    );
    assert!(
        rules[0].applies_to(Path::new("icon.svg"), Some("xml")),
        "icon.svg should match xml-language rule"
    );
}

/// Integration test: detect_language is called internally during evaluation
///
/// Verifies the handoff: evaluate_lines calls detect_language for HTML/HTM files
/// and uses the "xml" language to set up preprocessing.
#[test]
fn test_evaluate_lines_uses_detect_language_for_html_files() {
    let cfg = xml_rule("xml-pattern", vec!["TODO"], vec!["**/*"]);
    let rules = compile_rules(&[cfg]).unwrap();

    let input_lines = vec![
        InputLine {
            path: "page.html".to_string(),
            line: 1,
            content: "<!-- TODO: fix this -->".to_string(),
        },
        InputLine {
            path: "page.html".to_string(),
            line: 2,
            content: "<p>Hello world</p>".to_string(),
        },
    ];

    let evaluation = evaluate_lines(input_lines, &rules, 100);

    // Should find the TODO in the HTML file (preprocessed as XML)
    assert!(
        !evaluation.findings.is_empty(),
        "Should produce findings for TODO in HTML file"
    );
    assert_eq!(
        evaluation.findings[0].rule_id, "xml-pattern",
        "Finding should be from xml-pattern rule"
    );
    assert_eq!(
        evaluation.findings[0].path, "page.html",
        "Finding should be for page.html"
    );
}

/// Integration test: Full end-to-end flow with multiple HTML/HTM files
///
/// Verifies: file path → detect_language → rule applies → evaluation produces findings
#[test]
fn test_full_flow_html_htm_evaluation() {
    let cfg = xml_rule("xml-pattern", vec!["FIXME"], vec!["**/*"]);
    let rules = compile_rules(&[cfg]).unwrap();

    let input_lines = vec![
        // HTML file
        InputLine {
            path: "index.html".to_string(),
            line: 1,
            content: "<html>".to_string(),
        },
        InputLine {
            path: "index.html".to_string(),
            line: 2,
            content: "<!-- FIXME: needs redesign -->".to_string(),
        },
        InputLine {
            path: "index.html".to_string(),
            line: 3,
            content: "</html>".to_string(),
        },
        // HTM file
        InputLine {
            path: "old.htm".to_string(),
            line: 1,
            content: "<body>".to_string(),
        },
        InputLine {
            path: "old.htm".to_string(),
            line: 2,
            content: "<!-- FIXME: legacy code -->".to_string(),
        },
        InputLine {
            path: "old.htm".to_string(),
            line: 3,
            content: "</body>".to_string(),
        },
        // XHTML file (also xml)
        InputLine {
            path: "doc.xhtml".to_string(),
            line: 1,
            content: "<!-- FIXME: incomplete -->".to_string(),
        },
    ];

    let evaluation = evaluate_lines(input_lines, &rules, 100);

    // Should find FIXME in all three files
    assert_eq!(
        evaluation.findings.len(),
        3,
        "Should find FIXME in all three files (html, htm, xhtml)"
    );

    let paths: Vec<_> = evaluation
        .findings
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    assert!(
        paths.contains(&"index.html"),
        "Should find FIXME in index.html"
    );
    assert!(paths.contains(&"old.htm"), "Should find FIXME in old.htm");
    assert!(
        paths.contains(&"doc.xhtml"),
        "Should find FIXME in doc.xhtml"
    );
}

/// Integration test: HTML files with no match should produce no findings
///
/// Verifies the negative case: when pattern doesn't match, no findings produced.
#[test]
fn test_no_findings_when_pattern_not_present() {
    let cfg = xml_rule("xml-pattern", vec!["UNIQUE_PATTERN_12345"], vec!["**/*"]);
    let rules = compile_rules(&[cfg]).unwrap();

    let input_lines = vec![InputLine {
        path: "page.html".to_string(),
        line: 1,
        content: "<html><body>No special pattern here</body></html>".to_string(),
    }];

    let evaluation = evaluate_lines(input_lines, &rules, 100);

    assert!(
        evaluation.findings.is_empty(),
        "Should produce no findings when pattern not present"
    );
}

/// Integration test: Language detection via detect_language is case-insensitive
///
/// Verifies: HTML.HTM (uppercase) also detects as "xml"
#[test]
fn test_case_insensitive_language_detection_html_htm() {
    // detect_language is case-insensitive for extensions
    assert_eq!(
        detect_language(Path::new("page.HTML")),
        Some("xml"),
        "page.HTML should detect as xml (case-insensitive)"
    );
    assert_eq!(
        detect_language(Path::new("page.HTM")),
        Some("xml"),
        "page.HTM should detect as xml (case-insensitive)"
    );
    assert_eq!(
        detect_language(Path::new("page.HtMl")),
        Some("xml"),
        "page.HtMl should detect as xml (case-insensitive)"
    );
}

/// Integration test: Non-HTML files should not match xml-language rules
///
/// Verifies: .js, .py, .rs files should not match xml-language rules
#[test]
fn test_non_xml_files_do_not_match_xml_rules() {
    let cfg = xml_rule("xml-pattern", vec!["TODO"], vec!["**/*"]);
    let rules = compile_rules(&[cfg]).unwrap();

    // JavaScript file should NOT match xml-language rule (even though it has a pattern)
    assert!(
        !rules[0].applies_to(Path::new("script.js"), Some("javascript")),
        "JavaScript file should not match xml-language rule"
    );
    assert!(
        !rules[0].applies_to(Path::new("script.py"), Some("python")),
        "Python file should not match xml-language rule"
    );
    assert!(
        !rules[0].applies_to(Path::new("lib.rs"), Some("rust")),
        "Rust file should not match xml-language rule"
    );
    assert!(
        !rules[0].applies_to(Path::new("main.go"), Some("go")),
        "Go file should not match xml-language rule"
    );
}

/// Integration test: evaluate_lines uses correct language enum for HTML
///
/// Verifies: Language::from_str("xml") correctly parses for HTML files
#[test]
fn test_language_enum_xml_parsing() {
    use std::str::FromStr;

    assert_eq!(
        Language::from_str("xml"),
        Ok(Language::Xml),
        "xml string should parse to Language::Xml"
    );

    // HTML/HTM files map to Language::Xml via detect_language -> "xml" -> Language::Xml
    let lang = detect_language(Path::new("page.html")).and_then(|s| s.parse::<Language>().ok());
    assert_eq!(
        lang,
        Some(Language::Xml),
        "HTML file should detect as Language::Xml"
    );
}
