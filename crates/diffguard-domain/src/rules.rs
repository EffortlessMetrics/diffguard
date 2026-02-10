use std::collections::BTreeSet;
use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;

use diffguard_types::{RuleConfig, Severity};

#[derive(Debug, thiserror::Error)]
pub enum RuleCompileError {
    #[error("rule '{rule_id}' has no patterns")]
    MissingPatterns { rule_id: String },

    #[error("rule '{rule_id}' has invalid regex '{pattern}': {source}")]
    InvalidRegex {
        rule_id: String,
        pattern: String,
        source: regex::Error,
    },

    #[error("rule '{rule_id}' has invalid glob '{glob}': {source}")]
    InvalidGlob {
        rule_id: String,
        glob: String,
        source: globset::Error,
    },
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub severity: Severity,
    pub message: String,
    pub languages: BTreeSet<String>,
    pub patterns: Vec<Regex>,
    pub include: Option<GlobSet>,
    pub exclude: Option<GlobSet>,
    pub ignore_comments: bool,
    pub ignore_strings: bool,
}

impl CompiledRule {
    pub fn applies_to(&self, path: &Path, language: Option<&str>) -> bool {
        if self
            .include
            .as_ref()
            .is_some_and(|include| !include.is_match(path))
        {
            return false;
        }

        if self
            .exclude
            .as_ref()
            .is_some_and(|exclude| exclude.is_match(path))
        {
            return false;
        }

        if !self.languages.is_empty() {
            let Some(lang) = language else {
                return false;
            };
            if !self.languages.contains(&lang.to_ascii_lowercase()) {
                return false;
            }
        }

        true
    }
}

pub fn compile_rules(configs: &[RuleConfig]) -> Result<Vec<CompiledRule>, RuleCompileError> {
    let mut out = Vec::with_capacity(configs.len());

    for cfg in configs {
        if cfg.patterns.is_empty() {
            return Err(RuleCompileError::MissingPatterns {
                rule_id: cfg.id.clone(),
            });
        }

        let mut patterns = Vec::with_capacity(cfg.patterns.len());
        for p in &cfg.patterns {
            let r = Regex::new(p).map_err(|e| RuleCompileError::InvalidRegex {
                rule_id: cfg.id.clone(),
                pattern: p.clone(),
                source: e,
            })?;
            patterns.push(r);
        }

        let include = compile_globs(&cfg.paths, &cfg.id)?;
        let exclude = compile_globs(&cfg.exclude_paths, &cfg.id)?;

        let languages = cfg
            .languages
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();

        out.push(CompiledRule {
            id: cfg.id.clone(),
            severity: cfg.severity,
            message: cfg.message.clone(),
            languages,
            patterns,
            include,
            exclude,
            ignore_comments: cfg.ignore_comments,
            ignore_strings: cfg.ignore_strings,
        });
    }

    Ok(out)
}

fn compile_globs(globs: &[String], rule_id: &str) -> Result<Option<GlobSet>, RuleCompileError> {
    if globs.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for g in globs {
        let glob = Glob::new(g).map_err(|e| RuleCompileError::InvalidGlob {
            rule_id: rule_id.to_string(),
            glob: g.clone(),
            source: e,
        })?;
        builder.add(glob);
    }

    Ok(Some(builder.build().expect("globset build should succeed")))
}

/// Detects programming language from file extension.
/// Returns lowercase language identifier or None for unknown extensions.
pub fn detect_language(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?;
    match ext.to_ascii_lowercase().as_str() {
        "rs" => Some("rust"),
        "py" | "pyw" => Some("python"),
        "js" | "mjs" | "cjs" | "jsx" => Some("javascript"),
        "ts" | "mts" | "cts" | "tsx" => Some("typescript"),
        "go" => Some("go"),
        "java" => Some("java"),
        "kt" | "kts" => Some("kotlin"),
        "rb" | "rake" => Some("ruby"),
        "c" | "h" => Some("c"),
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" | "hh" => Some("cpp"),
        "cs" => Some("csharp"),
        "sh" | "bash" | "zsh" | "ksh" | "fish" => Some("shell"),
        "swift" => Some("swift"),
        "scala" | "sc" => Some("scala"),
        "sql" => Some("sql"),
        "xml" | "xsl" | "xslt" | "xsd" | "svg" | "xhtml" => Some("xml"),
        "html" | "htm" => Some("xml"),
        "php" | "phtml" | "php3" | "php4" | "php5" | "php7" | "phps" => Some("php"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a RuleConfig for testing with default help/url
    #[allow(clippy::too_many_arguments)]
    fn test_rule(
        id: &str,
        severity: Severity,
        message: &str,
        languages: Vec<&str>,
        patterns: Vec<&str>,
        paths: Vec<&str>,
        exclude_paths: Vec<&str>,
        ignore_comments: bool,
        ignore_strings: bool,
    ) -> RuleConfig {
        RuleConfig {
            id: id.to_string(),
            severity,
            message: message.to_string(),
            languages: languages.into_iter().map(|s| s.to_string()).collect(),
            patterns: patterns.into_iter().map(|s| s.to_string()).collect(),
            paths: paths.into_iter().map(|s| s.to_string()).collect(),
            exclude_paths: exclude_paths.into_iter().map(|s| s.to_string()).collect(),
            ignore_comments,
            ignore_strings,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        }
    }

    #[test]
    fn compile_and_match_basic_rule() {
        let cfg = test_rule(
            "x",
            Severity::Warn,
            "m",
            vec!["rust"],
            vec!["unwrap"],
            vec!["**/*.rs"],
            vec!["**/tests/**"],
            true,
            true,
        );

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        assert!(r.applies_to(Path::new("src/lib.rs"), Some("rust")));
        assert!(!r.applies_to(Path::new("src/lib.rs"), Some("python")));
        assert!(!r.applies_to(Path::new("tests/test.rs"), Some("rust")));
    }

    #[test]
    fn detect_language_rust() {
        assert_eq!(detect_language(Path::new("src/lib.rs")), Some("rust"));
    }

    #[test]
    fn detect_language_python() {
        assert_eq!(detect_language(Path::new("script.py")), Some("python"));
        assert_eq!(detect_language(Path::new("script.pyw")), Some("python"));
    }

    #[test]
    fn detect_language_javascript() {
        assert_eq!(detect_language(Path::new("app.js")), Some("javascript"));
        assert_eq!(detect_language(Path::new("module.mjs")), Some("javascript"));
        assert_eq!(detect_language(Path::new("module.cjs")), Some("javascript"));
        assert_eq!(
            detect_language(Path::new("component.jsx")),
            Some("javascript")
        );
    }

    #[test]
    fn detect_language_typescript() {
        assert_eq!(detect_language(Path::new("app.ts")), Some("typescript"));
        assert_eq!(detect_language(Path::new("module.mts")), Some("typescript"));
        assert_eq!(detect_language(Path::new("module.cts")), Some("typescript"));
        assert_eq!(
            detect_language(Path::new("component.tsx")),
            Some("typescript")
        );
    }

    #[test]
    fn detect_language_go() {
        assert_eq!(detect_language(Path::new("main.go")), Some("go"));
    }

    #[test]
    fn detect_language_java() {
        assert_eq!(detect_language(Path::new("Main.java")), Some("java"));
    }

    #[test]
    fn detect_language_kotlin() {
        assert_eq!(detect_language(Path::new("Main.kt")), Some("kotlin"));
        assert_eq!(detect_language(Path::new("build.kts")), Some("kotlin"));
    }

    #[test]
    fn detect_language_ruby() {
        assert_eq!(detect_language(Path::new("script.rb")), Some("ruby"));
        assert_eq!(detect_language(Path::new("Rakefile.rake")), Some("ruby"));
    }

    #[test]
    fn detect_language_c() {
        assert_eq!(detect_language(Path::new("main.c")), Some("c"));
        assert_eq!(detect_language(Path::new("header.h")), Some("c"));
    }

    #[test]
    fn detect_language_cpp() {
        assert_eq!(detect_language(Path::new("main.cpp")), Some("cpp"));
        assert_eq!(detect_language(Path::new("main.cc")), Some("cpp"));
        assert_eq!(detect_language(Path::new("main.cxx")), Some("cpp"));
        assert_eq!(detect_language(Path::new("header.hpp")), Some("cpp"));
        assert_eq!(detect_language(Path::new("header.hxx")), Some("cpp"));
        assert_eq!(detect_language(Path::new("header.hh")), Some("cpp"));
    }

    #[test]
    fn detect_language_csharp() {
        assert_eq!(detect_language(Path::new("Program.cs")), Some("csharp"));
    }

    #[test]
    fn detect_language_shell() {
        assert_eq!(detect_language(Path::new("script.sh")), Some("shell"));
        assert_eq!(detect_language(Path::new("script.bash")), Some("shell"));
        assert_eq!(detect_language(Path::new("script.zsh")), Some("shell"));
        assert_eq!(detect_language(Path::new("script.ksh")), Some("shell"));
        assert_eq!(detect_language(Path::new("script.fish")), Some("shell"));
    }

    #[test]
    fn detect_language_unknown() {
        assert_eq!(detect_language(Path::new("file.txt")), None);
        assert_eq!(detect_language(Path::new("file.md")), None);
        assert_eq!(detect_language(Path::new("file.json")), None);
        assert_eq!(detect_language(Path::new("file.yaml")), None);
        assert_eq!(detect_language(Path::new("file")), None);
    }

    #[test]
    fn detect_language_swift() {
        assert_eq!(detect_language(Path::new("app.swift")), Some("swift"));
        assert_eq!(detect_language(Path::new("App.SWIFT")), Some("swift"));
    }

    #[test]
    fn detect_language_scala() {
        assert_eq!(detect_language(Path::new("app.scala")), Some("scala"));
        assert_eq!(detect_language(Path::new("app.sc")), Some("scala"));
        assert_eq!(detect_language(Path::new("App.SCALA")), Some("scala"));
    }

    #[test]
    fn detect_language_sql() {
        assert_eq!(detect_language(Path::new("query.sql")), Some("sql"));
        assert_eq!(detect_language(Path::new("Query.SQL")), Some("sql"));
    }

    #[test]
    fn detect_language_xml() {
        assert_eq!(detect_language(Path::new("config.xml")), Some("xml"));
        assert_eq!(detect_language(Path::new("style.xsl")), Some("xml"));
        assert_eq!(detect_language(Path::new("transform.xslt")), Some("xml"));
        assert_eq!(detect_language(Path::new("schema.xsd")), Some("xml"));
        assert_eq!(detect_language(Path::new("icon.svg")), Some("xml"));
        assert_eq!(detect_language(Path::new("page.xhtml")), Some("xml"));
        assert_eq!(detect_language(Path::new("page.html")), Some("xml"));
        assert_eq!(detect_language(Path::new("page.htm")), Some("xml"));
    }

    #[test]
    fn detect_language_php() {
        assert_eq!(detect_language(Path::new("index.php")), Some("php"));
        assert_eq!(detect_language(Path::new("template.phtml")), Some("php"));
        assert_eq!(detect_language(Path::new("legacy.php3")), Some("php"));
        assert_eq!(detect_language(Path::new("legacy.php4")), Some("php"));
        assert_eq!(detect_language(Path::new("legacy.php5")), Some("php"));
        assert_eq!(detect_language(Path::new("modern.php7")), Some("php"));
        assert_eq!(detect_language(Path::new("highlight.phps")), Some("php"));
    }

    #[test]
    fn detect_language_case_insensitive() {
        // Test that extension matching is case-insensitive
        assert_eq!(detect_language(Path::new("file.RS")), Some("rust"));
        assert_eq!(detect_language(Path::new("file.PY")), Some("python"));
        assert_eq!(detect_language(Path::new("file.JS")), Some("javascript"));
        assert_eq!(detect_language(Path::new("file.TS")), Some("typescript"));
        assert_eq!(detect_language(Path::new("file.CPP")), Some("cpp"));
    }

    // =========================================================================
    // Rule Matching Tests - Task 12.3
    // Requirements: 9.4, 9.5
    // =========================================================================

    // --- Overlapping Patterns Tests (first match wins) ---

    #[test]
    fn overlapping_patterns_first_pattern_wins() {
        // When multiple patterns could match, the first pattern in the list wins
        let cfg = RuleConfig {
            id: "test.overlapping".to_string(),
            severity: Severity::Warn,
            message: "found match".to_string(),
            languages: vec![],
            patterns: vec![
                "foo".to_string(),    // First pattern
                "foobar".to_string(), // Second pattern (more specific)
            ],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Both patterns could match "foobar", but first_match should return "foo"
        let content = "foobar";
        let m = r
            .patterns
            .iter()
            .find_map(|p| p.find(content))
            .expect("Expected a pattern to match");
        // First pattern "foo" should match at position 0-3
        assert_eq!(m.start(), 0);
        assert_eq!(m.end(), 3);
        assert_eq!(&content[m.start()..m.end()], "foo");
    }

    #[test]
    fn overlapping_rules_first_rule_wins() {
        // When multiple rules could match the same content, both produce findings
        // but the order of findings follows the rule order
        let configs = vec![
            RuleConfig {
                id: "rule.first".to_string(),
                severity: Severity::Warn,
                message: "first rule".to_string(),
                languages: vec![],
                patterns: vec!["error".to_string()],
                paths: vec![],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                help: None,
                url: None,
                tags: vec![],
                test_cases: vec![],
            },
            RuleConfig {
                id: "rule.second".to_string(),
                severity: Severity::Error,
                message: "second rule".to_string(),
                languages: vec![],
                patterns: vec!["error".to_string()],
                paths: vec![],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                help: None,
                url: None,
                tags: vec![],
                test_cases: vec![],
            },
        ];

        let rules = compile_rules(&configs).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "rule.first");
        assert_eq!(rules[1].id, "rule.second");
    }

    #[test]
    fn overlapping_patterns_specific_vs_general() {
        // Test that pattern order matters: general pattern first catches everything
        let cfg = RuleConfig {
            id: "test.general_first".to_string(),
            severity: Severity::Warn,
            message: "found".to_string(),
            languages: vec![],
            patterns: vec![
                r"\w+".to_string(),      // General: matches any word
                r"specific".to_string(), // Specific: matches only "specific"
            ],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // The general pattern should match first
        let content = "specific";
        let m = r.patterns[0]
            .find(content)
            .expect("Expected specific pattern to match");
        assert_eq!(&content[m.start()..m.end()], "specific");
    }

    // --- Complex Glob Pattern Tests ---

    #[test]
    fn glob_pattern_recursive_wildcard() {
        // Test **/*.rs matches files in any subdirectory
        let cfg = RuleConfig {
            id: "test.glob".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()],
            paths: vec!["**/*.rs".to_string()],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should match files at any depth
        assert!(r.applies_to(Path::new("lib.rs"), None));
        assert!(r.applies_to(Path::new("src/lib.rs"), None));
        assert!(r.applies_to(Path::new("src/foo/bar/lib.rs"), None));
        assert!(r.applies_to(Path::new("deeply/nested/path/to/file.rs"), None));

        // Should not match non-.rs files
        assert!(!r.applies_to(Path::new("src/lib.py"), None));
        assert!(!r.applies_to(Path::new("src/lib.rs.bak"), None));
    }

    #[test]
    fn glob_pattern_specific_directory() {
        // Test src/**/*.ts matches only files under src/
        let cfg = RuleConfig {
            id: "test.glob".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()],
            paths: vec!["src/**/*.ts".to_string()],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should match files under src/
        assert!(r.applies_to(Path::new("src/app.ts"), None));
        assert!(r.applies_to(Path::new("src/components/Button.ts"), None));
        assert!(r.applies_to(Path::new("src/a/b/c/d.ts"), None));

        // Should not match files outside src/
        assert!(!r.applies_to(Path::new("app.ts"), None));
        assert!(!r.applies_to(Path::new("lib/app.ts"), None));
        assert!(!r.applies_to(Path::new("tests/app.ts"), None));
    }

    #[test]
    fn glob_pattern_exclude_test_directories() {
        // Test excluding **/test/** and **/tests/**
        let cfg = RuleConfig {
            id: "test.glob".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()],
            paths: vec!["**/*.rs".to_string()],
            exclude_paths: vec!["**/test/**".to_string(), "**/tests/**".to_string()],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should match regular source files
        assert!(r.applies_to(Path::new("src/lib.rs"), None));
        assert!(r.applies_to(Path::new("src/foo/bar.rs"), None));

        // Should exclude test directories
        assert!(!r.applies_to(Path::new("test/lib.rs"), None));
        assert!(!r.applies_to(Path::new("tests/lib.rs"), None));
        assert!(!r.applies_to(Path::new("src/test/lib.rs"), None));
        assert!(!r.applies_to(Path::new("src/tests/lib.rs"), None));
        assert!(!r.applies_to(Path::new("foo/test/bar.rs"), None));
        assert!(!r.applies_to(Path::new("foo/tests/bar.rs"), None));
    }

    #[test]
    fn glob_pattern_multiple_extensions() {
        // Test matching multiple file extensions
        let cfg = RuleConfig {
            id: "test.glob".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()],
            paths: vec![
                "**/*.js".to_string(),
                "**/*.ts".to_string(),
                "**/*.jsx".to_string(),
                "**/*.tsx".to_string(),
            ],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should match all specified extensions
        assert!(r.applies_to(Path::new("src/app.js"), None));
        assert!(r.applies_to(Path::new("src/app.ts"), None));
        assert!(r.applies_to(Path::new("src/App.jsx"), None));
        assert!(r.applies_to(Path::new("src/App.tsx"), None));

        // Should not match other extensions
        assert!(!r.applies_to(Path::new("src/app.py"), None));
        assert!(!r.applies_to(Path::new("src/app.rs"), None));
    }

    #[test]
    fn glob_pattern_exclude_specific_files() {
        // Test excluding specific file patterns like *.test.* and *.spec.*
        let cfg = RuleConfig {
            id: "test.glob".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()],
            paths: vec!["**/*.ts".to_string()],
            exclude_paths: vec!["**/*.test.ts".to_string(), "**/*.spec.ts".to_string()],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should match regular TypeScript files
        assert!(r.applies_to(Path::new("src/app.ts"), None));
        assert!(r.applies_to(Path::new("src/utils/helper.ts"), None));

        // Should exclude test and spec files
        assert!(!r.applies_to(Path::new("src/app.test.ts"), None));
        assert!(!r.applies_to(Path::new("src/app.spec.ts"), None));
        assert!(!r.applies_to(Path::new("src/utils/helper.test.ts"), None));
        assert!(!r.applies_to(Path::new("src/utils/helper.spec.ts"), None));
    }

    #[test]
    fn glob_pattern_no_include_matches_all() {
        // When no include paths are specified, rule applies to all files
        let cfg = RuleConfig {
            id: "test.glob".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()],
            paths: vec![], // Empty - matches all
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should match any file
        assert!(r.applies_to(Path::new("anything.txt"), None));
        assert!(r.applies_to(Path::new("src/lib.rs"), None));
        assert!(r.applies_to(Path::new("deeply/nested/file.py"), None));
    }

    // --- Language Filtering Edge Cases ---

    #[test]
    fn language_filter_empty_matches_all() {
        // When no languages are specified, rule applies to all languages
        let cfg = RuleConfig {
            id: "test.lang".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec![], // Empty - matches all
            patterns: vec!["x".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should match any language
        assert!(r.applies_to(Path::new("file.rs"), Some("rust")));
        assert!(r.applies_to(Path::new("file.py"), Some("python")));
        assert!(r.applies_to(Path::new("file.js"), Some("javascript")));
        // Should also match when language is None (unknown extension)
        assert!(r.applies_to(Path::new("file.txt"), None));
    }

    #[test]
    fn language_filter_single_language() {
        // Rule with single language filter
        let cfg = RuleConfig {
            id: "test.lang".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec!["rust".to_string()],
            patterns: vec!["x".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should only match Rust
        assert!(r.applies_to(Path::new("file.rs"), Some("rust")));
        assert!(!r.applies_to(Path::new("file.py"), Some("python")));
        assert!(!r.applies_to(Path::new("file.js"), Some("javascript")));
        // Should not match when language is None
        assert!(!r.applies_to(Path::new("file.txt"), None));
    }

    #[test]
    fn language_filter_multiple_languages() {
        // Rule with multiple language filters
        let cfg = RuleConfig {
            id: "test.lang".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec!["javascript".to_string(), "typescript".to_string()],
            patterns: vec!["x".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should match JavaScript and TypeScript
        assert!(r.applies_to(Path::new("file.js"), Some("javascript")));
        assert!(r.applies_to(Path::new("file.ts"), Some("typescript")));
        // Should not match other languages
        assert!(!r.applies_to(Path::new("file.rs"), Some("rust")));
        assert!(!r.applies_to(Path::new("file.py"), Some("python")));
    }

    #[test]
    fn language_filter_case_insensitive() {
        // Language matching should be case-insensitive
        let cfg = RuleConfig {
            id: "test.lang".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec!["RUST".to_string()], // Uppercase in config
            patterns: vec!["x".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should match regardless of case
        assert!(r.applies_to(Path::new("file.rs"), Some("rust")));
        assert!(r.applies_to(Path::new("file.rs"), Some("Rust")));
        assert!(r.applies_to(Path::new("file.rs"), Some("RUST")));
    }

    #[test]
    fn language_filter_with_path_filter_combined() {
        // Both language and path filters must match
        let cfg = RuleConfig {
            id: "test.combined".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec!["rust".to_string()],
            patterns: vec!["x".to_string()],
            paths: vec!["src/**/*.rs".to_string()],
            exclude_paths: vec!["**/tests/**".to_string()],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Must match both language AND path
        assert!(r.applies_to(Path::new("src/lib.rs"), Some("rust")));
        assert!(r.applies_to(Path::new("src/foo/bar.rs"), Some("rust")));

        // Wrong language - should not match
        assert!(!r.applies_to(Path::new("src/lib.rs"), Some("python")));

        // Wrong path - should not match
        assert!(!r.applies_to(Path::new("lib/lib.rs"), Some("rust")));

        // Excluded path - should not match
        assert!(!r.applies_to(Path::new("src/tests/lib.rs"), Some("rust")));

        // No language detected - should not match when language filter is set
        assert!(!r.applies_to(Path::new("src/lib.rs"), None));
    }

    #[test]
    fn language_filter_unknown_language_in_config() {
        // Rule with an unknown/custom language identifier
        let cfg = RuleConfig {
            id: "test.lang".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec!["customlang".to_string()],
            patterns: vec!["x".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should match when the custom language is provided
        assert!(r.applies_to(Path::new("file.custom"), Some("customlang")));
        // Should not match other languages
        assert!(!r.applies_to(Path::new("file.rs"), Some("rust")));
    }

    #[test]
    fn language_filter_none_language_with_filter() {
        // When language filter is set but file has no detected language
        let cfg = RuleConfig {
            id: "test.lang".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec!["rust".to_string()],
            patterns: vec!["x".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };

        let rules = compile_rules(&[cfg]).unwrap();
        let r = &rules[0];

        // Should not match when language is None and filter is set
        assert!(!r.applies_to(Path::new("file.txt"), None));
        assert!(!r.applies_to(Path::new("Makefile"), None));
        assert!(!r.applies_to(Path::new("README.md"), None));
    }
}
