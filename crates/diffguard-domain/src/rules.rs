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
        if let Some(include) = &self.include {
            if !include.is_match(path) {
                return false;
            }
        }

        if let Some(exclude) = &self.exclude {
            if exclude.is_match(path) {
                return false;
            }
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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_and_match_basic_rule() {
        let cfg = RuleConfig {
            id: "x".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec!["rust".to_string()],
            patterns: vec!["unwrap".to_string()],
            paths: vec!["**/*.rs".to_string()],
            exclude_paths: vec!["**/tests/**".to_string()],
            ignore_comments: true,
            ignore_strings: true,
        };

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
    fn detect_language_unknown() {
        assert_eq!(detect_language(Path::new("file.txt")), None);
        assert_eq!(detect_language(Path::new("file.md")), None);
        assert_eq!(detect_language(Path::new("file.json")), None);
        assert_eq!(detect_language(Path::new("file.yaml")), None);
        assert_eq!(detect_language(Path::new("file")), None);
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
}
