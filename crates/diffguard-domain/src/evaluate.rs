use std::collections::BTreeSet;

use diffguard_types::{Finding, Severity, VerdictCounts};

use crate::preprocess::{Language, PreprocessOptions, Preprocessor};
use crate::rules::{detect_language, CompiledRule};
use crate::suppression::SuppressionTracker;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputLine {
    pub path: String,
    pub line: u32,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub findings: Vec<Finding>,
    pub counts: VerdictCounts,
    pub truncated_findings: u32,
    pub files_scanned: u32,
    pub lines_scanned: u32,
}

pub fn evaluate_lines(
    lines: impl IntoIterator<Item = InputLine>,
    rules: &[CompiledRule],
    max_findings: usize,
) -> Evaluation {
    let mut findings: Vec<Finding> = Vec::new();
    let mut counts = VerdictCounts::default();
    let mut truncated_findings: u32 = 0;

    let mut files_seen = BTreeSet::<String>::new();
    let mut lines_scanned: u32 = 0;

    let mut current_file: Option<String> = None;
    let mut current_lang = Language::Unknown;
    let mut p_comments =
        Preprocessor::with_language(PreprocessOptions::comments_only(), current_lang);
    let mut p_strings =
        Preprocessor::with_language(PreprocessOptions::strings_only(), current_lang);
    let mut p_both =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), current_lang);

    // Suppression tracker for inline directives
    let mut suppression_tracker = SuppressionTracker::new();

    for l in lines {
        lines_scanned = lines_scanned.saturating_add(1);
        files_seen.insert(l.path.clone());

        if current_file.as_deref() != Some(&l.path) {
            current_file = Some(l.path.clone());

            // Detect language from file path and update preprocessors
            let path = std::path::Path::new(&l.path);
            let lang_str = detect_language(path);
            current_lang = lang_str
                .map(|s| s.parse::<Language>().unwrap_or(Language::Unknown))
                .unwrap_or(Language::Unknown);

            // Update preprocessors with the new language
            p_comments.set_language(current_lang);
            p_strings.set_language(current_lang);
            p_both.set_language(current_lang);

            // Reset suppression tracker when switching files
            suppression_tracker.reset();
        }

        let path = std::path::Path::new(&l.path);
        let lang = detect_language(path);

        let masked_comments = p_comments.sanitize_line(&l.content);
        // Parse suppressions from the RAW line, but only if the directive
        // is inside a masked comment span.
        let effective_suppressions = suppression_tracker.process_line(&l.content, &masked_comments);
        let masked_strings = p_strings.sanitize_line(&l.content);
        let masked_both = p_both.sanitize_line(&l.content);

        for r in rules {
            if !r.applies_to(path, lang) {
                continue;
            }

            let candidate = match (r.ignore_comments, r.ignore_strings) {
                (true, true) => masked_both.as_str(),
                (true, false) => masked_comments.as_str(),
                (false, true) => masked_strings.as_str(),
                (false, false) => l.content.as_str(),
            };

            if let Some((m_start, m_end)) = first_match(&r.patterns, candidate) {
                // Check if this rule is suppressed for this line
                if effective_suppressions.is_suppressed(&r.id) {
                    counts.suppressed = counts.suppressed.saturating_add(1);
                    continue;
                }

                bump_counts(&mut counts, r.severity);

                if findings.len() < max_findings {
                    let column = byte_to_column(&l.content, m_start).map(|c| c as u32);
                    let match_text = safe_slice(&l.content, m_start, m_end);

                    findings.push(Finding {
                        rule_id: r.id.clone(),
                        severity: r.severity,
                        message: r.message.clone(),
                        path: l.path.clone(),
                        line: l.line,
                        column,
                        match_text,
                        snippet: trim_snippet(&l.content),
                    });
                } else {
                    truncated_findings = truncated_findings.saturating_add(1);
                }
            }
        }
    }

    Evaluation {
        findings,
        counts,
        truncated_findings,
        files_scanned: files_seen.len() as u32,
        lines_scanned,
    }
}

fn first_match(patterns: &[regex::Regex], s: &str) -> Option<(usize, usize)> {
    for p in patterns {
        if let Some(m) = p.find(s) {
            return Some((m.start(), m.end()));
        }
    }
    None
}

fn bump_counts(counts: &mut VerdictCounts, severity: Severity) {
    match severity {
        Severity::Info => counts.info = counts.info.saturating_add(1),
        Severity::Warn => counts.warn = counts.warn.saturating_add(1),
        Severity::Error => counts.error = counts.error.saturating_add(1),
    }
}

fn trim_snippet(s: &str) -> String {
    let trimmed = s.trim_end();
    const MAX_CHARS: usize = 240;

    // Avoid slicing by byte indices (which can panic on Unicode boundaries).
    let mut out = String::new();
    for (i, ch) in trimmed.chars().enumerate() {
        if i >= MAX_CHARS {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

fn safe_slice(s: &str, start: usize, end: usize) -> String {
    let end = end.min(s.len());
    let start = start.min(end);
    s.get(start..end).unwrap_or("").to_string()
}

fn byte_to_column(s: &str, byte_idx: usize) -> Option<usize> {
    if byte_idx > s.len() {
        return None;
    }
    Some(s[..byte_idx].chars().count() + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::compile_rules;
    use diffguard_types::RuleConfig;

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
        }
    }

    #[test]
    fn finds_unwrap_in_added_line() {
        let rules = compile_rules(&[test_rule(
            "rust.no_unwrap",
            Severity::Error,
            "no",
            vec!["rust"],
            vec!["\\.unwrap\\("],
            vec!["**/*.rs"],
            vec![],
            true,
            true,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "src/lib.rs".to_string(),
                line: 12,
                content: "let x = y.unwrap();".to_string(),
            }],
            &rules,
            100,
        );

        assert_eq!(eval.counts.error, 1);
        assert_eq!(eval.findings.len(), 1);
        assert_eq!(eval.findings[0].line, 12);
        assert!(eval.findings[0].column.is_some());
    }

    #[test]
    fn does_not_match_in_comment_when_ignored() {
        let rules = compile_rules(&[test_rule(
            "rust.no_unwrap",
            Severity::Error,
            "no",
            vec!["rust"],
            vec!["unwrap"],
            vec!["**/*.rs"],
            vec![],
            true,
            false,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "src/lib.rs".to_string(),
                line: 1,
                content: "// unwrap should be ignored".to_string(),
            }],
            &rules,
            100,
        );

        assert_eq!(eval.counts.error, 0);
    }

    #[test]
    fn caps_findings_but_keeps_counts() {
        let rules = compile_rules(&[test_rule(
            "r",
            Severity::Warn,
            "m",
            vec![],
            vec!["x"],
            vec![],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let lines = (0..5).map(|i| InputLine {
            path: "a.txt".to_string(),
            line: i,
            content: "x".to_string(),
        });

        let eval = evaluate_lines(lines, &rules, 2);
        assert_eq!(eval.counts.warn, 5);
        assert_eq!(eval.findings.len(), 2);
        assert_eq!(eval.truncated_findings, 3);
    }

    #[test]
    fn trim_snippet_truncates_and_appends_ellipsis() {
        let long = "a".repeat(300);
        let trimmed = super::trim_snippet(&long);

        assert!(trimmed.ends_with('…'));
        assert_eq!(trimmed.chars().count(), 241);
        assert!(trimmed.len() <= long.len() + 3);
    }

    #[test]
    fn python_hash_comment_ignored_with_language_aware_preprocessing() {
        // This test verifies that Python hash comments are properly ignored
        // when processing Python files (language-aware preprocessing)
        let rules = compile_rules(&[test_rule(
            "python.no_print",
            Severity::Warn,
            "no print",
            vec!["python"],
            vec![r"\bprint\s*\("],
            vec!["**/*.py"],
            vec![],
            true,
            false,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "src/main.py".to_string(),
                line: 1,
                content: "# print() should be ignored in comment".to_string(),
            }],
            &rules,
            100,
        );

        // Hash comment should be masked for Python files
        assert_eq!(eval.counts.warn, 0);
        assert_eq!(eval.findings.len(), 0);
    }

    #[test]
    fn python_print_detected_outside_comment() {
        // This test verifies that print() is detected when not in a comment
        let rules = compile_rules(&[test_rule(
            "python.no_print",
            Severity::Warn,
            "no print",
            vec!["python"],
            vec![r"\bprint\s*\("],
            vec!["**/*.py"],
            vec![],
            true,
            false,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "src/main.py".to_string(),
                line: 1,
                content: "print('hello')".to_string(),
            }],
            &rules,
            100,
        );

        assert_eq!(eval.counts.warn, 1);
        assert_eq!(eval.findings.len(), 1);
    }

    #[test]
    fn javascript_template_literal_ignored_with_language_aware_preprocessing() {
        // This test verifies that JavaScript template literals are properly ignored
        let rules = compile_rules(&[test_rule(
            "js.no_console",
            Severity::Warn,
            "no console",
            vec!["javascript"],
            vec![r"\bconsole\.log\s*\("],
            vec!["**/*.js"],
            vec![],
            false,
            true,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "src/main.js".to_string(),
                line: 1,
                content: "const msg = `console.log() in template literal`;".to_string(),
            }],
            &rules,
            100,
        );

        // Template literal should be masked for JavaScript files
        assert_eq!(eval.counts.warn, 0);
        assert_eq!(eval.findings.len(), 0);
    }

    #[test]
    fn go_backtick_raw_string_ignored_with_language_aware_preprocessing() {
        // This test verifies that Go backtick raw strings are properly ignored
        let rules = compile_rules(&[test_rule(
            "go.no_fmt_print",
            Severity::Warn,
            "no fmt.Println",
            vec!["go"],
            vec![r"\bfmt\.Println\s*\("],
            vec!["**/*.go"],
            vec![],
            false,
            true,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "src/main.go".to_string(),
                line: 1,
                content: "var s = `fmt.Println() in raw string`".to_string(),
            }],
            &rules,
            100,
        );

        // Backtick raw string should be masked for Go files
        assert_eq!(eval.counts.warn, 0);
        assert_eq!(eval.findings.len(), 0);
    }

    #[test]
    fn language_changes_between_files() {
        // This test verifies that the preprocessor correctly switches languages
        // when processing files with different extensions
        let rules = compile_rules(&[test_rule(
            "detect_pattern",
            Severity::Warn,
            "found pattern",
            vec![],
            vec!["pattern"],
            vec![],
            vec![],
            true,
            false,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [
                // Python file - hash comment should be ignored
                InputLine {
                    path: "src/main.py".to_string(),
                    line: 1,
                    content: "# pattern in python comment".to_string(),
                },
                // Rust file - hash is NOT a comment, should be detected
                InputLine {
                    path: "src/lib.rs".to_string(),
                    line: 1,
                    content: "# pattern in rust (not a comment)".to_string(),
                },
            ],
            &rules,
            100,
        );

        // Only the Rust file should have a finding (hash is not a comment in Rust)
        assert_eq!(eval.counts.warn, 1);
        assert_eq!(eval.findings.len(), 1);
        assert_eq!(eval.findings[0].path, "src/lib.rs");
    }

    // ==================== Suppression tests ====================

    #[test]
    fn suppression_same_line_ignores_specific_rule() {
        let rules = compile_rules(&[test_rule(
            "rust.no_unwrap",
            Severity::Error,
            "no unwrap",
            vec!["rust"],
            vec!["\\.unwrap\\("],
            vec!["**/*.rs"],
            vec![],
            true,
            true,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "src/lib.rs".to_string(),
                line: 1,
                content: "let x = y.unwrap(); // diffguard: ignore rust.no_unwrap".to_string(),
            }],
            &rules,
            100,
        );

        assert_eq!(eval.counts.error, 0);
        assert_eq!(eval.counts.suppressed, 1);
        assert!(eval.findings.is_empty());
    }

    #[test]
    fn suppression_same_line_wildcard() {
        let rules = compile_rules(&[test_rule(
            "rust.no_unwrap",
            Severity::Error,
            "no unwrap",
            vec!["rust"],
            vec!["\\.unwrap\\("],
            vec!["**/*.rs"],
            vec![],
            true,
            true,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "src/lib.rs".to_string(),
                line: 1,
                content: "let x = y.unwrap(); // diffguard: ignore *".to_string(),
            }],
            &rules,
            100,
        );

        assert_eq!(eval.counts.error, 0);
        assert_eq!(eval.counts.suppressed, 1);
        assert!(eval.findings.is_empty());
    }

    #[test]
    fn suppression_next_line_ignores_rule() {
        let rules = compile_rules(&[test_rule(
            "rust.no_dbg",
            Severity::Warn,
            "no dbg",
            vec!["rust"],
            vec!["\\bdbg!\\("],
            vec!["**/*.rs"],
            vec![],
            true,
            true,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [
                InputLine {
                    path: "src/lib.rs".to_string(),
                    line: 1,
                    content: "// diffguard: ignore-next-line rust.no_dbg".to_string(),
                },
                InputLine {
                    path: "src/lib.rs".to_string(),
                    line: 2,
                    content: "dbg!(value);".to_string(),
                },
            ],
            &rules,
            100,
        );

        assert_eq!(eval.counts.warn, 0);
        assert_eq!(eval.counts.suppressed, 1);
        assert!(eval.findings.is_empty());
    }

    #[test]
    fn suppression_next_line_does_not_affect_third_line() {
        let rules = compile_rules(&[test_rule(
            "rust.no_dbg",
            Severity::Warn,
            "no dbg",
            vec!["rust"],
            vec!["\\bdbg!\\("],
            vec!["**/*.rs"],
            vec![],
            true,
            true,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [
                InputLine {
                    path: "src/lib.rs".to_string(),
                    line: 1,
                    content: "// diffguard: ignore-next-line rust.no_dbg".to_string(),
                },
                InputLine {
                    path: "src/lib.rs".to_string(),
                    line: 2,
                    content: "dbg!(value);".to_string(),
                },
                InputLine {
                    path: "src/lib.rs".to_string(),
                    line: 3,
                    content: "dbg!(other);".to_string(),
                },
            ],
            &rules,
            100,
        );

        // Line 2 is suppressed, line 3 is not
        assert_eq!(eval.counts.warn, 1);
        assert_eq!(eval.counts.suppressed, 1);
        assert_eq!(eval.findings.len(), 1);
        assert_eq!(eval.findings[0].line, 3);
    }

    #[test]
    fn suppression_wrong_rule_does_not_suppress() {
        let rules = compile_rules(&[test_rule(
            "rust.no_unwrap",
            Severity::Error,
            "no unwrap",
            vec!["rust"],
            vec!["\\.unwrap\\("],
            vec!["**/*.rs"],
            vec![],
            true,
            true,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "src/lib.rs".to_string(),
                line: 1,
                content: "let x = y.unwrap(); // diffguard: ignore wrong.rule".to_string(),
            }],
            &rules,
            100,
        );

        // The suppression is for a different rule, so unwrap is still flagged
        assert_eq!(eval.counts.error, 1);
        assert_eq!(eval.counts.suppressed, 0);
        assert_eq!(eval.findings.len(), 1);
    }

    #[test]
    fn suppression_resets_on_file_change() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Warn,
            "test",
            vec![],
            vec!["pattern"],
            vec![],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [
                // File 1: set up next-line suppression
                InputLine {
                    path: "file1.txt".to_string(),
                    line: 1,
                    content: "// diffguard: ignore-next-line test.rule".to_string(),
                },
                // File 2: different file, suppression should NOT apply
                InputLine {
                    path: "file2.txt".to_string(),
                    line: 1,
                    content: "pattern".to_string(),
                },
            ],
            &rules,
            100,
        );

        // Pattern in file2 should be detected (suppression was for file1's next line)
        assert_eq!(eval.counts.warn, 1);
        assert_eq!(eval.counts.suppressed, 0);
        assert_eq!(eval.findings.len(), 1);
        assert_eq!(eval.findings[0].path, "file2.txt");
    }

    #[test]
    fn suppression_multiple_rules_on_same_line() {
        let rules = compile_rules(&[
            test_rule(
                "rule.one",
                Severity::Warn,
                "one",
                vec![],
                vec!["pattern"],
                vec![],
                vec![],
                false,
                false,
            ),
            test_rule(
                "rule.two",
                Severity::Error,
                "two",
                vec![],
                vec!["pattern"],
                vec![],
                vec![],
                false,
                false,
            ),
        ])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "test.txt".to_string(),
                line: 1,
                content: "pattern // diffguard: ignore rule.one, rule.two".to_string(),
            }],
            &rules,
            100,
        );

        // Both rules should be suppressed
        assert_eq!(eval.counts.warn, 0);
        assert_eq!(eval.counts.error, 0);
        assert_eq!(eval.counts.suppressed, 2);
        assert!(eval.findings.is_empty());
    }

    #[test]
    fn suppression_ignore_all_directive() {
        let rules = compile_rules(&[
            test_rule(
                "rule.one",
                Severity::Warn,
                "one",
                vec![],
                vec!["pattern"],
                vec![],
                vec![],
                false,
                false,
            ),
            test_rule(
                "rule.two",
                Severity::Error,
                "two",
                vec![],
                vec!["pattern"],
                vec![],
                vec![],
                false,
                false,
            ),
        ])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "test.txt".to_string(),
                line: 1,
                content: "pattern // diffguard: ignore-all".to_string(),
            }],
            &rules,
            100,
        );

        // Both rules should be suppressed with ignore-all
        assert_eq!(eval.counts.warn, 0);
        assert_eq!(eval.counts.error, 0);
        assert_eq!(eval.counts.suppressed, 2);
        assert!(eval.findings.is_empty());
    }

    #[test]
    fn safe_slice_clamps_and_slices() {
        let s = "abcde";
        assert_eq!(safe_slice(s, 1, 3), "bc");
        assert_eq!(safe_slice(s, 0, 100), "abcde");
        assert_eq!(safe_slice(s, 10, 12), "");
    }

    #[test]
    fn byte_to_column_counts_chars() {
        let s = "aβc";
        assert_eq!(byte_to_column(s, 0), Some(1));
        assert_eq!(byte_to_column(s, 1), Some(2));
        assert_eq!(byte_to_column(s, 3), Some(3));
        assert_eq!(byte_to_column(s, s.len()), Some(4));
        assert_eq!(byte_to_column(s, s.len() + 1), None);
    }
}
