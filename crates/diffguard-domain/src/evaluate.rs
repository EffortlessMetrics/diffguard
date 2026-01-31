use std::collections::BTreeSet;

use diffguard_types::{Finding, Severity, VerdictCounts};

use crate::preprocess::{PreprocessOptions, Preprocessor};
use crate::rules::{detect_language, CompiledRule};

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
    let mut p_comments = Preprocessor::new(PreprocessOptions::comments_only());
    let mut p_strings = Preprocessor::new(PreprocessOptions::strings_only());
    let mut p_both = Preprocessor::new(PreprocessOptions::comments_and_strings());

    for l in lines {
        lines_scanned = lines_scanned.saturating_add(1);
        files_seen.insert(l.path.clone());

        if current_file.as_deref() != Some(&l.path) {
            current_file = Some(l.path.clone());
            p_comments.reset();
            p_strings.reset();
            p_both.reset();
        }

        let path = std::path::Path::new(&l.path);
        let lang = detect_language(path);

        let masked_comments = p_comments.sanitize_line(&l.content);
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

    #[test]
    fn finds_unwrap_in_added_line() {
        let rules = compile_rules(&[RuleConfig {
            id: "rust.no_unwrap".to_string(),
            severity: Severity::Error,
            message: "no".to_string(),
            languages: vec!["rust".to_string()],
            patterns: vec!["\\.unwrap\\(".to_string()],
            paths: vec!["**/*.rs".to_string()],
            exclude_paths: vec![],
            ignore_comments: true,
            ignore_strings: true,
        }])
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
        let rules = compile_rules(&[RuleConfig {
            id: "rust.no_unwrap".to_string(),
            severity: Severity::Error,
            message: "no".to_string(),
            languages: vec!["rust".to_string()],
            patterns: vec!["unwrap".to_string()],
            paths: vec!["**/*.rs".to_string()],
            exclude_paths: vec![],
            ignore_comments: true,
            ignore_strings: false,
        }])
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
        let rules = compile_rules(&[RuleConfig {
            id: "r".to_string(),
            severity: Severity::Warn,
            message: "m".to_string(),
            languages: vec![],
            patterns: vec!["x".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
        }])
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
}
