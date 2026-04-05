//! Focused fuzz target for `evaluate_lines`.
//!
//! This target exercises evaluation logic with arbitrary rule/line inputs and
//! validates core invariants (counts, truncation, scan accounting).

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use diffguard_domain::{InputLine, compile_rules, evaluate_lines};
use diffguard_types::{RuleConfig, Severity};

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    lines: Vec<FuzzLine>,
    rules: Vec<FuzzRule>,
    max_findings: u8,
}

#[derive(Arbitrary, Debug)]
struct FuzzLine {
    path: String,
    line: u32,
    content: String,
}

#[derive(Arbitrary, Debug)]
struct FuzzRule {
    id: String,
    severity: u8,
    message: String,
    languages: Vec<String>,
    patterns: Vec<String>,
    paths: Vec<String>,
    exclude_paths: Vec<String>,
    ignore_comments: bool,
    ignore_strings: bool,
}

impl FuzzRule {
    fn to_rule_config(&self) -> Option<RuleConfig> {
        if self.id.is_empty() || self.patterns.is_empty() {
            return None;
        }

        if self.patterns.iter().any(|p| p.len() > 500) {
            return None;
        }

        let severity = match self.severity % 3 {
            0 => Severity::Info,
            1 => Severity::Warn,
            _ => Severity::Error,
        };

        Some(RuleConfig {
            id: self.id.clone(),
            severity,
            message: self.message.clone(),
            languages: self.languages.clone(),
            patterns: self.patterns.clone(),
            paths: self.paths.clone(),
            exclude_paths: self.exclude_paths.clone(),
            ignore_comments: self.ignore_comments,
            ignore_strings: self.ignore_strings,
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
        })
    }
}

fuzz_target!(|input: FuzzInput| {
    let rules: Vec<RuleConfig> = input
        .rules
        .iter()
        .filter_map(FuzzRule::to_rule_config)
        .collect();
    if rules.is_empty() {
        return;
    }

    let compiled = match compile_rules(&rules) {
        Ok(rules) => rules,
        Err(_) => return,
    };

    let lines: Vec<InputLine> = input
        .lines
        .iter()
        .take(200)
        .map(|line| InputLine {
            path: line.path.clone(),
            line: line.line,
            content: line.content.clone(),
        })
        .collect();

    let max_findings = usize::from(input.max_findings).clamp(1, 200);
    let eval = evaluate_lines(lines.clone(), &compiled, max_findings);

    assert!(eval.findings.len() <= max_findings);

    let total = eval.counts.info + eval.counts.warn + eval.counts.error;
    assert!(total >= eval.findings.len() as u32);
    assert_eq!(total, eval.findings.len() as u32 + eval.truncated_findings);
    assert_eq!(eval.lines_scanned as usize, lines.len());
});
