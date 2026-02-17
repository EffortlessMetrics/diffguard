//! Fuzz target for rule matching via evaluate_lines.
//!
//! This target exercises the evaluate_lines function with randomly generated
//! input lines and rule patterns to discover edge cases in pattern matching,
//! preprocessing, and suppression handling.
//!
//! Requirements: 1.12 from ROADMAP.md - evaluate_lines fuzz target

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use diffguard_domain::{
    compile_rules, evaluate_lines, parse_suppression, InputLine, Language, PreprocessOptions,
    Preprocessor, SuppressionTracker,
};
use diffguard_types::{RuleConfig, Severity};

/// Fuzz input containing random lines and patterns.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Random input lines to evaluate.
    lines: Vec<FuzzLine>,
    /// Random rule configurations.
    rules: Vec<FuzzRule>,
    /// Max findings limit to use.
    max_findings: u8,
    /// Whether to include suppression directives in some lines.
    include_suppressions: bool,
}

/// A single input line with path, line number, and content.
#[derive(Arbitrary, Debug)]
struct FuzzLine {
    /// File path (used for language detection and glob matching).
    path: String,
    /// Line number.
    line: u32,
    /// Line content.
    content: String,
    /// Optional suppression directive to prepend/append.
    suppression: Option<FuzzSuppression>,
}

/// Fuzz-generated suppression directive.
#[derive(Arbitrary, Debug)]
struct FuzzSuppression {
    /// Kind: 0=same-line, 1=next-line
    kind: u8,
    /// Whether to use wildcard
    wildcard: bool,
    /// Rule IDs to suppress (if not wildcard)
    rule_ids: Vec<String>,
}

impl FuzzSuppression {
    /// Generate a suppression directive string.
    fn to_directive(&self) -> String {
        let kind_str = if self.kind % 2 == 0 {
            "ignore"
        } else {
            "ignore-next-line"
        };

        if self.wildcard {
            format!("// diffguard: {} *", kind_str)
        } else if self.rule_ids.is_empty() {
            format!("// diffguard: {}", kind_str)
        } else {
            format!(
                "// diffguard: {} {}",
                kind_str,
                self.rule_ids.join(", ")
            )
        }
    }
}

/// A fuzz-generated rule configuration.
#[derive(Arbitrary, Debug)]
struct FuzzRule {
    /// Rule identifier.
    id: String,
    /// Severity level (0=info, 1=warn, 2=error).
    severity: u8,
    /// Rule message.
    message: String,
    /// Language filters.
    languages: Vec<String>,
    /// Regex patterns to match.
    patterns: Vec<String>,
    /// Path include globs.
    paths: Vec<String>,
    /// Path exclude globs.
    exclude_paths: Vec<String>,
    /// Whether to ignore comments.
    ignore_comments: bool,
    /// Whether to ignore strings.
    ignore_strings: bool,
}

impl FuzzRule {
    /// Convert to a RuleConfig, returning None if the rule would be invalid.
    fn to_rule_config(&self) -> Option<RuleConfig> {
        // Skip rules with empty patterns (would fail compilation)
        if self.patterns.is_empty() {
            return None;
        }

        // Skip rules with empty id (not useful)
        if self.id.is_empty() {
            return None;
        }

        // Skip very long patterns to avoid regex compilation timeout
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
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        })
    }
}

/// Map a u8 to a Language variant for testing.
fn u8_to_language(v: u8) -> Language {
    match v % 12 {
        0 => Language::Rust,
        1 => Language::Python,
        2 => Language::JavaScript,
        3 => Language::TypeScript,
        4 => Language::Go,
        5 => Language::Ruby,
        6 => Language::C,
        7 => Language::Cpp,
        8 => Language::CSharp,
        9 => Language::Java,
        10 => Language::Kotlin,
        _ => Language::Unknown,
    }
}

fuzz_target!(|input: FuzzInput| {
    // Convert fuzz rules to RuleConfigs, skipping invalid ones
    let rule_configs: Vec<RuleConfig> = input
        .rules
        .iter()
        .filter_map(|r| r.to_rule_config())
        .collect();

    // Skip if no valid rules
    if rule_configs.is_empty() {
        return;
    }

    // Try to compile rules, skipping invalid regex/glob patterns
    let compiled_rules = match compile_rules(&rule_configs) {
        Ok(rules) => rules,
        Err(_) => {
            // Invalid regex or glob patterns are expected with random input.
            // The important thing is that we don't panic.
            return;
        }
    };

    // Skip if no rules compiled successfully
    if compiled_rules.is_empty() {
        return;
    }

    // Convert fuzz lines to InputLines, optionally adding suppression directives
    let input_lines: Vec<InputLine> = input
        .lines
        .iter()
        .take(100) // Limit to avoid excessive runtime
        .map(|l| {
            let content = if input.include_suppressions {
                if let Some(ref supp) = l.suppression {
                    format!("{} {}", l.content, supp.to_directive())
                } else {
                    l.content.clone()
                }
            } else {
                l.content.clone()
            };

            InputLine {
                path: l.path.clone(),
                line: l.line,
                content,
            }
        })
        .collect();

    // Use a bounded max_findings to test truncation behavior
    let max_findings = (input.max_findings as usize).max(1).min(100);

    // Exercise evaluate_lines - this should never panic regardless of input
    let evaluation = evaluate_lines(input_lines.clone(), &compiled_rules, max_findings);

    // Property: findings count should not exceed max_findings
    assert!(
        evaluation.findings.len() <= max_findings,
        "findings.len() ({}) should not exceed max_findings ({})",
        evaluation.findings.len(),
        max_findings
    );

    // Property: total counts should be >= findings.len() (since we might truncate)
    let total_counts =
        evaluation.counts.info + evaluation.counts.warn + evaluation.counts.error;
    assert!(
        total_counts >= evaluation.findings.len() as u32,
        "total counts ({}) should be >= findings.len() ({})",
        total_counts,
        evaluation.findings.len()
    );

    // Property: truncated_findings + findings.len() should equal total_counts
    assert_eq!(
        evaluation.truncated_findings + evaluation.findings.len() as u32,
        total_counts,
        "truncated ({}) + findings ({}) should equal total counts ({})",
        evaluation.truncated_findings,
        evaluation.findings.len(),
        total_counts
    );

    // Property: lines_scanned should equal the number of input lines
    assert_eq!(
        evaluation.lines_scanned as usize,
        input_lines.len(),
        "lines_scanned ({}) should equal input lines ({})",
        evaluation.lines_scanned,
        input_lines.len()
    );

    // === Additional fuzzing: Exercise suppression parsing directly ===
    for line in &input_lines {
        // parse_suppression should never panic on any input
        let _ = parse_suppression(&line.content);
    }

    // === Additional fuzzing: Exercise preprocessor with various languages ===
    if !input_lines.is_empty() {
        // Test with different language/options combinations
        for lang_idx in 0..12u8 {
            let lang = u8_to_language(lang_idx);

            // Test comments-only preprocessing
            let mut p_comments =
                Preprocessor::with_language(PreprocessOptions::comments_only(), lang);

            // Test strings-only preprocessing
            let mut p_strings =
                Preprocessor::with_language(PreprocessOptions::strings_only(), lang);

            // Test both
            let mut p_both =
                Preprocessor::with_language(PreprocessOptions::comments_and_strings(), lang);

            // Process a few lines to exercise multiline state
            for line in input_lines.iter().take(10) {
                let result_comments = p_comments.sanitize_line(&line.content);
                let result_strings = p_strings.sanitize_line(&line.content);
                let result_both = p_both.sanitize_line(&line.content);

                // Property: output length must equal input length
                assert_eq!(
                    result_comments.len(),
                    line.content.len(),
                    "Comments preprocessor output length mismatch"
                );
                assert_eq!(
                    result_strings.len(),
                    line.content.len(),
                    "Strings preprocessor output length mismatch"
                );
                assert_eq!(
                    result_both.len(),
                    line.content.len(),
                    "Both preprocessor output length mismatch"
                );
            }

            // Test reset
            p_comments.reset();
            p_strings.reset();
            p_both.reset();
        }
    }

    // === Additional fuzzing: Exercise SuppressionTracker ===
    let mut tracker = SuppressionTracker::new();
    let mut p = Preprocessor::with_language(PreprocessOptions::comments_only(), Language::Rust);

    for line in input_lines.iter().take(20) {
        let masked = p.sanitize_line(&line.content);
        let _ = tracker.process_line(&line.content, &masked);
    }

    // Test reset behavior
    tracker.reset();

    // Process again after reset
    for line in input_lines.iter().take(10) {
        let masked = p.sanitize_line(&line.content);
        let _ = tracker.process_line(&line.content, &masked);
    }

    // If we get here without panicking, the test passes.
    // The fuzz target verifies that evaluate_lines and related functions
    // handle arbitrary UTF-8 input without crashing.
});
