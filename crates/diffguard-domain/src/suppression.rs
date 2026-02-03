//! Inline suppression directive parsing.
//!
//! This module provides support for inline suppression directives that allow
//! developers to suppress specific rule matches on a line-by-line basis.
//!
//! # Supported Formats
//!
//! - `diffguard: ignore <rule_id>` - suppresses the match on the same line
//! - `diffguard: ignore-next-line <rule_id>` - suppresses matches on the next line
//! - `diffguard: ignore *` or `diffguard: ignore-all` - suppresses all rules on the line
//!
//! Multiple rules can be specified by separating with commas:
//! - `diffguard: ignore rule1, rule2`
//!
//! # Example
//!
//! ```rust,ignore
//! let x = y.unwrap(); // diffguard: ignore rust.no_unwrap
//! // diffguard: ignore-next-line rust.no_dbg
//! dbg!(value);
//! ```

use std::collections::HashSet;

/// Represents the type of suppression directive found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuppressionKind {
    /// Suppress on the same line as the directive.
    SameLine,
    /// Suppress on the next line after the directive.
    NextLine,
}

/// A parsed suppression directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    /// The kind of suppression (same line or next line).
    pub kind: SuppressionKind,
    /// The rule IDs to suppress, or None for wildcard (suppress all).
    /// When None, all rules are suppressed.
    pub rule_ids: Option<HashSet<String>>,
}

impl Suppression {
    /// Returns true if this suppression applies to the given rule ID.
    pub fn suppresses(&self, rule_id: &str) -> bool {
        match &self.rule_ids {
            None => true, // Wildcard - suppress all
            Some(ids) => ids.contains(rule_id),
        }
    }

    /// Returns true if this is a wildcard suppression (suppresses all rules).
    pub fn is_wildcard(&self) -> bool {
        self.rule_ids.is_none()
    }
}

/// The suppression directive prefix.
const DIRECTIVE_PREFIX: &str = "diffguard:";

/// Parse a line for suppression directives.
///
/// Returns None if no directive is found, or Some(Suppression) if a valid
/// directive is present.
///
/// This function should be called on the raw line BEFORE preprocessing
/// (so that comment content is visible).
pub fn parse_suppression(line: &str) -> Option<Suppression> {
    // Find the directive prefix (case-insensitive search)
    let lower = line.to_ascii_lowercase();
    let prefix_start = lower.find(DIRECTIVE_PREFIX)?;

    // Extract the directive content after the prefix
    let after_prefix = &line[prefix_start + DIRECTIVE_PREFIX.len()..];
    let after_prefix = after_prefix.trim_start();

    // Check for "ignore-next-line" first (longer match)
    if let Some(rest) = strip_prefix_ci(after_prefix, "ignore-next-line") {
        let rule_ids = parse_rule_ids(rest);
        return Some(Suppression {
            kind: SuppressionKind::NextLine,
            rule_ids,
        });
    }

    // Check for "ignore-all" (explicit wildcard)
    if strip_prefix_ci(after_prefix, "ignore-all").is_some() {
        return Some(Suppression {
            kind: SuppressionKind::SameLine,
            rule_ids: None,
        });
    }

    // Check for "ignore"
    if let Some(rest) = strip_prefix_ci(after_prefix, "ignore") {
        let rule_ids = parse_rule_ids(rest);
        return Some(Suppression {
            kind: SuppressionKind::SameLine,
            rule_ids,
        });
    }

    None
}

/// Strip a prefix case-insensitively and return the remainder.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let s_lower = s.to_ascii_lowercase();
    if s_lower.starts_with(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Parse rule IDs from the remainder of a directive.
///
/// Returns None for wildcard (*), or Some(HashSet) of rule IDs.
fn parse_rule_ids(rest: &str) -> Option<HashSet<String>> {
    // Strip any trailing block comment closer (*/)
    let rest = rest.trim();
    let rest = rest.strip_suffix("*/").unwrap_or(rest).trim();

    // Empty means wildcard (suppress all)
    if rest.is_empty() {
        return None;
    }

    // Check for explicit wildcard
    if rest == "*" {
        return None;
    }

    // Parse comma-separated rule IDs
    let mut ids = HashSet::new();
    for part in rest.split(',') {
        let id = part.trim();
        if !id.is_empty() && id != "*" {
            ids.insert(id.to_string());
        } else if id == "*" {
            // Wildcard in the list
            return None;
        }
    }

    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

/// Tracks suppression state for a file being processed.
///
/// This struct manages the "ignore-next-line" state that carries over
/// between lines.
#[derive(Debug, Clone, Default)]
pub struct SuppressionTracker {
    /// Suppressions that apply to the next line.
    pending_next_line: Vec<Suppression>,
}

impl SuppressionTracker {
    /// Create a new suppression tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the tracker state (e.g., when switching files).
    pub fn reset(&mut self) {
        self.pending_next_line.clear();
    }

    /// Process a line and return the effective suppressions for this line.
    ///
    /// This method:
    /// 1. Parses any directive in the current line
    /// 2. Applies any pending "next-line" suppressions from the previous line
    /// 3. Updates the pending state for the next line
    ///
    /// Returns the combined set of suppressions that apply to this line.
    pub fn process_line(&mut self, line: &str) -> EffectiveSuppressions {
        // Collect pending suppressions for this line
        let mut same_line_suppressions: Vec<Suppression> = Vec::new();
        let mut next_line_suppressions: Vec<Suppression> = Vec::new();

        // Apply pending "next-line" suppressions from previous line
        same_line_suppressions.append(&mut self.pending_next_line);

        // Parse the current line for directives
        if let Some(suppression) = parse_suppression(line) {
            match suppression.kind {
                SuppressionKind::SameLine => {
                    same_line_suppressions.push(suppression);
                }
                SuppressionKind::NextLine => {
                    next_line_suppressions.push(suppression);
                }
            }
        }

        // Update pending state for the next line
        self.pending_next_line = next_line_suppressions;

        EffectiveSuppressions::from_suppressions(same_line_suppressions)
    }
}

/// The effective suppressions for a single line.
#[derive(Debug, Clone, Default)]
pub struct EffectiveSuppressions {
    /// If true, all rules are suppressed (wildcard).
    pub suppress_all: bool,
    /// Set of specific rule IDs that are suppressed.
    pub suppressed_rules: HashSet<String>,
}

impl EffectiveSuppressions {
    /// Create from a list of suppressions.
    fn from_suppressions(suppressions: Vec<Suppression>) -> Self {
        let mut result = Self::default();

        for s in suppressions {
            match s.rule_ids {
                None => {
                    result.suppress_all = true;
                }
                Some(ids) => {
                    result.suppressed_rules.extend(ids);
                }
            }
        }

        result
    }

    /// Returns true if the given rule should be suppressed.
    pub fn is_suppressed(&self, rule_id: &str) -> bool {
        self.suppress_all || self.suppressed_rules.contains(rule_id)
    }

    /// Returns true if no suppressions are active.
    pub fn is_empty(&self) -> bool {
        !self.suppress_all && self.suppressed_rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== parse_suppression tests ====================

    #[test]
    fn parse_same_line_ignore_single_rule() {
        let line = "let x = y.unwrap(); // diffguard: ignore rust.no_unwrap";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::SameLine);
        assert!(!suppression.is_wildcard());
        assert!(suppression.suppresses("rust.no_unwrap"));
        assert!(!suppression.suppresses("other.rule"));
    }

    #[test]
    fn parse_same_line_ignore_multiple_rules() {
        let line = "// diffguard: ignore rule1, rule2, rule3";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::SameLine);
        assert!(!suppression.is_wildcard());
        assert!(suppression.suppresses("rule1"));
        assert!(suppression.suppresses("rule2"));
        assert!(suppression.suppresses("rule3"));
        assert!(!suppression.suppresses("rule4"));
    }

    #[test]
    fn parse_same_line_ignore_wildcard_star() {
        let line = "// diffguard: ignore *";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::SameLine);
        assert!(suppression.is_wildcard());
        assert!(suppression.suppresses("any.rule"));
        assert!(suppression.suppresses("other.rule"));
    }

    #[test]
    fn parse_same_line_ignore_all() {
        let line = "// diffguard: ignore-all";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::SameLine);
        assert!(suppression.is_wildcard());
        assert!(suppression.suppresses("any.rule"));
    }

    #[test]
    fn parse_same_line_ignore_empty_means_wildcard() {
        let line = "// diffguard: ignore";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::SameLine);
        assert!(suppression.is_wildcard());
    }

    #[test]
    fn parse_next_line_ignore_single_rule() {
        let line = "// diffguard: ignore-next-line rust.no_dbg";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::NextLine);
        assert!(!suppression.is_wildcard());
        assert!(suppression.suppresses("rust.no_dbg"));
        assert!(!suppression.suppresses("other.rule"));
    }

    #[test]
    fn parse_next_line_ignore_wildcard() {
        let line = "// diffguard: ignore-next-line *";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::NextLine);
        assert!(suppression.is_wildcard());
    }

    #[test]
    fn parse_next_line_ignore_empty_means_wildcard() {
        let line = "// diffguard: ignore-next-line";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::NextLine);
        assert!(suppression.is_wildcard());
    }

    #[test]
    fn parse_case_insensitive() {
        let line = "// DIFFGUARD: IGNORE rule.id";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::SameLine);
        assert!(suppression.suppresses("rule.id"));
    }

    #[test]
    fn parse_mixed_case() {
        let line = "// DiffGuard: Ignore-Next-Line rule.id";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::NextLine);
        assert!(suppression.suppresses("rule.id"));
    }

    #[test]
    fn parse_in_hash_comment() {
        let line = "x = 1  # diffguard: ignore python.no_print";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::SameLine);
        assert!(suppression.suppresses("python.no_print"));
    }

    #[test]
    fn parse_in_block_comment() {
        let line = "let x = y.unwrap(); /* diffguard: ignore rust.no_unwrap */";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::SameLine);
        assert!(suppression.suppresses("rust.no_unwrap"));
    }

    #[test]
    fn parse_no_directive_returns_none() {
        let line = "let x = y.unwrap();";
        assert!(parse_suppression(line).is_none());
    }

    #[test]
    fn parse_unrelated_comment_returns_none() {
        let line = "// This is a normal comment";
        assert!(parse_suppression(line).is_none());
    }

    #[test]
    fn parse_partial_directive_returns_none() {
        let line = "// diffguard";
        assert!(parse_suppression(line).is_none());
    }

    #[test]
    fn parse_directive_with_extra_whitespace() {
        let line = "//   diffguard:   ignore   rule.id  ";
        let suppression = parse_suppression(line).expect("should parse");

        assert_eq!(suppression.kind, SuppressionKind::SameLine);
        assert!(suppression.suppresses("rule.id"));
    }

    #[test]
    fn parse_multiple_rules_with_varying_whitespace() {
        let line = "// diffguard: ignore rule1,rule2,  rule3  ,rule4";
        let suppression = parse_suppression(line).expect("should parse");

        assert!(suppression.suppresses("rule1"));
        assert!(suppression.suppresses("rule2"));
        assert!(suppression.suppresses("rule3"));
        assert!(suppression.suppresses("rule4"));
    }

    #[test]
    fn parse_wildcard_in_list_becomes_wildcard() {
        let line = "// diffguard: ignore rule1, *, rule2";
        let suppression = parse_suppression(line).expect("should parse");

        // If there's a wildcard in the list, it becomes a full wildcard
        assert!(suppression.is_wildcard());
    }

    // ==================== SuppressionTracker tests ====================

    #[test]
    fn tracker_same_line_suppression() {
        let mut tracker = SuppressionTracker::new();

        let effective =
            tracker.process_line("let x = y.unwrap(); // diffguard: ignore rust.no_unwrap");

        assert!(effective.is_suppressed("rust.no_unwrap"));
        assert!(!effective.is_suppressed("other.rule"));
    }

    #[test]
    fn tracker_next_line_suppression() {
        let mut tracker = SuppressionTracker::new();

        // First line has the directive
        let effective1 = tracker.process_line("// diffguard: ignore-next-line rust.no_dbg");
        assert!(!effective1.is_suppressed("rust.no_dbg")); // Not suppressed on directive line

        // Second line should be suppressed
        let effective2 = tracker.process_line("dbg!(value);");
        assert!(effective2.is_suppressed("rust.no_dbg"));

        // Third line should not be suppressed
        let effective3 = tracker.process_line("dbg!(other);");
        assert!(!effective3.is_suppressed("rust.no_dbg"));
    }

    #[test]
    fn tracker_both_same_and_next_line() {
        let mut tracker = SuppressionTracker::new();

        // Line with both same-line and next-line suppressions
        let effective1 = tracker.process_line("// diffguard: ignore-next-line rule1");
        assert!(!effective1.is_suppressed("rule1"));

        let effective2 = tracker.process_line("x = 1 // diffguard: ignore rule2");
        assert!(effective2.is_suppressed("rule1")); // From previous line
        assert!(effective2.is_suppressed("rule2")); // From same line
    }

    #[test]
    fn tracker_wildcard_suppression() {
        let mut tracker = SuppressionTracker::new();

        let effective = tracker.process_line("// diffguard: ignore *");
        assert!(effective.is_suppressed("any.rule"));
        assert!(effective.is_suppressed("other.rule"));
        assert!(effective.suppress_all);
    }

    #[test]
    fn tracker_reset_clears_pending() {
        let mut tracker = SuppressionTracker::new();

        // Set up a pending next-line suppression
        tracker.process_line("// diffguard: ignore-next-line rule1");

        // Reset (simulates file change)
        tracker.reset();

        // Next line should NOT be suppressed
        let effective = tracker.process_line("some code");
        assert!(!effective.is_suppressed("rule1"));
    }

    #[test]
    fn tracker_multiple_next_line_directives() {
        let mut tracker = SuppressionTracker::new();

        // Two consecutive next-line directives
        tracker.process_line("// diffguard: ignore-next-line rule1");
        let effective1 = tracker.process_line("// diffguard: ignore-next-line rule2");

        // First directive was "consumed" by the second line,
        // so rule1 applies to line 2
        assert!(effective1.is_suppressed("rule1"));

        // Second directive applies to line 3
        let effective2 = tracker.process_line("actual code");
        assert!(effective2.is_suppressed("rule2"));
        assert!(!effective2.is_suppressed("rule1"));
    }

    // ==================== EffectiveSuppressions tests ====================

    #[test]
    fn effective_suppressions_is_empty() {
        let effective = EffectiveSuppressions::default();
        assert!(effective.is_empty());
        assert!(!effective.is_suppressed("any.rule"));
    }

    #[test]
    fn effective_suppressions_specific_rules() {
        let mut effective = EffectiveSuppressions::default();
        effective.suppressed_rules.insert("rule1".to_string());
        effective.suppressed_rules.insert("rule2".to_string());

        assert!(!effective.is_empty());
        assert!(effective.is_suppressed("rule1"));
        assert!(effective.is_suppressed("rule2"));
        assert!(!effective.is_suppressed("rule3"));
    }

    #[test]
    fn effective_suppressions_wildcard() {
        let effective = EffectiveSuppressions {
            suppress_all: true,
            ..Default::default()
        };

        assert!(!effective.is_empty());
        assert!(effective.is_suppressed("any.rule"));
        assert!(effective.is_suppressed("other.rule"));
    }
}
