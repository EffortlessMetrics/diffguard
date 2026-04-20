use std::collections::{BTreeMap, BTreeSet};

use diffguard_types::{Finding, MatchMode, Severity, VerdictCounts};

use crate::overrides::RuleOverrideMatcher;
use crate::preprocess::{Language, PreprocessOptions, Preprocessor};
use crate::rules::{CompiledRule, detect_language};
use crate::suppression::SuppressionTracker;

/// A single line of input from a diff.
///
/// `InputLine` represents one line from the diff being scanned. It contains
/// the file path, line number (1-indexed in the new version), and the
/// raw line content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputLine {
    /// Path to the file this line belongs to.
    pub path: String,
    /// Line number in the new version of the file (1-indexed).
    pub line: u32,
    /// Raw content of this line (excluding trailing newline).
    pub content: String,
}

/// The result of evaluating a set of rules against a set of diff lines.
///
/// `Evaluation` contains all findings matched by the rules, along with
/// aggregated statistics about the scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// All findings matched by the rules, sorted by file path, line, then column.
    pub findings: Vec<Finding>,
    /// Aggregated counts of findings by severity level.
    pub counts: VerdictCounts,
    /// Number of findings that were suppressed because `max_findings` was reached.
    pub truncated_findings: u32,
    /// Number of distinct files that were scanned.
    ///
    /// Changed from `u32` to `u64` to avoid silent truncation when scanning
    /// repositories with more than 2^32 - 1 (≈4.3 billion) unique files.
    /// The previous `u32` cast would silently truncate, producing incorrect
    /// (often zero) counts for very large codebases.
    pub files_scanned: u64,
    /// Total number of lines scanned across all files.
    pub lines_scanned: u32,
    /// Aggregated per-rule hit counts (deterministically sorted by rule ID).
    pub rule_hits: Vec<RuleHitStat>,
}

/// Per-rule hit statistics for a single rule.
///
/// `RuleHitStat` tracks how many times a rule was matched, emitted,
/// suppressed, and broken down by severity level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHitStat {
    /// The rule ID these stats apply to.
    pub rule_id: String,
    /// Total number of times this rule was matched (before suppression checks).
    pub total: u32,
    /// Number of findings actually emitted (not suppressed).
    pub emitted: u32,
    /// Number of matches suppressed by inline suppression directives.
    pub suppressed: u32,
    /// Number of emitted findings with `Severity::Info`.
    pub info: u32,
    /// Number of emitted findings with `Severity::Warn`.
    pub warn: u32,
    /// Number of emitted findings with `Severity::Error`.
    pub error: u32,
}

#[derive(Debug, Clone)]
struct PreparedLine {
    line: InputLine,
    lang: Option<String>,
    masked_comments: String,
    masked_strings: String,
    masked_both: String,
    suppressions: crate::suppression::EffectiveSuppressions,
}

#[derive(Debug, Clone)]
struct RawMatchEvent {
    anchor_file_pos: usize,
    match_start: Option<usize>,
    match_end: Option<usize>,
    match_text: String,
}

#[derive(Debug, Clone)]
struct MatchEvent {
    rule_idx: usize,
    anchor_idx: usize,
    match_start: Option<usize>,
    match_end: Option<usize>,
    match_text: String,
    severity: Severity,
}

/// Evaluate `lines` against `rules` and return all findings.
///
/// This is the simplest entry point for evaluating diff lines against rules.
/// It uses default settings with no rule overrides or forced language detection.
///
/// # Arguments
///
/// * `lines` - Iterator of input lines to evaluate
/// * `rules` - Compiled rules to match against
/// * `max_findings` - Maximum number of findings to collect before truncating
///
/// # Returns
///
/// `Evaluation` containing all findings and aggregated statistics
pub fn evaluate_lines(
    lines: impl IntoIterator<Item = InputLine>,
    rules: &[CompiledRule],
    max_findings: usize,
) -> Evaluation {
    evaluate_lines_with_overrides_and_language(lines, rules, max_findings, None, None)
}

/// Evaluate `lines` against `rules` with directory-based rule overrides.
///
/// This variant allows passing a `RuleOverrideMatcher` to modify rule behavior
/// based on the directory containing the file being scanned.
pub fn evaluate_lines_with_overrides(
    lines: impl IntoIterator<Item = InputLine>,
    rules: &[CompiledRule],
    max_findings: usize,
    overrides: Option<&RuleOverrideMatcher>,
) -> Evaluation {
    evaluate_lines_with_overrides_and_language(lines, rules, max_findings, overrides, None)
}

/// Evaluate `lines` against `rules` with optional overrides and forced language.
///
/// This is the most general entry point for evaluating diff lines. It supports:
/// - Directory-based rule overrides via `RuleOverrideMatcher`
/// - Forced language detection for files with unknown extensions
///
/// # Arguments
///
/// * `lines` - Iterator of input lines to evaluate
/// * `rules` - Compiled rules to match against
/// * `max_findings` - Maximum number of findings to collect before truncating
/// * `overrides` - Optional rule override matcher for directory-based configuration
/// * `force_language` - Optional language to force for all files (overrides detection)
pub fn evaluate_lines_with_overrides_and_language(
    lines: impl IntoIterator<Item = InputLine>,
    rules: &[CompiledRule],
    max_findings: usize,
    overrides: Option<&RuleOverrideMatcher>,
    force_language: Option<&str>,
) -> Evaluation {
    let input_lines: Vec<InputLine> = lines.into_iter().collect();
    let mut findings: Vec<Finding> = Vec::new();
    let mut counts = VerdictCounts::default();
    let mut truncated_findings: u32 = 0;
    let mut per_rule_hits = BTreeMap::<String, RuleHitStat>::new();

    let files_seen = input_lines
        .iter()
        .map(|line| line.path.clone())
        .collect::<BTreeSet<_>>();
    let lines_scanned = u32::try_from(input_lines.len()).unwrap_or(u32::MAX);

    let mut current_file: Option<String> = None;
    let mut current_lang = Language::Unknown;
    let mut p_comments =
        Preprocessor::with_language(PreprocessOptions::comments_only(), current_lang);
    let mut p_strings =
        Preprocessor::with_language(PreprocessOptions::strings_only(), current_lang);
    let mut p_both =
        Preprocessor::with_language(PreprocessOptions::comments_and_strings(), current_lang);

    let forced_language_name = force_language.map(str::to_ascii_lowercase);
    let forced_language_enum =
        forced_language_name
            .as_deref()
            .map(|lang| match lang.parse::<Language>() {
                Ok(parsed) => parsed,
                Err(infallible) => match infallible {},
            });

    let mut suppression_tracker = SuppressionTracker::new();
    let mut prepared_lines: Vec<PreparedLine> = Vec::with_capacity(input_lines.len());
    for input in input_lines {
        if current_file.as_deref() != Some(&input.path) {
            current_file = Some(input.path.clone());
            current_lang = if let Some(forced_lang) = forced_language_enum {
                forced_lang
            } else {
                let path = std::path::Path::new(&input.path);
                detect_language(path)
                    .and_then(|s| s.parse::<Language>().ok())
                    .unwrap_or(Language::Unknown)
            };

            p_comments.set_language(current_lang);
            p_strings.set_language(current_lang);
            p_both.set_language(current_lang);
            suppression_tracker.reset();
        }

        let path = std::path::Path::new(&input.path);
        let lang = forced_language_name
            .as_deref()
            .or_else(|| detect_language(path))
            .map(ToOwned::to_owned);

        let masked_comments = p_comments.sanitize_line(&input.content);
        let suppressions = suppression_tracker.process_line(&input.content, &masked_comments);
        let masked_strings = p_strings.sanitize_line(&input.content);
        let masked_both = p_both.sanitize_line(&input.content);

        prepared_lines.push(PreparedLine {
            line: input,
            lang,
            masked_comments,
            masked_strings,
            masked_both,
            suppressions,
        });
    }

    let mut by_file = BTreeMap::<String, Vec<usize>>::new();
    for (idx, line) in prepared_lines.iter().enumerate() {
        by_file.entry(line.line.path.clone()).or_default().push(idx);
    }

    let mut events: Vec<MatchEvent> = Vec::new();

    for (path, file_indices) in &by_file {
        if file_indices.is_empty() {
            continue;
        }

        let path_ref = std::path::Path::new(path);
        let lang = prepared_lines[file_indices[0]].lang.as_deref();
        let mut per_rule_events = vec![Vec::<MatchEvent>::new(); rules.len()];

        for (rule_idx, rule) in rules.iter().enumerate() {
            if !rule.applies_to(path_ref, lang) {
                continue;
            }

            let resolved_override = overrides.map(|m| m.resolve(path, &rule.id));
            if resolved_override.is_some_and(|resolved| !resolved.enabled) {
                continue;
            }

            let base_severity = resolved_override
                .and_then(|resolved| resolved.severity)
                .unwrap_or(rule.severity);

            let rule_matches = match rule.match_mode {
                MatchMode::Any => {
                    find_positive_matches_for_rule(rule, file_indices, &prepared_lines)
                }
                MatchMode::Absent => {
                    let positive =
                        find_positive_matches_for_rule(rule, file_indices, &prepared_lines);
                    if positive.is_empty() {
                        vec![RawMatchEvent {
                            anchor_file_pos: 0,
                            match_start: None,
                            match_end: None,
                            match_text: "<absent>".to_string(),
                        }]
                    } else {
                        Vec::new()
                    }
                }
            };

            if rule_matches.is_empty() {
                continue;
            }

            let mut converted = Vec::with_capacity(rule_matches.len());
            for matched in rule_matches {
                let anchor_idx = file_indices[matched.anchor_file_pos];
                let severity = maybe_escalate_severity(
                    rule,
                    file_indices,
                    matched.anchor_file_pos,
                    &prepared_lines,
                    base_severity,
                );
                converted.push(MatchEvent {
                    rule_idx,
                    anchor_idx,
                    match_start: matched.match_start,
                    match_end: matched.match_end,
                    match_text: matched.match_text,
                    severity,
                });
            }

            per_rule_events[rule_idx] = converted;
        }

        let active_rule_ids = resolve_dependency_gated_rule_ids(rules, &per_rule_events);
        for (rule_idx, mut matched) in per_rule_events.into_iter().enumerate() {
            if matched.is_empty() {
                continue;
            }
            if !active_rule_ids.contains(&rules[rule_idx].id) {
                continue;
            }
            events.append(&mut matched);
        }
    }

    events.sort_by(|a, b| {
        a.anchor_idx
            .cmp(&b.anchor_idx)
            .then_with(|| a.rule_idx.cmp(&b.rule_idx))
            .then_with(|| {
                a.match_start
                    .unwrap_or(usize::MAX)
                    .cmp(&b.match_start.unwrap_or(usize::MAX))
            })
    });

    for event in events {
        let rule = &rules[event.rule_idx];
        let prepared = &prepared_lines[event.anchor_idx];
        let stat = per_rule_hits
            .entry(rule.id.clone())
            .or_insert_with(|| RuleHitStat {
                rule_id: rule.id.clone(),
                total: 0,
                emitted: 0,
                suppressed: 0,
                info: 0,
                warn: 0,
                error: 0,
            });
        stat.total = stat.total.saturating_add(1);

        if prepared.suppressions.is_suppressed(&rule.id) {
            counts.suppressed = counts.suppressed.saturating_add(1);
            stat.suppressed = stat.suppressed.saturating_add(1);
            continue;
        }

        bump_counts(&mut counts, event.severity);
        stat.emitted = stat.emitted.saturating_add(1);
        match event.severity {
            Severity::Info => stat.info = stat.info.saturating_add(1),
            Severity::Warn => stat.warn = stat.warn.saturating_add(1),
            Severity::Error => stat.error = stat.error.saturating_add(1),
        }

        if findings.len() < max_findings {
            let column = event
                .match_start
                .and_then(|start| byte_to_column(&prepared.line.content, start))
                .and_then(|c| u32::try_from(c).ok());
            // For absent mode, match_start/match_end are None; use full line as bounds
            let (snippet_start, snippet_end) = match (event.match_start, event.match_end) {
                (Some(start), Some(end)) => (start, end),
                _ => (0, prepared.line.content.len()),
            };
            findings.push(Finding {
                rule_id: rule.id.clone(),
                severity: event.severity,
                message: rule.message.clone(),
                path: prepared.line.path.clone(),
                line: prepared.line.line,
                column,
                match_text: event.match_text,
                snippet: trim_snippet(&prepared.line.content, snippet_start, snippet_end),
            });
        } else {
            truncated_findings = truncated_findings.saturating_add(1);
        }
    }

    Evaluation {
        findings,
        counts,
        truncated_findings,
        // Use u64 to avoid overflow when scanning repos with >4B files.
        // Prior to the u64 migration, `files_seen.len() as u32` would silently
        // truncate for extremely large codebases, producing incorrect counts.
        files_scanned: files_seen.len() as u64,
        lines_scanned,
        rule_hits: per_rule_hits.into_values().collect(),
    }
}

/// Resolve which rules are active after applying dependency gating.
///
/// Rules that `depends_on` another rule are only active if that dependency
/// also matched at least one line. This is a fixed-point iteration: we start
/// with all rules that matched, then iteratively remove rules whose
/// dependencies are not in the active set. The process converges when no
/// more rules are removed in an iteration.
///
/// # Arguments
///
/// * `rules` - All compiled rules
/// * `per_rule_events` - Match events for each rule (empty = no matches)
fn resolve_dependency_gated_rule_ids(
    rules: &[CompiledRule],
    per_rule_events: &[Vec<MatchEvent>],
) -> BTreeSet<String> {
    let mut active_rule_ids = rules
        .iter()
        .enumerate()
        .filter(|(idx, _)| !per_rule_events[*idx].is_empty())
        .map(|(_, rule)| rule.id.clone())
        .collect::<BTreeSet<_>>();

    loop {
        let mut removed_any = false;
        let mut removed_ids = Vec::new();
        for rule in rules {
            if !active_rule_ids.contains(&rule.id) {
                continue;
            }
            if rule
                .depends_on
                .iter()
                .any(|dependency| !active_rule_ids.contains(dependency))
            {
                removed_ids.push(rule.id.clone());
            }
        }

        for id in removed_ids {
            if active_rule_ids.remove(&id) {
                removed_any = true;
            }
        }

        if !removed_any {
            break;
        }
    }

    active_rule_ids
}

/// Find all positive matches for a rule across a single file's lines.
///
/// Returns raw match events for all lines that match the rule's patterns.
/// If the rule has context patterns, filters events to only those with
/// required context nearby.
fn find_positive_matches_for_rule(
    rule: &CompiledRule,
    file_indices: &[usize],
    prepared_lines: &[PreparedLine],
) -> Vec<RawMatchEvent> {
    let mut events = if rule.multiline {
        find_multiline_matches(rule, file_indices, prepared_lines)
    } else {
        find_single_line_matches(rule, file_indices, prepared_lines)
    };

    if !rule.context_patterns.is_empty() {
        events.retain(|event| {
            has_required_context(rule, file_indices, event.anchor_file_pos, prepared_lines)
        });
    }

    events
}

/// Find all single-line matches for a rule.
///
/// Scans each line individually (no cross-line matching). For each line,
/// extracts the matched text and its byte offsets within the original line.
fn find_single_line_matches(
    rule: &CompiledRule,
    file_indices: &[usize],
    prepared_lines: &[PreparedLine],
) -> Vec<RawMatchEvent> {
    let mut out = Vec::new();
    for (file_pos, global_idx) in file_indices.iter().copied().enumerate() {
        let line = &prepared_lines[global_idx];
        let candidate = candidate_line_for_rule(rule, line);
        if let Some((start, end)) = first_match(&rule.patterns, candidate) {
            out.push(RawMatchEvent {
                anchor_file_pos: file_pos,
                match_start: Some(start),
                match_end: Some(end),
                match_text: safe_slice(&line.line.content, start, end),
            });
        }
    }
    out
}

/// Find all multiline matches for a rule across consecutive lines.
///
/// For each starting position, joins `multiline_window` consecutive lines
/// into a single candidate string and runs the pattern match on it.
/// Uses offset tracking to convert the joined-string byte position back
/// to the corresponding per-line byte position in the anchor line.
///
/// # Deduplication
///
/// Uses a BTreeSet of `(anchor_file_pos, start_in_line, match_text)` to
/// avoid reporting the same match twice when different windows overlap.
fn find_multiline_matches(
    rule: &CompiledRule,
    file_indices: &[usize],
    prepared_lines: &[PreparedLine],
) -> Vec<RawMatchEvent> {
    if file_indices.len() < 2 {
        return Vec::new();
    }

    let mut seen = BTreeSet::<(usize, usize, String)>::new();
    let mut out = Vec::new();

    for start in 0..file_indices.len() {
        let end = (start + rule.multiline_window).min(file_indices.len());
        if end.saturating_sub(start) < 2 {
            continue;
        }

        let mut joined_candidate = String::new();
        let mut joined_raw = String::new();
        let mut offsets = Vec::with_capacity(end - start);
        let mut cursor = 0usize;

        for (pos, idx) in file_indices
            .iter()
            .copied()
            .enumerate()
            .take(end)
            .skip(start)
        {
            offsets.push(cursor);
            let line = &prepared_lines[idx];
            let candidate = candidate_line_for_rule(rule, line);

            joined_candidate.push_str(candidate);
            joined_raw.push_str(&line.line.content);
            cursor = cursor.saturating_add(candidate.len());

            if pos + 1 < end {
                joined_candidate.push('\n');
                joined_raw.push('\n');
                cursor = cursor.saturating_add(1);
            }
        }

        if let Some((m_start, m_end)) = first_match(&rule.patterns, &joined_candidate) {
            let rel = offsets
                .partition_point(|offset| *offset <= m_start)
                .saturating_sub(1);
            let anchor_file_pos = start + rel;
            let start_in_line = m_start.saturating_sub(offsets[rel]);
            let end_in_line = m_end.saturating_sub(offsets[rel]);
            let match_text = safe_slice(&joined_raw, m_start, m_end);
            let dedupe_key = (anchor_file_pos, start_in_line, match_text.clone());

            if seen.insert(dedupe_key) {
                out.push(RawMatchEvent {
                    anchor_file_pos,
                    match_start: Some(start_in_line),
                    match_end: Some(end_in_line),
                    match_text,
                });
            }
        }
    }

    out
}

/// Check if a match has the required context patterns nearby.
///
/// Looks for context patterns within `context_window` lines before and after
/// the anchor line. Returns `true` if any context pattern matches (or if the
/// rule has no context patterns). The anchor line itself is not checked.
fn has_required_context(
    rule: &CompiledRule,
    file_indices: &[usize],
    anchor_file_pos: usize,
    prepared_lines: &[PreparedLine],
) -> bool {
    if rule.context_patterns.is_empty() {
        return true;
    }

    let start = anchor_file_pos.saturating_sub(rule.context_window);
    let end = (anchor_file_pos + rule.context_window + 1).min(file_indices.len());
    for idx in file_indices[start..end].iter().copied() {
        let candidate = candidate_line_for_rule(rule, &prepared_lines[idx]);
        if first_match(&rule.context_patterns, candidate).is_some() {
            return true;
        }
    }

    false
}

/// Potentially escalate the severity of a match based on context patterns.
///
/// If the rule has `escalate_patterns`, searches within `escalate_window` lines
/// of the anchor for any escalate pattern. If found, escalates to either the
/// rule's configured `escalate_to` severity or `Error` as default.
fn maybe_escalate_severity(
    rule: &CompiledRule,
    file_indices: &[usize],
    anchor_file_pos: usize,
    prepared_lines: &[PreparedLine],
    base: Severity,
) -> Severity {
    if rule.escalate_patterns.is_empty() {
        return base;
    }

    let start = anchor_file_pos.saturating_sub(rule.escalate_window);
    let end = (anchor_file_pos + rule.escalate_window + 1).min(file_indices.len());
    let should_escalate = file_indices[start..end].iter().copied().any(|idx| {
        let candidate = candidate_line_for_rule(rule, &prepared_lines[idx]);
        first_match(&rule.escalate_patterns, candidate).is_some()
    });

    if !should_escalate {
        return base;
    }

    let target = rule.escalate_to.unwrap_or(Severity::Error);
    max_severity(base, target)
}

/// Select the appropriate preprocessed line for rule matching.
///
/// Depending on the rule's `ignore_comments` and `ignore_strings` flags,
/// returns either the original line content or one of the masked variants
/// (comments masked, strings masked, or both masked).
fn candidate_line_for_rule<'a>(rule: &CompiledRule, line: &'a PreparedLine) -> &'a str {
    match (rule.ignore_comments, rule.ignore_strings) {
        (true, true) => line.masked_both.as_str(),
        (true, false) => line.masked_comments.as_str(),
        (false, true) => line.masked_strings.as_str(),
        (false, false) => line.line.content.as_str(),
    }
}

/// Return the higher of two severities.
///
/// Used when escalating severity: takes the maximum of the base severity
/// and the escalation target. Error > Warn > Info.
fn max_severity(a: Severity, b: Severity) -> Severity {
    fn rank(s: Severity) -> u8 {
        match s {
            Severity::Info => 0,
            Severity::Warn => 1,
            Severity::Error => 2,
        }
    }

    if rank(a) >= rank(b) { a } else { b }
}

/// Find the first match of any pattern in a string.
///
/// Iterates through the patterns in order, returning the start and end
/// byte positions of the first match found. Returns `None` if no pattern matches.
fn first_match(patterns: &[regex::Regex], s: &str) -> Option<(usize, usize)> {
    for p in patterns {
        if let Some(m) = p.find(s) {
            return Some((m.start(), m.end()));
        }
    }
    None
}

/// Increment the appropriate severity counter in `VerdictCounts`.
///
/// Adds 1 to the counter corresponding to the given severity level.
fn bump_counts(counts: &mut VerdictCounts, severity: Severity) {
    match severity {
        Severity::Info => counts.info = counts.info.saturating_add(1),
        Severity::Warn => counts.warn = counts.warn.saturating_add(1),
        Severity::Error => counts.error = counts.error.saturating_add(1),
    }
}

/// Extract and truncate a snippet from a string using bounded match positions.
///
/// First extracts the bounded region `[start, end)` using `safe_slice`, then
/// applies 240-character truncation with ellipsis if the bounded region exceeds
/// that limit. This ensures the snippet represents the actual matched region,
/// not just the first N characters of the line.
///
/// # Arguments
///
/// * `s` - The full line content
/// * `start` - Byte offset where the match begins
/// * `end` - Byte offset where the match ends
///
/// # Returns
///
/// The bounded match text, truncated to 240 chars with ellipsis if needed.
/// If `start >= end`, returns an empty string.
fn trim_snippet(s: &str, start: usize, end: usize) -> String {
    const MAX_CHARS: usize = 240;

    // First, extract the bounded match region using safe_slice
    let bounded = safe_slice(s, start, end);

    // Then apply 240-char truncation with ellipsis to the bounded region
    let trimmed = bounded.trim_end();

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

/// Safely extract a substring slice with bounds checking.
///
/// Clamps `start` and `end` to valid string bounds and returns the substring.
/// Never panics; returns an empty string if the bounds are invalid.
fn safe_slice(s: &str, start: usize, end: usize) -> String {
    let end = end.min(s.len());
    let start = start.min(end);
    s.get(start..end).unwrap_or("").to_string()
}

/// Convert a byte index to a 1-based column number.
///
/// Counts the UTF-8 characters up to `byte_idx` and returns the column number.
/// Returns `None` if `byte_idx` exceeds the string length.
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
    use crate::{DirectoryRuleOverride, RuleOverrideMatcher};
    use diffguard_types::{MatchMode, RuleConfig};

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
            description: String::new(),
            severity,
            message: message.to_string(),
            languages: languages.into_iter().map(|s| s.to_string()).collect(),
            patterns: patterns.into_iter().map(|s| s.to_string()).collect(),
            paths: paths.into_iter().map(|s| s.to_string()).collect(),
            exclude_paths: exclude_paths.into_iter().map(|s| s.to_string()).collect(),
            ignore_comments,
            ignore_strings,
            match_mode: MatchMode::Any,
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
    fn skips_rules_that_do_not_apply_to_language() {
        let rules = compile_rules(&[test_rule(
            "python.no_print",
            Severity::Warn,
            "no",
            vec!["python"],
            vec!["print\\("],
            vec!["**/*.py"],
            vec!["**/tests/**"],
            false,
            false,
        )])
        .unwrap();

        let eval = evaluate_lines(
            [InputLine {
                path: "src/lib.rs".to_string(),
                line: 1,
                content: "print(\"hello\")".to_string(),
            }],
            &rules,
            100,
        );

        assert!(eval.findings.is_empty());
        assert_eq!(eval.counts.warn, 0);
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
        // Pass start=0, end=300 to extract the full 300-char string,
        // which exceeds MAX_CHARS=240 and should be truncated with ellipsis
        let trimmed = super::trim_snippet(&long, 0, 300);

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

    #[test]
    fn forced_language_override_applies_to_unknown_extension() {
        let rules = compile_rules(&[test_rule(
            "rust.no_unwrap",
            Severity::Error,
            "no unwrap",
            vec!["rust"],
            vec!["\\.unwrap\\("],
            vec![],
            vec![],
            true,
            true,
        )])
        .unwrap();

        let lines = [InputLine {
            path: "src/custom.ext".to_string(),
            line: 1,
            content: "let x = y.unwrap();".to_string(),
        }];

        let without_override = evaluate_lines(lines.clone(), &rules, 100);
        assert_eq!(without_override.counts.error, 0);

        let with_override =
            evaluate_lines_with_overrides_and_language(lines, &rules, 100, None, Some("rust"));
        assert_eq!(with_override.counts.error, 1);
        assert_eq!(with_override.findings.len(), 1);
    }

    #[test]
    fn rule_hits_track_emitted_and_suppressed() {
        let rules = compile_rules(&[
            test_rule(
                "rule.warn",
                Severity::Warn,
                "warn",
                vec![],
                vec!["pattern"],
                vec![],
                vec![],
                false,
                false,
            ),
            test_rule(
                "rule.error",
                Severity::Error,
                "error",
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
            [
                InputLine {
                    path: "a.txt".to_string(),
                    line: 1,
                    content: "pattern".to_string(),
                },
                InputLine {
                    path: "a.txt".to_string(),
                    line: 2,
                    content: "pattern // diffguard: ignore rule.warn".to_string(),
                },
            ],
            &rules,
            100,
        );

        let warn_stats = eval
            .rule_hits
            .iter()
            .find(|s| s.rule_id == "rule.warn")
            .expect("warn stats");
        assert_eq!(warn_stats.total, 2);
        assert_eq!(warn_stats.emitted, 1);
        assert_eq!(warn_stats.suppressed, 1);
        assert_eq!(warn_stats.warn, 1);

        let error_stats = eval
            .rule_hits
            .iter()
            .find(|s| s.rule_id == "rule.error")
            .expect("error stats");
        assert_eq!(error_stats.total, 2);
        assert_eq!(error_stats.emitted, 2);
        assert_eq!(error_stats.suppressed, 0);
        assert_eq!(error_stats.error, 2);
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

    #[test]
    fn first_match_returns_none_for_empty_patterns() {
        let patterns: Vec<regex::Regex> = Vec::new();
        assert_eq!(first_match(&patterns, "abc"), None);
    }

    #[test]
    fn bump_counts_increments_all_severities() {
        let mut counts = VerdictCounts::default();
        bump_counts(&mut counts, Severity::Info);
        bump_counts(&mut counts, Severity::Warn);
        bump_counts(&mut counts, Severity::Error);

        assert_eq!(counts.info, 1);
        assert_eq!(counts.warn, 1);
        assert_eq!(counts.error, 1);
    }

    #[test]
    fn directory_overrides_can_change_severity_or_disable_rule() {
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

        let overrides = RuleOverrideMatcher::compile(&[
            DirectoryRuleOverride {
                directory: "src/legacy".to_string(),
                rule_id: "rust.no_unwrap".to_string(),
                enabled: None,
                severity: Some(Severity::Warn),
                exclude_paths: vec![],
            },
            DirectoryRuleOverride {
                directory: "src/generated".to_string(),
                rule_id: "rust.no_unwrap".to_string(),
                enabled: Some(false),
                severity: None,
                exclude_paths: vec![],
            },
        ])
        .expect("compile overrides");

        let eval = evaluate_lines_with_overrides(
            [
                InputLine {
                    path: "src/new/lib.rs".to_string(),
                    line: 1,
                    content: "let x = y.unwrap();".to_string(),
                },
                InputLine {
                    path: "src/legacy/lib.rs".to_string(),
                    line: 1,
                    content: "let x = y.unwrap();".to_string(),
                },
                InputLine {
                    path: "src/generated/lib.rs".to_string(),
                    line: 1,
                    content: "let x = y.unwrap();".to_string(),
                },
            ],
            &rules,
            100,
            Some(&overrides),
        );

        assert_eq!(eval.counts.error, 1);
        assert_eq!(eval.counts.warn, 1);
        assert_eq!(eval.findings.len(), 2);
        assert!(
            eval.findings
                .iter()
                .any(|f| { f.path == "src/new/lib.rs" && matches!(f.severity, Severity::Error) })
        );
        assert!(
            eval.findings
                .iter()
                .any(|f| { f.path == "src/legacy/lib.rs" && matches!(f.severity, Severity::Warn) })
        );
        assert!(
            !eval
                .findings
                .iter()
                .any(|f| f.path == "src/generated/lib.rs")
        );
    }

    #[test]
    fn multiline_rule_matches_across_consecutive_lines() {
        let rule = RuleConfig {
            id: "js.console_then_return".to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "console.log before return".to_string(),
            languages: vec!["javascript".to_string()],
            patterns: vec![r"console\.log\('[^']*'\);\nreturn".to_string()],
            paths: vec!["**/*.js".to_string()],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: MatchMode::Any,
            multiline: true,
            multiline_window: Some(2),
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
        };
        let rules = compile_rules(&[rule]).expect("compile rule");

        let eval = evaluate_lines(
            [
                InputLine {
                    path: "src/app.js".to_string(),
                    line: 10,
                    content: "console.log('x');".to_string(),
                },
                InputLine {
                    path: "src/app.js".to_string(),
                    line: 11,
                    content: "return value;".to_string(),
                },
            ],
            &rules,
            100,
        );
        assert_eq!(eval.counts.warn, 1);
        assert_eq!(eval.findings.len(), 1);
        assert_eq!(eval.findings[0].line, 10);
    }

    #[test]
    fn absent_mode_emits_when_pattern_missing() {
        let rule = RuleConfig {
            id: "rust.missing_timeout".to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "timeout should be configured".to_string(),
            languages: vec!["rust".to_string()],
            patterns: vec![r"\btimeout\b".to_string()],
            paths: vec!["**/*.rs".to_string()],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: MatchMode::Absent,
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
        };
        let rules = compile_rules(&[rule]).expect("compile rule");

        let eval = evaluate_lines(
            [InputLine {
                path: "src/lib.rs".to_string(),
                line: 7,
                content: "let retries = 3;".to_string(),
            }],
            &rules,
            100,
        );

        assert_eq!(eval.counts.warn, 1);
        assert_eq!(eval.findings.len(), 1);
        assert_eq!(eval.findings[0].match_text, "<absent>");
    }

    #[test]
    fn context_patterns_require_nearby_match() {
        let rule = RuleConfig {
            id: "sql.where_required_for_delete".to_string(),
            description: String::new(),
            severity: Severity::Error,
            message: "DELETE requires WHERE nearby".to_string(),
            languages: vec!["sql".to_string()],
            patterns: vec![r"(?i)\bDELETE\s+FROM\b".to_string()],
            paths: vec!["**/*.sql".to_string()],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: MatchMode::Any,
            multiline: false,
            multiline_window: None,
            context_patterns: vec![r"(?i)\bWHERE\b".to_string()],
            context_window: Some(1),
            escalate_patterns: vec![],
            escalate_window: None,
            escalate_to: None,
            depends_on: vec![],
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };
        let rules = compile_rules(&[rule]).expect("compile rule");

        let eval = evaluate_lines(
            [
                InputLine {
                    path: "migrations/a.sql".to_string(),
                    line: 1,
                    content: "DELETE FROM users".to_string(),
                },
                InputLine {
                    path: "migrations/a.sql".to_string(),
                    line: 2,
                    content: "SET active = false;".to_string(),
                },
            ],
            &rules,
            100,
        );

        assert_eq!(eval.counts.error, 0);
        assert!(eval.findings.is_empty());
    }

    #[test]
    fn escalation_patterns_raise_effective_severity() {
        let rule = RuleConfig {
            id: "python.exec_usage".to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "Avoid exec".to_string(),
            languages: vec!["python".to_string()],
            patterns: vec![r"\bexec\s*\(".to_string()],
            paths: vec!["**/*.py".to_string()],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
            match_mode: MatchMode::Any,
            multiline: false,
            multiline_window: None,
            context_patterns: vec![],
            context_window: None,
            escalate_patterns: vec![r"(?i)\buntrusted".to_string()],
            escalate_window: Some(0),
            escalate_to: Some(Severity::Error),
            depends_on: vec![],
            help: None,
            url: None,
            tags: vec![],
            test_cases: vec![],
        };
        let rules = compile_rules(&[rule]).expect("compile rule");

        let eval = evaluate_lines(
            [InputLine {
                path: "src/run.py".to_string(),
                line: 20,
                content: "exec(untrusted_input)".to_string(),
            }],
            &rules,
            100,
        );
        assert_eq!(eval.counts.warn, 0);
        assert_eq!(eval.counts.error, 1);
        assert_eq!(eval.findings[0].severity, Severity::Error);
    }

    #[test]
    fn dependency_gates_secondary_rule() {
        let rules = compile_rules(&[
            RuleConfig {
                id: "python.has_eval".to_string(),
                description: String::new(),
                severity: Severity::Warn,
                message: "eval used".to_string(),
                languages: vec!["python".to_string()],
                patterns: vec![r"\beval\s*\(".to_string()],
                paths: vec!["**/*.py".to_string()],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                match_mode: MatchMode::Any,
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
            },
            RuleConfig {
                id: "python.eval_untrusted".to_string(),
                description: String::new(),
                severity: Severity::Error,
                message: "eval with untrusted input".to_string(),
                languages: vec!["python".to_string()],
                patterns: vec![r"(?i)\buntrusted".to_string()],
                paths: vec!["**/*.py".to_string()],
                exclude_paths: vec![],
                ignore_comments: false,
                ignore_strings: false,
                match_mode: MatchMode::Any,
                multiline: false,
                multiline_window: None,
                context_patterns: vec![],
                context_window: None,
                escalate_patterns: vec![],
                escalate_window: None,
                escalate_to: None,
                depends_on: vec!["python.has_eval".to_string()],
                help: None,
                url: None,
                tags: vec![],
                test_cases: vec![],
            },
        ])
        .expect("compile rules");

        let eval_without_eval = evaluate_lines(
            [InputLine {
                path: "src/a.py".to_string(),
                line: 1,
                content: "untrusted_input".to_string(),
            }],
            &rules,
            100,
        );
        assert_eq!(eval_without_eval.counts.error, 0);

        let eval_with_eval = evaluate_lines(
            [
                InputLine {
                    path: "src/a.py".to_string(),
                    line: 1,
                    content: "eval(x)".to_string(),
                },
                InputLine {
                    path: "src/a.py".to_string(),
                    line: 2,
                    content: "untrusted_input".to_string(),
                },
            ],
            &rules,
            100,
        );
        assert_eq!(eval_with_eval.counts.warn, 1);
        assert_eq!(eval_with_eval.counts.error, 1);
    }

    // =========================================================================
    // EDGE CASE TESTS: trim_snippet with bounded match region
    // These tests verify edge cases not covered by red_tests_work_cb67ea3b.rs
    // =========================================================================

    /// Edge case: Empty line content should produce no findings when no match.
    #[test]
    fn trim_snippet_edge_case_empty_line() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "pattern",
            vec!["rust"],
            vec!["x"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: String::new(),
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(
            eval.findings.is_empty(),
            "Empty line with no match should produce no findings"
        );
    }

    /// Edge case: Match at position 0 (start of line) should still be bounded correctly.
    #[test]
    fn trim_snippet_edge_case_match_at_start_of_line() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "found START",
            vec!["rust"],
            vec!["START"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let line_content = format!("START{}", "x".repeat(300));
        assert_eq!(line_content.len(), 305);

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: line_content,
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(!eval.findings.is_empty());
        let finding = &eval.findings[0];

        assert_eq!(finding.snippet, "START");
        assert!(
            !finding.snippet.ends_with('…'),
            "Short match at start should not be truncated"
        );
    }

    /// Edge case: Match exactly at MAX_CHARS (240) boundary should truncate correctly.
    #[test]
    fn trim_snippet_edge_case_exactly_at_max_chars() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "pattern",
            vec!["rust"],
            vec![".*"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let line_content = "x".repeat(240);
        assert_eq!(line_content.len(), 240);

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: line_content,
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(!eval.findings.is_empty());
        let finding = &eval.findings[0];

        assert_eq!(finding.snippet.chars().count(), 240);
        assert!(
            !finding.snippet.ends_with('…'),
            "Exactly MAX_CHARS should not be truncated"
        );
    }

    /// Edge case: Match exceeding MAX_CHARS (500 chars) should truncate with ellipsis.
    #[test]
    fn trim_snippet_edge_case_exceeds_max_chars_by_large_margin() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "pattern",
            vec!["rust"],
            vec![".*"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let line_content = "x".repeat(500);
        assert_eq!(line_content.len(), 500);

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: line_content,
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(!eval.findings.is_empty());
        let finding = &eval.findings[0];

        assert_eq!(finding.snippet.chars().count(), 241);
        assert!(finding.snippet.ends_with('…'));
    }

    /// Edge case: Match at end of line (no trailing content).
    #[test]
    fn trim_snippet_edge_case_match_at_end_of_line() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "found END",
            vec!["rust"],
            vec!["END"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let line_content = format!("{}{}", "x".repeat(250), "END");
        assert_eq!(line_content.len(), 253);

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: line_content,
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(!eval.findings.is_empty());
        let finding = &eval.findings[0];

        assert_eq!(finding.snippet, "END");
    }

    /// Edge case: Match with trailing whitespace should have whitespace trimmed.
    #[test]
    fn trim_snippet_edge_case_trailing_whitespace_in_match() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "found trailing",
            vec!["rust"],
            vec!["trailing  "],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let line_content = "prefix trailing  more_content";
        assert!(line_content.contains("trailing  "));

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: line_content.to_string(),
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        if !eval.findings.is_empty() {
            let finding = &eval.findings[0];
            assert!(
                !finding.snippet.ends_with(' '),
                "Trailing whitespace should be trimmed"
            );
        }
    }

    /// Edge case: Match near MAX_CHARS boundary (239 chars) should not truncate.
    #[test]
    fn trim_snippet_edge_case_one_char_under_max() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "pattern",
            vec!["rust"],
            vec![".*"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let line_content = "x".repeat(239);
        assert_eq!(line_content.len(), 239);

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: line_content,
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(!eval.findings.is_empty());
        let finding = &eval.findings[0];

        assert_eq!(finding.snippet.chars().count(), 239);
        assert!(!finding.snippet.ends_with('…'));
    }

    /// Edge case: Match just over MAX_CHARS (241 chars) should truncate.
    #[test]
    fn trim_snippet_edge_case_one_char_over_max() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "pattern",
            vec!["rust"],
            vec![".*"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let line_content = "x".repeat(241);
        assert_eq!(line_content.len(), 241);

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: line_content,
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(!eval.findings.is_empty());
        let finding = &eval.findings[0];

        assert_eq!(finding.snippet.chars().count(), 241);
        assert!(finding.snippet.ends_with('…'));
    }

    /// Edge case: Whitespace-only line with no match.
    #[test]
    fn trim_snippet_edge_case_whitespace_only_line_no_match() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "pattern",
            vec!["rust"],
            vec!["NOMATCH"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: "      ".to_string(),
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(
            eval.findings.is_empty(),
            "Whitespace-only line with no match should produce no findings"
        );
    }

    /// Edge case: Very long line (1000 chars) with short match in middle.
    #[test]
    fn trim_snippet_edge_case_very_long_line_short_match_in_middle() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "found short",
            vec!["rust"],
            vec!["HIT"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let line_content = format!("{}{}{}", "A".repeat(500), "HIT", "B".repeat(500));
        assert_eq!(line_content.len(), 1003);

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: line_content,
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(!eval.findings.is_empty());
        let finding = &eval.findings[0];

        assert_eq!(finding.snippet, "HIT");
        assert!(
            finding.snippet.len() < 240,
            "Short match should not be truncated"
        );
    }

    /// Edge case: Line containing only match (no surrounding content).
    #[test]
    fn trim_snippet_edge_case_line_is_only_match() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "exact match",
            vec!["rust"],
            vec!["ONLY"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: "ONLY".to_string(),
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(!eval.findings.is_empty());
        let finding = &eval.findings[0];

        assert_eq!(finding.snippet, "ONLY");
        assert_eq!(finding.match_text, "ONLY");
    }

    /// Edge case: Unicode characters throughout the line.
    #[test]
    fn trim_snippet_edge_case_wide_unicode_line() {
        let rules = compile_rules(&[test_rule(
            "test.rule",
            Severity::Error,
            "found emoji",
            vec!["rust"],
            vec!["🚀"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        )])
        .unwrap();

        let line_content = format!("{}{}{}", "a".repeat(100), "🚀", "a".repeat(100));

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: line_content,
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(!eval.findings.is_empty());
        let finding = &eval.findings[0];

        assert_eq!(finding.snippet, "🚀");
    }

    /// Edge case: Absent mode should use full line as bounded region.
    #[test]
    fn trim_snippet_edge_case_absent_mode_uses_full_line() {
        let mut rule_config = test_rule(
            "test.absent",
            Severity::Error,
            "should be absent",
            vec!["rust"],
            vec!["NEVER_MATCH_THIS"],
            vec!["*.rs"],
            vec![],
            false,
            false,
        );
        rule_config.match_mode = MatchMode::Absent;

        let rules = compile_rules(&[rule_config]).unwrap();

        let line_content = format!("{}{}", "x".repeat(250), "some content");
        assert_eq!(line_content.len(), 262);

        let lines = vec![InputLine {
            path: "test.rs".to_string(),
            line: 1,
            content: line_content,
        }];

        let eval = evaluate_lines(lines, &rules, 100);
        assert!(
            !eval.findings.is_empty(),
            "Absent mode should produce finding when pattern is absent"
        );
        let finding = &eval.findings[0];

        assert!(
            finding.snippet.ends_with('…'),
            "Absent mode with long line should truncate"
        );
        assert_eq!(finding.snippet.chars().count(), 241);
    }
}
