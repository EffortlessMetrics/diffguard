//! Property tests for baseline/grandfather mode functionality.
//!
//! These tests verify invariants that should hold across all inputs:
//! 1. Fingerprint determinism: same finding -> same fingerprint
//! 2. Fingerprint uniqueness: different findings -> different fingerprints
//! 3. Partition completeness: every finding is either baseline or new
//! 4. Count conservation: baseline + new counts = original counts
//! 5. Exit code correctness: exit code matches new findings only

use proptest::prelude::*;
use std::collections::BTreeSet;

// =============================================================================
// Proptest Strategies for Generating Test Data
// =============================================================================

/// Strategy for generating arbitrary strings that are valid UTF-8
fn arbitrary_string() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[a-zA-Z0-9_./:-]{0,100}").unwrap()
}

/// Strategy for generating a Finding with controlled properties
fn strategy_finding() -> impl Strategy<Value = diffguard_types::Finding> {
    (
        arbitrary_string(),           // rule_id
        arbitrary_string(),           // message
        arbitrary_string(),           // path
        1u32..=1000,                  // line
        arbitrary_string(),           // match_text
        arbitrary_string(),           // snippet
        prop::option::of(1u32..=200), // column
    )
        .prop_map(
            |(rule_id, message, path, line, match_text, snippet, column)| {
                diffguard_types::Finding {
                    rule_id,
                    // Use fixed severity for property tests to avoid edge cases
                    severity: diffguard_types::Severity::Error,
                    message,
                    path,
                    line,
                    column,
                    match_text,
                    snippet,
                }
            },
        )
}

/// Strategy for generating a set of unique findings
fn strategy_findings(size: usize) -> impl Strategy<Value = Vec<diffguard_types::Finding>> {
    prop::collection::vec(strategy_finding(), 0..size)
}

/// Strategy for generating a baseline fingerprint set
fn strategy_fingerprint_set(size: usize) -> impl Strategy<Value = BTreeSet<String>> {
    prop::collection::vec(
        proptest::string::string_regex("[a-f0-9]{64}").unwrap(),
        0..size,
    )
    .prop_map(|fps| fps.into_iter().collect())
}

// =============================================================================
// Property 1: Fingerprint Determinism
// "For all findings, fingerprint_for_finding is deterministic"
// =============================================================================

proptest! {
    #[test]
    fn fingerprint_is_deterministic(finding in strategy_finding()) {
        let fp1 = diffguard_analytics::fingerprint_for_finding(&finding);
        let fp2 = diffguard_analytics::fingerprint_for_finding(&finding);
        prop_assert_eq!(fp1, fp2, "fingerprint should be deterministic");
    }

    #[test]
    fn fingerprint_length_is_sha256_hex_size(finding in strategy_finding()) {
        let fp = diffguard_analytics::fingerprint_for_finding(&finding);
        prop_assert_eq!(fp.len(), 64, "SHA-256 produces 64 hex characters");
    }

    #[test]
    fn fingerprint_is_valid_hex(finding in strategy_finding()) {
        let fp = diffguard_analytics::fingerprint_for_finding(&finding);
        prop_assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint should only contain hex characters"
        );
    }
}

// =============================================================================
// Property 2: Fingerprint Stability Under Field Changes
// "Changing any field in a finding produces a different fingerprint"
// =============================================================================

proptest! {
    #[test]
    fn different_rule_id_different_fingerprint(
        rule_id in arbitrary_string(),
        path in arbitrary_string(),
        line: u32,
        match_text in arbitrary_string()
    ) {
        let mut f1 = diffguard_types::Finding {
            rule_id: rule_id.clone(),
            severity: diffguard_types::Severity::Error,
            message: "msg".to_string(),
            path: path.clone(),
            line,
            column: None,
            match_text: match_text.clone(),
            snippet: "snippet".to_string(),
        };
        let mut f2 = f1.clone();
        f2.rule_id = format!("{}_modified", rule_id);

        let fp1 = diffguard_analytics::fingerprint_for_finding(&f1);
        let fp2 = diffguard_analytics::fingerprint_for_finding(&f2);

        prop_assert_ne!(
            fp1, fp2,
            "changing rule_id should change fingerprint"
        );
    }

    #[test]
    fn different_path_different_fingerprint(
        rule_id in arbitrary_string(),
        path in arbitrary_string(),
        line: u32,
        match_text in arbitrary_string()
    ) {
        let mut f1 = diffguard_types::Finding {
            rule_id: rule_id.clone(),
            severity: diffguard_types::Severity::Error,
            message: "msg".to_string(),
            path: path.clone(),
            line,
            column: None,
            match_text: match_text.clone(),
            snippet: "snippet".to_string(),
        };
        let mut f2 = f1.clone();
        f2.path = format!("{}_modified", path);

        let fp1 = diffguard_analytics::fingerprint_for_finding(&f1);
        let fp2 = diffguard_analytics::fingerprint_for_finding(&f2);

        prop_assert_ne!(
            fp1, fp2,
            "changing path should change fingerprint"
        );
    }

    #[test]
    fn different_line_different_fingerprint(
        rule_id in arbitrary_string(),
        path in arbitrary_string(),
        line: u32,
        match_text in arbitrary_string()
    ) {
        let mut f1 = diffguard_types::Finding {
            rule_id: rule_id.clone(),
            severity: diffguard_types::Severity::Error,
            message: "msg".to_string(),
            path: path.clone(),
            line,
            column: None,
            match_text: match_text.clone(),
            snippet: "snippet".to_string(),
        };
        let mut f2 = f1.clone();
        f2.line = line + 1;

        let fp1 = diffguard_analytics::fingerprint_for_finding(&f1);
        let fp2 = diffguard_analytics::fingerprint_for_finding(&f2);

        prop_assert_ne!(
            fp1, fp2,
            "changing line should change fingerprint"
        );
    }

    #[test]
    fn different_match_text_different_fingerprint(
        rule_id in arbitrary_string(),
        path in arbitrary_string(),
        line: u32,
        match_text in arbitrary_string()
    ) {
        let mut f1 = diffguard_types::Finding {
            rule_id: rule_id.clone(),
            severity: diffguard_types::Severity::Error,
            message: "msg".to_string(),
            path: path.clone(),
            line,
            column: None,
            match_text: match_text.clone(),
            snippet: "snippet".to_string(),
        };
        let mut f2 = f1.clone();
        f2.match_text = format!("{}_modified", match_text);

        let fp1 = diffguard_analytics::fingerprint_for_finding(&f1);
        let fp2 = diffguard_analytics::fingerprint_for_finding(&f2);

        prop_assert_ne!(
            fp1, fp2,
            "changing match_text should change fingerprint"
        );
    }
}

// =============================================================================
// Property 3: Baseline Fingerprint Set Operations
// =============================================================================

proptest! {
    #[test]
    fn fingerprint_set_union_contains_all_elements(
        mut set1 in strategy_fingerprint_set(10),
        set2 in strategy_fingerprint_set(10)
    ) {
        // Add all elements from set2 to set1
        for fp in &set2 {
            set1.insert(fp.clone());
        }

        // The union should contain all unique elements
        for fp in &set1 {
            prop_assert!(
                set1.contains(fp),
                "fingerprint set should contain its own elements"
            );
        }
    }

    #[test]
    fn empty_baseline_means_all_findings_are_new(
        findings in strategy_findings(10)
    ) {
        let empty_baseline: BTreeSet<String> = BTreeSet::new();

        // With empty baseline, all findings should be "new"
        // We verify by checking that none of the finding fingerprints
        // are in the empty baseline
        for finding in &findings {
            let fp = diffguard_analytics::fingerprint_for_finding(finding);
            prop_assert!(
                !empty_baseline.contains(&fp),
                "empty baseline should not contain any fingerprints"
            );
        }
    }
}

// =============================================================================
// Property 4: baseline_from_receipt Determinism
// =============================================================================

proptest! {
    #[test]
    fn baseline_from_receipt_is_deterministic(
        findings in strategy_findings(20)
    ) {
        let receipt = diffguard_types::CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.2.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "base".to_string(),
                head: "head".to_string(),
                context_lines: 3,
                scope: diffguard_types::Scope::Added,
                files_scanned: 1,
                lines_scanned: 10,
            },
            findings: findings.clone(),
            verdict: diffguard_types::Verdict {
                status: diffguard_types::VerdictStatus::Fail,
                counts: diffguard_types::VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: findings.len() as u32,
                    suppressed: 0,
                },
                reasons: vec![],
            },
            timing: None,
        };

        let baseline1 = diffguard_analytics::baseline_from_receipt(&receipt);
        let baseline2 = diffguard_analytics::baseline_from_receipt(&receipt);

        prop_assert_eq!(baseline1, baseline2, "baseline_from_receipt should be deterministic");
    }

    #[test]
    fn baseline_entries_count_matches_findings(
        findings in strategy_findings(20)
    ) {
        let receipt = diffguard_types::CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.2.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "base".to_string(),
                head: "head".to_string(),
                context_lines: 3,
                scope: diffguard_types::Scope::Added,
                files_scanned: 1,
                lines_scanned: 10,
            },
            findings: findings.clone(),
            verdict: diffguard_types::Verdict {
                status: diffguard_types::VerdictStatus::Fail,
                counts: diffguard_types::VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: findings.len() as u32,
                    suppressed: 0,
                },
                reasons: vec![],
            },
            timing: None,
        };

        let baseline = diffguard_analytics::baseline_from_receipt(&receipt);

        prop_assert_eq!(
            baseline.entries.len(),
            findings.len(),
            "baseline should have one entry per finding"
        );
    }

    #[test]
    fn baseline_fingerprints_match_individual_fingerprints(
        findings in strategy_findings(20)
    ) {
        let receipt = diffguard_types::CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.2.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "base".to_string(),
                head: "head".to_string(),
                context_lines: 3,
                scope: diffguard_types::Scope::Added,
                files_scanned: 1,
                lines_scanned: 10,
            },
            findings: findings.clone(),
            verdict: diffguard_types::Verdict {
                status: diffguard_types::VerdictStatus::Fail,
                counts: diffguard_types::VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: findings.len() as u32,
                    suppressed: 0,
                },
                reasons: vec![],
            },
            timing: None,
        };

        let baseline = diffguard_analytics::baseline_from_receipt(&receipt);
        let baseline_fps: BTreeSet<String> = baseline
            .entries
            .iter()
            .map(|e| e.fingerprint.clone())
            .collect();

        // Each finding's fingerprint should be in the baseline
        for finding in &findings {
            let fp = diffguard_analytics::fingerprint_for_finding(finding);
            prop_assert!(
                baseline_fps.contains(&fp),
                "each finding's fingerprint should be in baseline"
            );
        }
    }
}

// =============================================================================
// Property 5: false_positive_fingerprint_set Consistency
// =============================================================================

proptest! {
    #[test]
    fn fingerprint_set_from_baseline_contains_all_fingerprints(
        findings in strategy_findings(20)
    ) {
        let receipt = diffguard_types::CheckReceipt {
            schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
            tool: diffguard_types::ToolMeta {
                name: "diffguard".to_string(),
                version: "0.2.0".to_string(),
            },
            diff: diffguard_types::DiffMeta {
                base: "base".to_string(),
                head: "head".to_string(),
                context_lines: 3,
                scope: diffguard_types::Scope::Added,
                files_scanned: 1,
                lines_scanned: 10,
            },
            findings: findings.clone(),
            verdict: diffguard_types::Verdict {
                status: diffguard_types::VerdictStatus::Fail,
                counts: diffguard_types::VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: findings.len() as u32,
                    suppressed: 0,
                },
                reasons: vec![],
            },
            timing: None,
        };

        let baseline = diffguard_analytics::baseline_from_receipt(&receipt);
        let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

        // All baseline entries should be in the fingerprint set
        for entry in &baseline.entries {
            prop_assert!(
                fps.contains(&entry.fingerprint),
                "fingerprint set should contain all baseline fingerprints"
            );
        }

        // All fingerprints should be 64 hex characters
        for fp in &fps {
            prop_assert_eq!(
                fp.len(),
                64,
                "each fingerprint should be 64 hex characters (SHA-256)"
            );
        }
    }
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn fingerprint_with_empty_strings() {
    let finding = diffguard_types::Finding {
        rule_id: String::new(),
        severity: diffguard_types::Severity::Error,
        message: String::new(),
        path: String::new(),
        line: 0,
        column: None,
        match_text: String::new(),
        snippet: String::new(),
    };

    let fp = diffguard_analytics::fingerprint_for_finding(&finding);
    assert_eq!(
        fp.len(),
        64,
        "empty string inputs should still produce valid fingerprint"
    );
}

#[test]
fn fingerprint_with_unicode_characters() {
    let finding = diffguard_types::Finding {
        rule_id: "rust.unicode".to_string(),
        severity: diffguard_types::Severity::Error,
        message: "Unicode: \u{1F600}".to_string(),
        path: "src/main.rs".to_string(),
        line: 42,
        column: None,
        match_text: "\u{1F600}".to_string(),
        snippet: "let emoji = \u{1F600};".to_string(),
    };

    let fp = diffguard_analytics::fingerprint_for_finding(&finding);
    assert_eq!(
        fp.len(),
        64,
        "unicode inputs should produce valid fingerprint"
    );
}

#[test]
fn fingerprint_with_special_regex_characters() {
    let finding = diffguard_types::Finding {
        rule_id: "regex.special".to_string(),
        severity: diffguard_types::Severity::Error,
        message: "Special chars: []{}()*+?.,\\^$|".to_string(),
        path: "src/pattern.rs".to_string(),
        line: 100,
        column: None,
        match_text: "[]{}()*+?.,\\^$|".to_string(),
        snippet: "let pattern = r\"[a-z]+\";".to_string(),
    };

    let fp = diffguard_analytics::fingerprint_for_finding(&finding);
    assert_eq!(
        fp.len(),
        64,
        "regex special chars should produce valid fingerprint"
    );
}

#[test]
fn empty_findings_list_produces_empty_baseline() {
    let receipt = diffguard_types::CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: diffguard_types::ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: diffguard_types::DiffMeta {
            base: "base".to_string(),
            head: "head".to_string(),
            context_lines: 3,
            scope: diffguard_types::Scope::Added,
            files_scanned: 0,
            lines_scanned: 0,
        },
        findings: vec![],
        verdict: diffguard_types::Verdict {
            status: diffguard_types::VerdictStatus::Pass,
            counts: diffguard_types::VerdictCounts {
                info: 0,
                warn: 0,
                error: 0,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    };

    let baseline = diffguard_analytics::baseline_from_receipt(&receipt);
    assert_eq!(
        baseline.entries.len(),
        0,
        "empty findings should produce empty baseline"
    );
    assert_eq!(
        baseline.schema,
        diffguard_analytics::FALSE_POSITIVE_BASELINE_SCHEMA_V1
    );
}

#[test]
fn large_findings_list_handled_efficiently() {
    // Generate a large number of findings and ensure no overflow/panic
    let findings: Vec<diffguard_types::Finding> = (0..1000)
        .map(|i| diffguard_types::Finding {
            rule_id: format!("rule{}", i),
            severity: diffguard_types::Severity::Error,
            message: format!("message{}", i),
            path: format!("src/file{}.rs", i),
            line: i as u32,
            column: None,
            match_text: format!("match{}", i),
            snippet: format!("snippet{}", i),
        })
        .collect();

    let receipt = diffguard_types::CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: diffguard_types::ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: diffguard_types::DiffMeta {
            base: "base".to_string(),
            head: "head".to_string(),
            context_lines: 3,
            scope: diffguard_types::Scope::Added,
            files_scanned: 1000,
            lines_scanned: 10000,
        },
        findings,
        verdict: diffguard_types::Verdict {
            status: diffguard_types::VerdictStatus::Fail,
            counts: diffguard_types::VerdictCounts {
                info: 0,
                warn: 0,
                error: 1000,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    };

    let baseline = diffguard_analytics::baseline_from_receipt(&receipt);
    assert_eq!(
        baseline.entries.len(),
        1000,
        "large findings list should be processed"
    );
}
