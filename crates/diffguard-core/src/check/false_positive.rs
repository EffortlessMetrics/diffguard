use std::collections::{BTreeMap, BTreeSet};

use diffguard_types::{Finding, VerdictCounts};

use crate::fingerprint::compute_fingerprint;

/// Per-rule tally of false-positive filtering: (total_filtered, info, warn, error).
pub(super) type PerRuleFalsePositive = BTreeMap<String, (u32, u32, u32, u32)>;

pub(super) struct FalsePositiveOutcome {
    pub kept_findings: Vec<Finding>,
    pub adjusted_counts: VerdictCounts,
    pub false_positive_findings: u32,
    pub per_rule: PerRuleFalsePositive,
}

/// Drop findings whose fingerprints appear in `false_positive_fingerprints`, adjusting
/// verdict counts and recording per-rule false-positive tallies for analytics.
pub(super) fn apply_false_positive_filter(
    findings: Vec<Finding>,
    initial_counts: &VerdictCounts,
    false_positive_fingerprints: &BTreeSet<String>,
) -> FalsePositiveOutcome {
    let mut kept = Vec::with_capacity(findings.len());
    let mut adjusted = initial_counts.clone();
    let mut total_fp = 0u32;
    let mut per_rule = PerRuleFalsePositive::new();

    for finding in findings {
        let fingerprint = compute_fingerprint(&finding);
        if false_positive_fingerprints.contains(&fingerprint) {
            total_fp = total_fp.saturating_add(1);
            let entry = per_rule
                .entry(finding.rule_id.clone())
                .or_insert((0, 0, 0, 0));
            entry.0 = entry.0.saturating_add(1);
            match finding.severity {
                diffguard_types::Severity::Info => {
                    adjusted.info = adjusted.info.saturating_sub(1);
                    entry.1 = entry.1.saturating_add(1);
                }
                diffguard_types::Severity::Warn => {
                    adjusted.warn = adjusted.warn.saturating_sub(1);
                    entry.2 = entry.2.saturating_add(1);
                }
                diffguard_types::Severity::Error => {
                    adjusted.error = adjusted.error.saturating_sub(1);
                    entry.3 = entry.3.saturating_add(1);
                }
            }
            continue;
        }
        kept.push(finding);
    }

    FalsePositiveOutcome {
        kept_findings: kept,
        adjusted_counts: adjusted,
        false_positive_findings: total_fp,
        per_rule,
    }
}
