use diffguard_domain::RuleHitStat as DomainRuleHitStat;

use super::RuleHitStat;
use super::false_positive::PerRuleFalsePositive;

/// Map domain-layer per-rule stats to core `RuleHitStat`, subtracting any false-positive
/// filtering recorded in `per_rule_fp` so that final analytics reflect the user's view.
pub(super) fn build_rule_hits(
    domain_hits: Vec<DomainRuleHitStat>,
    per_rule_fp: &PerRuleFalsePositive,
) -> Vec<RuleHitStat> {
    let mut rule_hits: Vec<RuleHitStat> = domain_hits
        .into_iter()
        .map(|s| RuleHitStat {
            rule_id: s.rule_id,
            total: s.total,
            emitted: s.emitted,
            suppressed: s.suppressed,
            info: s.info,
            warn: s.warn,
            error: s.error,
            false_positive: 0,
        })
        .collect();

    if !per_rule_fp.is_empty() {
        for stat in &mut rule_hits {
            if let Some((filtered, info, warn, error)) = per_rule_fp.get(&stat.rule_id) {
                stat.emitted = stat.emitted.saturating_sub(*filtered);
                stat.info = stat.info.saturating_sub(*info);
                stat.warn = stat.warn.saturating_sub(*warn);
                stat.error = stat.error.saturating_sub(*error);
                stat.false_positive = stat.false_positive.saturating_add(*filtered);
            }
        }
    }

    rule_hits
}
