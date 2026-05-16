use super::CheckPlan;

/// Filter a rule based on tag criteria in the plan.
///
/// - If `only_tags` is non-empty, the rule must have at least one matching tag.
/// - `enable_tags` is additive to `only_tags` (a rule matching either set is included).
/// - If `disable_tags` is non-empty and the rule has any matching tag, it's excluded.
pub(super) fn filter_rule_by_tags(rule: &diffguard_types::RuleConfig, plan: &CheckPlan) -> bool {
    // If only_tags is specified, allow rules matching only_tags OR enable_tags.
    // This keeps enable_tags additive rather than restrictive on its own.
    if !plan.only_tags.is_empty() {
        let has_only_tag = rule
            .tags
            .iter()
            .any(|t| plan.only_tags.iter().any(|ot| ot.eq_ignore_ascii_case(t)));
        let has_enabled_tag = !plan.enable_tags.is_empty()
            && rule
                .tags
                .iter()
                .any(|t| plan.enable_tags.iter().any(|et| et.eq_ignore_ascii_case(t)));
        if !has_only_tag && !has_enabled_tag {
            return false;
        }
    }

    // If disable_tags is specified, exclude rules that have any matching tag
    if !plan.disable_tags.is_empty() {
        let has_disabled_tag = rule.tags.iter().any(|t| {
            plan.disable_tags
                .iter()
                .any(|dt| dt.eq_ignore_ascii_case(t))
        });
        if has_disabled_tag {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::super::CheckPlan;
    use super::*;
    use diffguard_types::FailOn;
    use std::collections::BTreeSet;

    fn make_rule_with_tags(id: &str, tags: Vec<&str>) -> diffguard_types::RuleConfig {
        diffguard_types::RuleConfig {
            id: id.to_string(),
            description: String::new(),
            severity: diffguard_types::Severity::Warn,
            message: "Test message".to_string(),
            languages: vec![],
            patterns: vec!["test".to_string()],
            paths: vec![],
            exclude_paths: vec![],
            ignore_comments: false,
            ignore_strings: false,
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
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            test_cases: vec![],
        }
    }

    fn test_plan() -> CheckPlan {
        CheckPlan {
            base: "base".to_string(),
            head: "head".to_string(),
            scope: diffguard_types::Scope::Added,
            diff_context: 0,
            fail_on: FailOn::Error,
            max_findings: 100,
            path_filters: vec![],
            only_tags: vec![],
            enable_tags: vec![],
            disable_tags: vec![],
            directory_overrides: vec![],
            force_language: None,
            allowed_lines: None,
            false_positive_fingerprints: BTreeSet::new(),
        }
    }

    #[test]
    fn no_filters_keeps_rule() {
        let rule = make_rule_with_tags("test.rule", vec!["debug"]);
        assert!(filter_rule_by_tags(&rule, &test_plan()));
    }

    #[test]
    fn only_tags_matches() {
        let rule = make_rule_with_tags("test.rule", vec!["debug", "safety"]);
        let mut plan = test_plan();
        plan.only_tags = vec!["debug".to_string()];
        assert!(filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn only_tags_no_match() {
        let rule = make_rule_with_tags("test.rule", vec!["security"]);
        let mut plan = test_plan();
        plan.only_tags = vec!["debug".to_string()];
        assert!(!filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn only_tags_case_insensitive() {
        let rule = make_rule_with_tags("test.rule", vec!["DEBUG"]);
        let mut plan = test_plan();
        plan.only_tags = vec!["debug".to_string()];
        assert!(filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn enable_tags_additive_with_only_tags() {
        let rule = make_rule_with_tags("test.rule", vec!["security"]);
        let mut plan = test_plan();
        plan.only_tags = vec!["debug".to_string()];
        plan.enable_tags = vec!["security".to_string()];

        assert!(filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn enable_tags_no_effect_without_only_tags() {
        let rule = make_rule_with_tags("test.rule", vec!["style"]);
        let mut plan = test_plan();
        plan.enable_tags = vec!["security".to_string()];

        assert!(filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn disable_tags_excludes() {
        let rule = make_rule_with_tags("test.rule", vec!["debug"]);
        let mut plan = test_plan();
        plan.disable_tags = vec!["debug".to_string()];
        assert!(!filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn disable_tags_no_match() {
        let rule = make_rule_with_tags("test.rule", vec!["safety"]);
        let mut plan = test_plan();
        plan.disable_tags = vec!["debug".to_string()];
        assert!(filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn combined_filters() {
        // Rule has both "security" and "debug" tags
        let rule = make_rule_with_tags("test.rule", vec!["security", "debug"]);

        // Only security rules, but exclude debug rules
        let mut plan = test_plan();
        plan.only_tags = vec!["security".to_string()];
        plan.disable_tags = vec!["debug".to_string()];

        // Should be excluded because it has a disabled tag
        assert!(!filter_rule_by_tags(&rule, &plan));
    }

    #[test]
    fn rule_without_tags() {
        let rule = make_rule_with_tags("test.rule", vec![]);
        let mut plan = test_plan();
        plan.only_tags = vec!["debug".to_string()];
        // Rule without tags doesn't match only_tags filter
        assert!(!filter_rule_by_tags(&rule, &plan));

        // But with no filters, it should pass
        plan.only_tags.clear();
        assert!(filter_rule_by_tags(&rule, &plan));
    }
}
