// Integration tests for diffguard-lsp
//
// These tests verify the behavior of the diffguard-lsp crate.
// The build.rs script verifies that find_similar_rules has #[must_use] attribute.

use diffguard_lsp::config::find_similar_rules;
use diffguard_types::{MatchMode, RuleConfig, Severity};

/// Test that find_similar_rules returns similar rule IDs based on prefix matching.
/// This test verifies the function's behavior is correct.
/// The #[must_use] attribute is verified separately by build.rs.
#[test]
fn test_find_similar_rules_returns_similar_on_prefix_match() {
    let rules = vec![
        RuleConfig {
            id: "rust.no_unwrap".to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "msg".to_string(),
            languages: vec![],
            patterns: vec!["a".to_string()],
            paths: vec![],
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
            id: "security.no_eval".to_string(),
            description: String::new(),
            severity: Severity::Warn,
            message: "msg".to_string(),
            languages: vec![],
            patterns: vec!["a".to_string()],
            paths: vec![],
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
    ];

    // Query with prefix that should match rust.no_unwrap
    let suggestions = find_similar_rules("rust.no_unwra", &rules);

    // Should find rust.no_unwrap as a similar rule
    assert!(
        suggestions.contains(&"rust.no_unwrap".to_string()),
        "Expected 'rust.no_unwrap' in suggestions, got {:?}",
        suggestions
    );
}
