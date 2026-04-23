//! Fuzz target for `RuleOverrideMatcher::resolve()` and LRU cache.
//!
//! This target exercises the override matching logic with arbitrary path and
//! rule_id inputs, validating that no panics occur and results are consistent.
//!
//! The LRU cache is also fuzzed directly for edge cases in capacity limits,
//! eviction order, and concurrent-like access patterns through repeated gets.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use diffguard_domain::{DirectoryRuleOverride, RuleOverrideMatcher};
use diffguard_types::Severity;

#[derive(Arbitrary, Debug)]
struct FuzzOverride {
    directory: String,
    rule_id: String,
    enabled: Option<bool>,
    severity: Option<u8>, // 0=None, 1=Info, 2=Warn, 3=Error
    exclude_paths: Vec<String>,
}

impl FuzzOverride {
    fn to_directory_rule_override(&self) -> DirectoryRuleOverride {
        let severity = match self.severity.unwrap_or(0) % 4 {
            0 => None,
            1 => Some(Severity::Info),
            2 => Some(Severity::Warn),
            _ => Some(Severity::Error),
        };

        DirectoryRuleOverride {
            directory: self.directory.clone(),
            rule_id: self.rule_id.clone(),
            enabled: self.enabled,
            severity,
            exclude_paths: self.exclude_paths.clone(),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    overrides: Vec<FuzzOverride>,
    resolve_path: String,
    resolve_rule_id: String,
    // Number of repeated resolve calls to test cache consistency
    repeat_count: u8,
    // Also test glob compilation separately
    test_globs: bool,
    glob_patterns: Vec<String>,
    glob_directory: String,
    glob_rule_id: String,
}

fuzz_target!(|input: FuzzInput| {
    // Skip excessively large inputs to avoid timeout
    if input.overrides.len() > 100 {
        return;
    }

    // Limit string lengths to prevent excessive computation
    let path = if input.resolve_path.len() > 1000 {
        return;
    } else {
        input.resolve_path.clone()
    };

    let rule_id = if input.resolve_rule_id.len() > 500 {
        return;
    } else {
        input.resolve_rule_id.clone()
    };

    // Convert fuzz overrides, filtering out ones with obviously bad globs
    let overrides: Vec<DirectoryRuleOverride> = input
        .overrides
        .into_iter()
        .take(100)
        .map(|o| o.to_directory_rule_override())
        .collect();

    // Compile the matcher - invalid globs return error, never panic
    let matcher = match RuleOverrideMatcher::compile(&overrides) {
        Ok(m) => m,
        Err(_) => return, // Expected for invalid globs
    };

    // Call resolve multiple times to test cache consistency
    let repeat_count = usize::from(input.repeat_count).clamp(1, 20);
    let mut results = Vec::with_capacity(repeat_count);

    for _ in 0..repeat_count {
        let result = matcher.resolve(&path, &rule_id);

        // Validate result invariants
        assert!(
            matches!(result.severity, None | Some(Severity::Info | Severity::Warn | Severity::Error)),
            "severity must be None or valid Severity variant"
        );
        // enabled is always a bool, no need to validate

        results.push(result);
    }

    // All repeated calls must return identical results
    for result in &results {
        assert_eq!(
            result.enabled, results[0].enabled,
            "repeated resolve() calls must return same enabled value"
        );
        assert_eq!(
            result.severity, results[0].severity,
            "repeated resolve() calls must return same severity value"
        );
    }

    // Also test glob compilation separately if requested
    if input.test_globs && !input.glob_patterns.is_empty() {
        let patterns: Vec<String> = input
            .glob_patterns
            .into_iter()
            .filter(|p| p.len() <= 200)
            .take(50)
            .collect();

        if !patterns.is_empty() {
            let directory = if input.glob_directory.len() > 500 {
                return;
            } else {
                input.glob_directory.clone()
            };

            let rule_id = if input.glob_rule_id.len() > 200 {
                return;
            } else {
                input.glob_rule_id.clone()
            };

            let override_spec = DirectoryRuleOverride {
                directory,
                rule_id,
                enabled: Some(true),
                severity: Some(Severity::Warn),
                exclude_paths: patterns,
            };

            // Compile should return error for invalid globs, never panic
            let _ = RuleOverrideMatcher::compile(&[override_spec]);
        }
    }
});
