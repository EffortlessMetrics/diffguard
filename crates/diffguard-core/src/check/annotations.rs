use diffguard_types::Finding;

pub(super) fn render_annotations(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                diffguard_types::Severity::Info => "notice",
                diffguard_types::Severity::Warn => "warning",
                diffguard_types::Severity::Error => "error",
            };
            format!(
                "::{level} file={path},line={line}::{rule} {msg}",
                level = level,
                path = f.path,
                line = f.line,
                rule = f.rule_id,
                msg = f.message
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn test_finding(severity: diffguard_types::Severity) -> Finding {
        Finding {
            rule_id: "test.rule".to_string(),
            severity,
            message: "Test message".to_string(),
            path: "src/lib.rs".to_string(),
            line: 42,
            column: Some(3),
            match_text: "match".to_string(),
            snippet: "let x = match;".to_string(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_annotations_format_matches_expected(
            severity in prop_oneof![Just(diffguard_types::Severity::Info), Just(diffguard_types::Severity::Warn), Just(diffguard_types::Severity::Error)],
            line in 1u32..1000,
        ) {
            let mut finding = test_finding(severity);
            finding.line = line;

            let annotations = render_annotations(&[finding.clone()]);
            prop_assert_eq!(annotations.len(), 1);

            let level = match severity {
                diffguard_types::Severity::Info => "notice",
                diffguard_types::Severity::Warn => "warning",
                diffguard_types::Severity::Error => "error",
            };

            let expected = format!(
                "::{level} file={path},line={line}::{rule} {msg}",
                level = level,
                path = finding.path,
                line = finding.line,
                rule = finding.rule_id,
                msg = finding.message
            );

            prop_assert_eq!(annotations[0].as_str(), expected.as_str());
        }
    }
}
