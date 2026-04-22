//! Tests for the `#[must_use]` attribute on `false_positive_fingerprint_set()`.
//!
//! The `false_positive_fingerprint_set()` function returns an owned `BTreeSet<String>`
//! that callers must use. If the return value is discarded, fingerprints are silently
//! lost, causing false positives to be incorrectly processed.
//!
//! This test verifies that `#[must_use]` is present on the function, preventing
//! such silent data loss.

/// Verifies that `false_positive_fingerprint_set()` has the `#[must_use]` attribute.
///
/// In RED state (before fix): The attribute is absent, and callers who discard
/// the return value receive no compiler warning.
///
/// In GREEN state (after fix): The `#[must_use]` attribute is present, and
/// callers who discard the return value receive a compiler warning.
#[test]
fn false_positive_fingerprint_set_has_must_use_attribute() {
    let source = include_str!("../src/lib.rs");
    let lines: Vec<&str> = source.lines().collect();

    // Find the line with "pub fn false_positive_fingerprint_set"
    let fn_line_index = lines
        .iter()
        .enumerate()
        .find_map(|(i, line)| {
            if line.contains("pub fn false_positive_fingerprint_set") {
                Some(i)
            } else {
                None
            }
        })
        .expect("Function false_positive_fingerprint_set not found in source");

    // The #[must_use] attribute should be on the line immediately before the function
    let attr_line_index = fn_line_index.saturating_sub(1);
    let attr_line = lines[attr_line_index].trim();

    // Check for #[must_use] attribute (possibly with other attributes like doc comments)
    // The pattern should be: either the immediate previous line is #[must_use],
    // or there's exactly one doc comment line between them
    let has_must_use = attr_line == "#[must_use]"
        || (attr_line.starts_with("///")
            && lines[fn_line_index.saturating_sub(2)].trim() == "#[must_use]");

    assert!(
        has_must_use,
        "Function false_positive_fingerprint_set is missing #[must_use] attribute. \
         Found instead: '{}'. The #[must_use] attribute must appear immediately before \
         the function declaration (between any doc comment and the fn).",
        attr_line
    );
}

/// Verifies the function signature and basic behavior are correct.
///
/// This ensures that when code-builder implements the fix, the function
/// continues to return the correct data structure.
#[test]
fn false_positive_fingerprint_set_returns_btreeset() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};
    use std::collections::BTreeSet;

    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "abc123".to_string(),
                rule_id: "rule1".to_string(),
                path: "src/lib.rs".to_string(),
                line: 10,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "def456".to_string(),
                rule_id: "rule2".to_string(),
                path: "src/main.rs".to_string(),
                line: 20,
                note: Some("test note".to_string()),
            },
        ],
    };

    let result = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    // Verify return type is BTreeSet<String>
    fn assert_btreeset(_: BTreeSet<String>) {}
    assert_btreeset(result.clone());

    // Verify contents
    assert_eq!(result.len(), 2);
    assert!(result.contains("abc123"));
    assert!(result.contains("def456"));
}

/// Verifies that the fingerprint set contains exactly the fingerprints from entries.
///
/// This test ensures the function correctly extracts fingerprints without
/// modifying or filtering them.
#[test]
fn false_positive_fingerprint_set_contains_all_entry_fingerprints() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};

    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "fp1".to_string(),
                rule_id: "rule1".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "fp2".to_string(),
                rule_id: "rule1".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "fp3".to_string(),
                rule_id: "rule2".to_string(),
                path: "c.rs".to_string(),
                line: 3,
                note: None,
            },
        ],
    };

    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert_eq!(fps.len(), 3);
    assert!(fps.contains("fp1"));
    assert!(fps.contains("fp2"));
    assert!(fps.contains("fp3"));
}

/// Verifies that empty baseline returns empty set.
#[test]
fn false_positive_fingerprint_set_empty_baseline() {
    use diffguard_analytics::FalsePositiveBaseline;

    let baseline = FalsePositiveBaseline::default();
    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert!(fps.is_empty());
}

// ============================================================================
// Edge case tests added by green-test-builder
// ============================================================================

/// Edge case: single entry baseline.
/// Verifies the function handles minimal non-empty input correctly.
#[test]
fn false_positive_fingerprint_set_single_entry() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};

    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "only_one".to_string(),
            rule_id: "rule".to_string(),
            path: "file.rs".to_string(),
            line: 1,
            note: None,
        }],
    };

    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert_eq!(fps.len(), 1);
    assert!(fps.contains("only_one"));
}

/// Edge case: entries with duplicate fingerprints.
/// BTreeSet should deduplicate, so only one copy of each unique fingerprint remains.
#[test]
fn false_positive_fingerprint_set_deduplicates_by_fingerprint() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};

    // Three entries, but two share the same fingerprint
    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "dup_fp".to_string(),
                rule_id: "rule1".to_string(),
                path: "a.rs".to_string(),
                line: 10,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "unique_fp".to_string(),
                rule_id: "rule2".to_string(),
                path: "b.rs".to_string(),
                line: 20,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "dup_fp".to_string(), // duplicate fingerprint
                rule_id: "rule3".to_string(),
                path: "c.rs".to_string(),
                line: 30,
                note: None,
            },
        ],
    };

    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    // BTreeSet collects unique fingerprints only
    assert_eq!(fps.len(), 2);
    assert!(fps.contains("dup_fp"));
    assert!(fps.contains("unique_fp"));
}

/// Edge case: baseline with 1000 entries.
/// Tests that the function scales to large baselines without issues.
#[test]
fn false_positive_fingerprint_set_large_baseline() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};

    let entries: Vec<FalsePositiveEntry> = (0..1000)
        .map(|i| FalsePositiveEntry {
            fingerprint: format!("fp_{:04}", i),
            rule_id: format!("rule_{}", i % 10),
            path: format!("src_{}.rs", i % 100),
            line: i,
            note: None,
        })
        .collect();

    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries,
    };

    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert_eq!(fps.len(), 1000);
    assert!(fps.contains("fp_0000"));
    assert!(fps.contains("fp_0999"));
}

/// Edge case: entries with empty rule_id and path.
/// The fingerprint extraction should work regardless of other field values.
#[test]
fn false_positive_fingerprint_set_empty_rule_id_and_path() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};

    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "abc123".to_string(),
            rule_id: String::new(),
            path: String::new(),
            line: 0,
            note: None,
        }],
    };

    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert_eq!(fps.len(), 1);
    assert!(fps.contains("abc123"));
}

/// Edge case: entries with special Unicode characters in fingerprint.
/// Ensures UTF-8 encoding is handled correctly.
#[test]
fn false_positive_fingerprint_set_unicode_fingerprints() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};

    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "fp_日本語".to_string(),
                rule_id: "rule1".to_string(),
                path: "src/lib.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "fp_émojis_🎉".to_string(),
                rule_id: "rule2".to_string(),
                path: "src/main.rs".to_string(),
                line: 2,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "fp_עברית".to_string(), // Hebrew
                rule_id: "rule3".to_string(),
                path: "src/lib.rs".to_string(),
                line: 3,
                note: None,
            },
        ],
    };

    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert_eq!(fps.len(), 3);
    assert!(fps.contains("fp_日本語"));
    assert!(fps.contains("fp_émojis_🎉"));
    assert!(fps.contains("fp_עברית"));
}

/// Edge case: very long fingerprint string.
/// SHA-256 hex strings are 64 characters; test fingerprints can be even longer.
#[test]
fn false_positive_fingerprint_set_long_fingerprint() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};

    let long_fingerprint = "a".repeat(10_000); // 10,000 character fingerprint

    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: long_fingerprint.clone(),
            rule_id: "rule".to_string(),
            path: "file.rs".to_string(),
            line: 1,
            note: None,
        }],
    };

    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert_eq!(fps.len(), 1);
    let contained: String = fps.into_iter().next().unwrap();
    assert_eq!(contained, long_fingerprint);
}

/// Edge case: fingerprint with non-printable/control characters.
/// Ensures the function doesn't break on unusual but valid String content.
#[test]
fn false_positive_fingerprint_set_control_characters() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};

    // Fingerprint with null byte, newline, tab, and other control chars
    let control_fp = "fp\x00with\n\ttab\r\nand\0null".to_string();

    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: control_fp.clone(),
            rule_id: "rule".to_string(),
            path: "file.rs".to_string(),
            line: 1,
            note: None,
        }],
    };

    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert_eq!(fps.len(), 1);
    let contained: String = fps.into_iter().next().unwrap();
    assert_eq!(contained, control_fp);
}

/// Edge case: entries with line number at u32::MAX boundary.
/// Ensures no overflow or truncation occurs for maximum line values.
#[test]
fn false_positive_fingerprint_set_max_line_number() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};

    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "fp_max_line".to_string(),
            rule_id: "rule".to_string(),
            path: "file.rs".to_string(),
            line: u32::MAX,
            note: None,
        }],
    };

    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert_eq!(fps.len(), 1);
    assert!(fps.contains("fp_max_line"));
}

/// Edge case: fingerprint with path traversal characters.
/// Ensures special characters in fingerprints don't cause issues.
#[test]
fn false_positive_fingerprint_set_path_traversal_chars() {
    use diffguard_analytics::{FalsePositiveBaseline, FalsePositiveEntry};

    let baseline = FalsePositiveBaseline {
        schema: "test".to_string(),
        entries: vec![
            FalsePositiveEntry {
                fingerprint: "fp_../etc/passwd".to_string(),
                rule_id: "rule1".to_string(),
                path: "a.rs".to_string(),
                line: 1,
                note: None,
            },
            FalsePositiveEntry {
                fingerprint: "fp_..\\..\\windows\\system32".to_string(),
                rule_id: "rule2".to_string(),
                path: "b.rs".to_string(),
                line: 2,
                note: None,
            },
        ],
    };

    let fps = diffguard_analytics::false_positive_fingerprint_set(&baseline);

    assert_eq!(fps.len(), 2);
    assert!(fps.contains("fp_../etc/passwd"));
    assert!(fps.contains("fp_..\\..\\windows\\system32"));
}

/// Integration: false_positive_fingerprint_set with baseline_from_receipt pipeline.
/// Verifies the functions work correctly when chained/composed.
#[test]
fn false_positive_fingerprint_set_integration_with_baseline_from_receipt() {
    use diffguard_analytics::{baseline_from_receipt, false_positive_fingerprint_set};
    use diffguard_types::{
        CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict, VerdictCounts,
        VerdictStatus,
    };

    let receipt = CheckReceipt {
        schema: diffguard_types::CHECK_SCHEMA_V1.to_string(),
        tool: ToolMeta {
            name: "diffguard".to_string(),
            version: "0.2.0".to_string(),
        },
        diff: DiffMeta {
            base: "origin/main".to_string(),
            head: "HEAD".to_string(),
            context_lines: 0,
            scope: Scope::Added,
            files_scanned: 1,
            lines_scanned: 2,
        },
        findings: vec![
            Finding {
                rule_id: "rust.no_unwrap".to_string(),
                severity: Severity::Error,
                message: "no unwrap".to_string(),
                path: "src/lib.rs".to_string(),
                line: 12,
                column: Some(4),
                match_text: ".unwrap()".to_string(),
                snippet: "let x = y.unwrap();".to_string(),
            },
            Finding {
                rule_id: "rust.no_expect".to_string(),
                severity: Severity::Warn,
                message: "no expect".to_string(),
                path: "src/main.rs".to_string(),
                line: 20,
                column: Some(4),
                match_text: ".expect()".to_string(),
                snippet: "x.expect(\"msg\")".to_string(),
            },
        ],
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 1,
                error: 1,
                suppressed: 0,
            },
            reasons: vec![],
        },
        timing: None,
    };

    // Chain: receipt -> baseline -> fingerprint set
    let baseline = baseline_from_receipt(&receipt);
    let fps = false_positive_fingerprint_set(&baseline);

    // Should have exactly 2 fingerprints (one per finding)
    assert_eq!(fps.len(), 2);

    // All fingerprints should be 64-character SHA-256 hex strings
    for fp in &fps {
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
