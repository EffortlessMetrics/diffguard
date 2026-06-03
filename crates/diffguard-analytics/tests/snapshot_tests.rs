//! Snapshot test for `merge_false_positive_baselines` note precedence.
//!
//! Per spec AC3: "base.note wins when both are Some" because base is the curated
//! baseline and incoming is ephemeral.

use diffguard_analytics::{
    FALSE_POSITIVE_BASELINE_SCHEMA_V1, FalsePositiveBaseline, FalsePositiveEntry,
    merge_false_positive_baselines,
};

/// Snapshot test for baseline merge - note precedence when BOTH have Some notes.
///
/// Per spec AC3: "base.note wins when both are Some" because base is the curated
/// baseline and incoming is ephemeral.
///
/// This test verifies the fix is working: when both base and incoming have Some notes
/// for the same fingerprint, base.note is preserved (incoming.note is ignored).
#[test]
fn snapshot_merge_note_precedence_both_some() {
    let base = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "aaa".to_string(),
            rule_id: "a.rule".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: Some("base note".to_string()),
        }],
    };
    let incoming = FalsePositiveBaseline {
        schema: FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string(),
        entries: vec![FalsePositiveEntry {
            fingerprint: "aaa".to_string(),
            rule_id: "a.rule".to_string(),
            path: "a.rs".to_string(),
            line: 1,
            note: Some("incoming note".to_string()),
        }],
    };
    let merged = merge_false_positive_baselines(&base, &incoming);
    let note_value = format!("{:?}", merged.entries[0].note.as_deref());
    insta::assert_snapshot!("snapshot_merge_note_precedence_both_some", note_value);
}
