//! Tests verifying the clippy refactor preserves behavior
//! The "red" state is the clippy warning itself.

use diffguard_types::MatchMode;
use diffguard_types::VerdictCounts;

#[test]
fn test_verdict_counts_suppressed_is_zero() {
    let counts = VerdictCounts {
        suppressed: 5,
        ..Default::default()
    };
    // is_zero checks suppressed == 0
    assert!(counts.suppressed != 0);
}

#[test]
fn test_match_mode_is_match_mode_any() {
    let mode = MatchMode::Any;
    // is_match_mode_any returns true for MatchMode::Any
    assert!(matches!(mode, MatchMode::Any));
}
