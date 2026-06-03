//! Green/functional tests for diffguard-analytics.
//!
//! These tests verify the functions work correctly when return values ARE used.
//! They should PASS both before and after the #[must_use] change (no regression).
//!
//! Note: These are unit tests embedded in the crate's test module in lib.rs.
//! This file is for reference only - the actual tests run via cargo test.

/// These functional behaviors are tested:
/// 1. merge_false_positive_baselines_merges_correctly - verifies baseline merging logic
/// 2. false_positive_fingerprint_set_creates_set - verifies fingerprint set creation
/// 3. normalize_trend_history_preserves_schema - verifies schema normalization
/// 4. trend_run_from_receipt_creates_trend_run - verifies TrendRun creation from receipt
/// 5. append_trend_run_adds_run - verifies appending runs to history
/// 6. append_trend_run_trims_to_max - verifies max_runs trimming
/// 7. summarize_trend_history_computes_totals - verifies summary calculations
///
/// All 7 tests PASS in RED state (before implementation).
