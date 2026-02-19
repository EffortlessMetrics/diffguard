# diffguard-analytics

Analytics helpers for diffguard outputs.

This crate is pure logic (no filesystem/process/env I/O) and focuses on two
areas:

- false-positive baseline generation/normalization/merge
- trend history append/trim/summarize

## False-Positive Baselines

Main types and helpers:

- `FalsePositiveBaseline`
- `FalsePositiveEntry`
- `baseline_from_receipt()`
- `merge_false_positive_baselines()`
- `false_positive_fingerprint_set()`

Fingerprints are deterministic SHA-256 hashes of
`rule_id:path:line:match_text`.

## Trend History

Main types and helpers:

- `TrendHistory`
- `TrendRun`
- `TrendSummary`
- `trend_run_from_receipt()`
- `append_trend_run()`
- `summarize_trend_history()`

`append_trend_run()` can trim history to the newest `N` entries, and
`summarize_trend_history()` reports totals plus delta from the previous run.

## Schema IDs

- `diffguard.false_positive_baseline.v1`
- `diffguard.trend_history.v1`
