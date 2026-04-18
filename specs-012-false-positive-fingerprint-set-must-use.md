# Specifications — work-ea81e659

## Feature/Behavior Description

Add `#[must_use]` attribute to the `false_positive_fingerprint_set()` function in `crates/diffguard-analytics/src/lib.rs`. This prevents the compiler from silently discarding the returned `BTreeSet<String>` when callers fail to use the result.

## Acceptance Criteria

1. **`#[must_use]` attribute present**: The `false_positive_fingerprint_set()` function in `crates/diffguard-analytics/src/lib.rs` has `#[must_use]` placed between its doc comment and function declaration, matching the pattern of sister functions (`normalize_false_positive_baseline`, `fingerprint_for_finding`, `baseline_from_receipt`).

2. **Compilation succeeds**: `cargo check -p diffguard-analytics` passes with no errors.

3. **Tests pass**: `cargo test -p diffguard-analytics` passes with no failures.

## Non-Goals

- This fix does NOT add `#[must_use]` to other functions in `diffguard-analytics` (e.g., `merge_false_positive_baselines`, `normalize_trend_history`, `append_trend_run`). Those are out of scope per issue #540.
- This fix does NOT modify any logic — only adds a single attribute.
- This fix does NOT require documentation changes.

## Dependencies

- None. The `#[must_use]` attribute is a standard Rust lint attribute with no external dependencies.

## Implementation Detail

The attribute should be added as follows:

```rust
/// Returns the baseline as a fingerprint set for fast lookup.
#[must_use]
pub fn false_positive_fingerprint_set(baseline: &FalsePositiveBaseline) -> BTreeSet<String> {
```

Note: The `pub fn` shifts from line 139 to line 140 after inserting `#[must_use]` on a new line.