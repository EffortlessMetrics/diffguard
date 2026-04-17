# Specification — work-fe879e77

## Feature/Behavior Description

Refactor `normalize_false_positive_baseline` in `crates/diffguard-analytics/src/lib.rs` to take `&mut FalsePositiveBaseline` instead of owned `FalsePositiveBaseline`, removing the return type. This eliminates the unnecessary `.clone()` in `merge_false_positive_baselines` that existed solely to satisfy the owned parameter.

### Current Behavior

```rust
#[must_use]
pub fn normalize_false_positive_baseline(
    mut baseline: FalsePositiveBaseline,
) -> FalsePositiveBaseline {
    if baseline.schema.is_empty() {
        baseline.schema = FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string();
    }
    baseline.entries.sort_by(...);
    baseline.entries.dedup_by(...);
    baseline  // identity return
}
```

Callers must pass an owned value. The return is semantically identity — the function never creates new data.

### Desired Behavior

```rust
pub fn normalize_false_positive_baseline(
    baseline: &mut FalsePositiveBaseline,
) {
    if baseline.schema.is_empty() {
        baseline.schema = FALSE_POSITIVE_BASELINE_SCHEMA_V1.to_string();
    }
    baseline.entries.sort_by(...);
    baseline.entries.dedup_by(...);
}
```

The `#[must_use]` attribute is removed since the function returns `()`.

## Acceptance Criteria

### AC-1: No unnecessary clone in `merge_false_positive_baselines`

After the refactor, `merge_false_positive_baselines` must not call `.clone()` to satisfy `normalize_false_positive_baseline`. The `incoming.clone()` call remains at line 104, but it now serves only the merge operation (creating `merged`), not the normalization step. Verification: `cargo test -p diffguard-analytics` passes.

### AC-2: All call sites updated to `&mut`

The function signature changes to `fn normalize_false_positive_baseline(baseline: &mut FalsePositiveBaseline)`. All four call sites must be updated:
- `lib.rs:95` — `baseline_from_receipt`
- `lib.rs:104` — `merge_false_positive_baselines` (first call)
- `lib.rs:135` — `merge_false_positive_baselines` (second call)
- `main.rs:1524` — `load_false_positive_baseline`

Verification: `cargo build --all-targets` completes without errors.

### AC-3: `#[must_use]` attribute removed

The `#[must_use]` attribute on `normalize_false_positive_baseline` is removed since the function no longer returns a value. Verification: `cargo clippy --all-targets` emits no warnings related to unused `#[must_use]` on this function.

### AC-4: Functional behavior unchanged

All existing tests pass. The normalization results (sorted entries, deduplicated fingerprints, schema set if empty) are identical before and after. Verification: `cargo test -p diffguard` and `cargo test -p diffguard-analytics` both pass.

## Non-Goals

- This refactor does **not** address `normalize_trend_history` (line 203), which has the identical ownership pattern but is out of scope. A separate tracking issue should be filed.
- This refactor does **not** change the public API of `merge_false_positive_baselines` or `baseline_from_receipt` — only the internal helper `normalize_false_positive_baseline`.
- This refactor does **not** eliminate the `incoming.clone()` in `merge_false_positive_baselines` entirely — that clone is still needed to create the `merged` value for the merge operation.

## Dependencies

- Rust toolchain (no external dependencies)
- Full workspace build and test capability (`cargo build --all-targets`, `cargo test --all-targets`)
- `cargo clippy --all-targets` for lint verification
