# ADR-0013: Change `normalize_false_positive_baseline` to take `&mut` instead of owned

## Status

Accepted

## Context

In `crates/diffguard-analytics/src/lib.rs`, the function `normalize_false_positive_baseline` takes a `FalsePositiveBaseline` by value, mutates it in-place (sorts and deduplicates entries, sets schema if empty), then returns the same value. The return is semantically identity — the function never derives new data or transforms the value, it only normalizes existing fields.

This owned-taking signature forces callers to clone the struct when they only have a borrow, even though mutation-only access is sufficient. The most affected caller is `merge_false_positive_baselines`, which currently clones the incoming baseline to satisfy the owned parameter:

```rust
// lib.rs:104
let mut merged = normalize_false_positive_baseline(incoming.clone());
```

The `incoming` parameter is already borrowed as `&FalsePositiveBaseline`, but `normalize_false_positive_baseline` requires ownership, making the `.clone()` call unavoidable. The clone is not semantically necessary — it only exists because of the function's signature.

## Decision

Change `normalize_false_positive_baseline` to take `&mut FalsePositiveBaseline` instead of `FalsePositiveBaseline` by value, and remove the return type. The function becomes a pure in-place normalization routine with no return value:

```rust
// Before
#[must_use]
pub fn normalize_false_positive_baseline(
    mut baseline: FalsePositiveBaseline,
) -> FalsePositiveBaseline { ... baseline }

// After
pub fn normalize_false_positive_baseline(
    baseline: &mut FalsePositiveBaseline,
) { /* no return */ }
```

Update all four call sites to pass `&mut` instead of owned values:
- `lib.rs:95` — `baseline_from_receipt`
- `lib.rs:104` — `merge_false_positive_baselines` (first call)
- `lib.rs:135` — `merge_false_positive_baselines` (second call)
- `main.rs:1524` — `load_false_positive_baseline`

Remove the `#[must_use]` attribute since the function no longer returns a value.

## Consequences

### Benefits
- **Eliminates unnecessary clone** in `merge_false_positive_baselines`: the `incoming.clone()` call is still present but now only serves the merge operation itself (creating the `merged` value), not the normalization pass. The normalization no longer forces a clone on the caller.
- **Accurate ownership semantics**: the function only needs mutable access to the struct's fields; it never needs to own the struct itself.
- **Self-documenting API**: `&mut` signals in-place mutation explicitly, matching the actual behavior.

### Tradeoffs
- **Call site ergonomics change**: callers must now use `let baseline = ...; normalize_false_positive_baseline(&mut baseline);` instead of `let baseline = normalize_false_positive_baseline(...);`. This is a non-breaking change for all current call sites since none use the return value (the return was always `baseline` itself).
- **`#[must_use]` removal**: the compiler warning that caught forgotten normalization results is removed. However, no callers relied on this warning — all four call sites either discarded the return or immediately returned the result unchanged.
- **Public API change**: `normalize_false_positive_baseline` is publicly exported. Any external crate depending on `diffguard-analytics` directly would need to update call sites. Since the crate is not published to crates.io and has no external workspace consumers, the blast radius is limited to the diffguard workspace.

### Risks
- **Undiscovered call sites**: if any caller outside the four known sites exists, it will produce a compile error. Full workspace build and test verification mitigates this.
- **Asymmetry with `normalize_trend_history`**: the sibling function `normalize_trend_history` (line 203) retains the same owned-taking signature. After this change, the crate will have inconsistent `normalize_*` signatures. A follow-up issue should track this discrepancy before the PR merges.

## Alternatives Considered

### 1. Keep owned signature, document clone as intentional
Reject: The owned signature implies ownership is needed when it isn't. This misleads future contributors and creates unnecessary friction at every call site.

### 2. Change `merge_false_positive_baselines` to take owned instead of borrow
Reject: `merge_false_positive_baselines` is a public API function; changing its signature to take owned `FalsePositiveBaseline` would force clones on all callers of that function, which is the opposite of the goal.

### 3. Add a new `normalize_false_positive_baseline_mut` function and deprecate old one
Reject: Two functions with nearly identical names would confuse contributors. The refactor is purely mechanical — no behavior changes — so a deprecation path is unnecessary complexity.

## Dependencies

- No external API or type changes — `FalsePositiveBaseline` and `FalsePositiveEntry` remain unchanged
- All callers are within the diffguard workspace (verified by grep across all crates)
- No I/O or side effects in the function — purely in-place mutation
