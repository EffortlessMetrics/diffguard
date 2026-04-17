# Specs — work-eefe7ef9: merge_false_positive_baselines optimization

## Feature/Behavior Description

**Status: CLOSED — Will not be implemented**

This work item proposed optimizing the `merge_false_positive_baselines` function in `crates/diffguard-analytics/src/lib.rs` by replacing `clone()` calls with `std::mem::take()` pattern to avoid unnecessary allocations.

The function merges two false positive baselines (union by fingerprint), preferring existing entries in the base baseline. The inefficient pattern was in lines 120-127 where field-by-field cloning occurred.

## Acceptance Criteria

Since the work item is closed, these criteria document what a valid implementation would need to satisfy if the work is ever revived:

### AC1: Correctness
The implementation must preserve existing behavior. Specifically:
- When merging entries with the same fingerprint, existing metadata (note, rule_id, path, line) must be preserved if present
- The test `merge_baseline_preserves_existing_note` must continue to pass
- The function must not mutate its input parameters (`base` and `incoming`)

### AC2: Compilation
The implementation must compile without borrowing violations:
- Must not use `take()` on fields accessed through a shared reference (`&base.entries`)
- Must not require `&mut base` since callers pass shared references

### AC3: Performance (if applicable)
If an optimization is implemented, it must actually improve performance:
- `take()` only provides benefit when overwriting non-empty destinations
- If the conditional guards prevent non-empty destinations, the optimization is moot

## Non-Goals

- This work item does NOT include fixing other functions in the crate
- This work item does NOT include changing the function signature
- This work item does NOT include adding new test coverage (existing coverage is adequate)
- This work item does NOT include addressing the underlying duplicate issue

## Dependencies

None — the work item is closed.

## Closure Rationale

The work item is closed because:
1. **Cannot compile**: The proposed approach requires mutable access to source fields through a shared reference, which Rust prohibits
2. **No warning**: `cargo clippy -p diffguard-analytics` returns zero warnings — nothing to fix
3. **Stale issue**: GitHub issue #474 is closed as duplicate — requirements are superseded
4. **No benefit**: Even with correct borrowing, the conditional guards prevent the optimization from applying

## If Revived

If this work item is revived, the implementation approach must be redesigned from scratch. The plan must:
1. Cite an open GitHub issue (not closed as duplicate)
2. Demonstrate the Clippy warning with specific Rust/Clippy version
3. Provide a feasible implementation that respects Rust borrowing rules
4. Show that the optimization actually applies given the existing conditional guards