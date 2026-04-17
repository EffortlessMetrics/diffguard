# ADR: Close work-eefe7ef9 as Not Feasible

## Status
**Closed** — Work item will not proceed through the conveyor.

## Context

GitHub issue #474 reports that `merge_false_positive_baselines` in `diffguard-analytics` uses an inefficient clone pattern at lines 120-127. The issue suggests using `std::mem::take()` instead of `clone()` to avoid unnecessary allocations.

The proposed fix involves:
1. Restructuring iteration from `for entry in &base.entries` to index-based
2. Using `take(&mut entry.rule_id)` and `take(&mut entry.path)` on source fields
3. Using `take()` on `existing.note` before conditional clone

## Decision

**Do not implement the proposed fix.** Close work-eefe7ef9 as NOT FEASIBLE.

### Reasons

#### 1. The proposed fix cannot compile
The function receives `base: &FalsePositiveBaseline` (a shared reference). The plan proposes using `take(&mut entry.rule_id)` where `entry` is `&FalsePositiveEntry` from iterating over `base.entries`. Rust borrowing rules prohibit obtaining mutable access to fields through a shared reference. Index-based iteration does not change this — `base.entries[i]` still requires a mutable borrow of `base`.

#### 2. The optimization provides no benefit
The conditional guards in the code:
```rust
if existing.note.is_none() && entry.note.is_some() { ... }
if existing.rule_id.is_empty() { ... }
if existing.path.is_empty() { ... }
if existing.line == 0 { ... }
```
...guarantee the destination is **always empty** when assignment occurs. `take()` only provides benefit when overwriting a non-empty destination with existing allocation capacity. Here, no capacity exists to reuse.

#### 3. The issue is closed as duplicate
GitHub issue #474 is marked `state: "CLOSED"` with comment "Duplicate of related issue. Closing as duplicate." This work item operates on superseded requirements.

#### 4. No Clippy warning exists
Running `cargo clippy -p diffguard-analytics` produces **zero warnings**. Without an active lint, there is no objective measure of success for the fix.

## Consequences

### Tradeoffs
- **Loss**: The allocation optimization described in issue #474 is not implemented
- **Gain**: No wasted effort on a fix that cannot compile and provides no benefit
- **Gain**: No risk of semantic violations (mutating input parameters)
- **Gain**: Maintainer attention directed to active issues

### What Would Be Needed to Revive This Work Item
1. A GitHub issue that is **open** (not closed as duplicate)
2. A **reproducible Clippy warning** with specific Rust/Clippy version
3. A **feasible implementation approach** that respects Rust borrowing rules
4. Evidence that the optimization **actually applies** given the conditional guards

## Alternatives Considered

### Alternative 1: Implement fix using `take()` on destination only
- **Rejected**: When `existing.rule_id.is_empty()` is true, `take(&mut existing.rule_id)` returns `""` — no allocation to reuse. The subsequent `entry.rule_id.clone()` still clones. No benefit.

### Alternative 2: Accept semantic mutation of `base`
- **Rejected**: Calling `take(&mut entry.rule_id)` would mutate fields of the input parameter `base`. Callers expect `base` to be unchanged after the call. This violates the function's semantic contract.

### Alternative 3: Change function signature to take `&mut base`
- **Rejected**: This is a breaking API change affecting all callers. Additionally, callers at `main.rs:2615` pass references to shared data structures that should not be mutated.

## References

- GitHub issue #474 (CLOSED as duplicate)
- Plan review findings (NOT FEASIBLE assessment)
- Vision alignment findings (MISALIGNED assessment)
- Verification: `cargo clippy -p diffguard-analytics` returns 0 warnings