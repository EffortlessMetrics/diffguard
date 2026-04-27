# ADR — work-40b6ed21: Close Issue #545 as Already Resolved

## Status
Accepted

## Context

Issue #545 reported silent `usize → u32` truncation in `crates/diffguard-diff/src/unified.rs:336-337`, specifically:
```rust
files: files.len() as u32,
lines: out.len() as u32,
```

The issue was filed on 2026-04-16. Investigation reveals that **the identical fix was already merged one day prior** (commit `e38e907`, 2026-04-15) via PR #535, which replaced the `as u32` casts with `u32::try_from()` + `DiffParseError::Overflow`.

Additionally, prior conveyor agents (research_agent, plan_review_agent) reported phantom uncommitted changes to `unified.rs`. The maintainer-vision-agent verified these reports were incorrect — there are zero uncommitted changes to `unified.rs` in the working directory.

## Decision

**No implementation is required.** Issue #545 is already resolved and should be closed as a duplicate of #475 (which was the vehicle for commit `e38e907`).

The fix at `crates/diffguard-diff/src/unified.rs:337-342` uses the **fail-loudly** approach:
```rust
let stats = DiffStats {
    files: u32::try_from(files.len())
        .map_err(|_| DiffParseError::Overflow(format!("too many files (> {})", u32::MAX)))?,
    lines: u32::try_from(out.len())
        .map_err(|_| DiffParseError::Overflow(format!("too many lines (> {})", u32::MAX)))?,
};
```

## Consequences

### Benefits
- No regression: the truncation vulnerability is already fixed
- No code changes needed, reducing risk

### Tradeoffs / Latent Debt
1. **`DiffParseError::Overflow` has no test coverage** — no test verifies that the Overflow variant is actually triggered when counts exceed `u32::MAX`
2. **Inconsistent overflow strategies across the codebase** — three different approaches exist:
   - `unified.rs:337-342`: `u32::try_from().map_err()` — fail loudly
   - `evaluate.rs:105`: `u32::try_from().unwrap_or(u32::MAX)` — cap silently
   - `evaluate.rs:298`: `u32::try_from().ok()` — swallow silently
3. **No stated policy** for which approach to use when `usize → u32` conversions are needed

## Alternatives Considered

### Alternative 1: Add Regression Test for Overflow
Add a fuzz/property test that exercises `DiffParseError::Overflow` by providing diff input with >4.3B files or lines. **Rejected** — feasible but out of scope for this work item; should be a separate work item.

### Alternative 2: Remove `DiffParseError::Overflow` as Dead Code
If the Overflow variant truly has no call sites in practice, remove it. **Rejected** — the variant IS used at `unified.rs:339-342` (the committed fix). It is not dead code.

### Alternative 3: Formalize Overflow Policy via ADR
Create a new ADR establishing a project-wide policy for `usize → u32` conversions. **Deferred** — worth doing but should be its own work item, not blocking this issue's closure.

## References
- Issue #545: https://github.com/EffortlessMetrics/diffguard/issues/545
- Commit `e38e907`: fix: replace lossy usize→u32 casts with checked conversions (#535)
- Issue #475: Vehicle for the original fix
- Issue #481: Related overflow issue in `evaluate.rs` (separate location, different fix applied)
