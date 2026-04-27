# ADR-012: DiffStats Overflow Handling in parse_unified_diff

**Status:** Accepted

**Work Item:** work-c961ec86

**Issue:** [#235](https://github.com/EffortlessMetrics/diffguard/issues/235) — DiffStats files/lines usize→u32 casts lack truncation guard

---

## Context

Issue #235 reported that `DiffStats::files` and `DiffStats::lines` (both `u32`) in `parse_unified_diff()` were being set via unguarded `as u32` casts from `usize`. A diff with more than 4,294,967,295 files or lines would silently truncate.

The issue author requested applying the clamping pattern used elsewhere in the codebase:
```rust
.min(u32::MAX as usize) as u32
```

However, PR #535 (commit `e38e907`, April 15, 2026) addressed the truncation vulnerability using a different semantic approach: error propagation via `try_from().map_err()`.

---

## Decision

**Close issue #235 as addressed by PR #535.**

PR #535's error-propagation approach is architecturally superior to the clamping approach requested in issue #235. The `parse_unified_diff()` function already returns `Result<(Vec<DiffLine>, DiffStats), DiffParseError>`, so propagating overflow errors is idiomatic and gives callers explicit signals they can handle appropriately.

---

## Alternatives Considered

### 1. Clamping via `.min(u32::MAX as usize) as u32`

**Requested by issue #235**, consistent with `analytics/lib.rs:226`.

**Rejected because:**
- Silently returns `u32::MAX` for overflow — callers receive silently corrupted data
- Inconsistent with the function's `Result`-based API contract
- The `analytics/lib.rs` use case differs: it aggregates display metrics where `u32::MAX` is a meaningful sentinel. `parse_unified_diff` is a parser where overflow indicates an invalid or malicious input.
- Would break callers that handle `DiffParseError::Overflow`

### 2. Silent clamping via `try_from().unwrap_or(u32::MAX)`

**Found on branch `feat/work-095e24f2`** (commit `d6a3b91`).

**Rejected because:**
- Same problem as above — silently corrupts data
- Introduces inconsistency with the error-propagating approach already on main

### 3. Keep error propagation (PR #535 approach)

**Chosen.**

**Reasons:**
- `parse_unified_diff` returns `Result`, so error propagation is idiomatic Rust
- Callers receive explicit `DiffParseError::Overflow` on invalid input
- No silent data corruption
- Matches the pattern in `evaluate.rs:105` which also uses `try_from()` in a `Result`-returning context

---

## Consequences

### Benefits
- **No silent truncation**: Overflow always produces an explicit error
- **API consistency**: The function behaves as its return type promises
- **Caller control**: Callers choose how to handle overflow (fail, clamp, log)

### Tradeoffs
- **Different from analytics/lib.rs**: The analytics crate uses clamping for display aggregation — this is intentional and appropriate there, but not here
- **Breaking change potential**: If any caller was relying on clamped values, it will now receive an error. However, such callers were already broken by PR #535's merge.

---

## Current Code (as of HEAD at PR #535 merge)

```rust
let stats = DiffStats {
    files: u32::try_from(files.len())
        .map_err(|_| DiffParseError::Overflow(format!("too many files (> {})", u32::MAX)))?,
    lines: u32::try_from(out.len())
        .map_err(|_| DiffParseError::Overflow(format!("too many lines (> {})", u32::MAX)))?,
};
```

---

## References

- Issue [#235](https://github.com/EffortlessMetrics/diffguard/issues/235)
- PR #535 (commit `e38e907`)
- `crates/diffguard-analytics/src/lib.rs:226` — clamping pattern (different context)
- `crates/diffguard-domain/src/evaluate.rs:105` — `try_from().unwrap_or()` (silent clamp, different context)
- `crates/diffguard-diff/src/unified.rs:337-341` — current error-propagation approach