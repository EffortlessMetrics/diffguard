# Specs-012: DiffStats Overflow Handling

**Work Item:** work-c961ec86

**Issue:** [#235](https://github.com/EffortlessMetrics/diffguard/issues/235)

## Summary

Issue #235 reported that `DiffStats::files` and `DiffStats::lines` (both `u32`) in `parse_unified_diff()` were being set via unguarded `as u32` casts from `usize`. A diff with > 4,294,967,295 files or lines would silently truncate.

**This issue is already resolved by PR #535** which implemented error propagation via `try_from().map_err()`.

---

## Behavior

### Current Behavior (after PR #535)

`parse_unified_diff()` returns `DiffParseError::Overflow` when a diff contains more than `u32::MAX` files or lines:

```
DiffParseError::Overflow("too many files (> 4294967295)")
DiffParseError::Overflow("too many lines (> 4294967295)")
```

### Not in Scope

- **Switching to clamping**: The issue author requested `.min(u32::MAX as usize) as u32` (clamping), but this is not appropriate for `parse_unified_diff()` because:
  - The function returns `Result`, so error propagation is idiomatic
  - Clamping would silently corrupt data
  - Callers handling `DiffParseError::Overflow` would break

---

## Acceptance Criteria

1. **`parse_unified_diff()` returns `DiffParseError::Overflow` on overflow** — When a diff input contains more than `u32::MAX` (4,294,967,295) files or lines, the function returns `Err(DiffParseError::Overflow(...))` instead of silently truncating.

2. **No silent truncation** — `DiffStats::files` and `DiffStats::lines` are never set to truncated values. All `usize → u32` conversions use `try_from()` with proper error handling.

3. **Tests pass** — All existing tests in `diffguard-diff` pass, including the overflow-handling red tests added by commit `cada59ab`.

4. **Clippy clean** — `cargo clippy --workspace` reports no new warnings related to this code path.

---

## Non-Goals

- **Do not switch to clamping** — The `d6a3b91` branch introduced `unwrap_or(u32::MAX)` (silent clamping). This is a regression from the correct error-propagation approach and should not be merged.
- **Do not close #235 as "wontfix"** — The issue is legitimately resolved; it just uses error propagation instead of the clamping the author suggested.

---

## Dependencies

- `DiffParseError::Overflow` variant (added by PR #535)
- `try_from()` conversions (stable Rust)
- No new dependencies required