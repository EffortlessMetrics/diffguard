# Specification: `utf16_length` Saturating Overflow Fix

**Work Item:** work-6f087574  
**Issue:** [#434](https://github.com/EffortlessMetrics/diffguard/issues/434)  
**File:** `crates/diffguard-lsp/src/text.rs`

## Feature/Behavior Description

The `utf16_length()` function returns the number of UTF-16 code units in a string. It must not silently produce incorrect values due to integer overflow. For strings whose UTF-16 length would exceed `u32::MAX`, the function saturates to `u32::MAX`.

## Current Behavior

```rust
pub fn utf16_length(text: &str) -> u32 {
    text.chars().map(|ch| ch.len_utf16() as u32).sum()
}
```

Uses standard wrapping `sum()`, which silently wraps to small values for strings >~2B UTF-16 code units.

## Desired Behavior

```rust
pub fn utf16_length(text: &str) -> u32 {
    text.chars().map(|ch| ch.len_utf16() as u32).fold(0u32, |acc, v| acc.saturating_add(v))
}
```

Uses `fold` with `saturating_add`, so values saturate to `u32::MAX` instead of wrapping.

## Acceptance Criteria

1. **No silent overflow:** For any input string, `utf16_length()` returns either the correct UTF-16 length (if ≤ `u32::MAX`) or `u32::MAX` (if the true length exceeds `u32::MAX`). It never returns a wrapped-around incorrect value.

2. **Backward compatible API:** The function signature and return type remain unchanged (`pub fn utf16_length(text: &str) -> u32`). No callers need to be updated.

3. **Matches existing pattern:** The fix follows the same `saturating_add` pattern already used at line 140 in `byte_offset_at_position()` within the same file.

4. **All existing tests pass:** The 18 existing `utf16_length` tests continue to pass without modification.

## Non-Goals

- Changing the return type (e.g., to `Option<u32>` or `u64`)
- Adding overflow tests (proptest cannot generate strings >2B characters)
- Fixing any other overflow issues in the codebase
- Performance optimization

## Dependencies

- Rust edition 2024, MSRV 1.92
- `proptest` available in dev-dependencies (no changes needed)
- No external crate changes required
