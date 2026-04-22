# ADR-047: Saturating Arithmetic for `utf16_length()` Overflow Prevention

**Status:** Accepted  
**Work Item:** work-6f087574  
**Issue:** [#434](https://github.com/EffortlessMetrics/diffguard/issues/434)  
**Date:** 2026-04-17  
**Repo:** /home/hermes/repos/diffguard

## Context

The `utf16_length()` function in `crates/diffguard-lsp/src/text.rs` computes the number of UTF-16 code units in a string. It currently uses `.sum()` on an iterator of `u32` values:

```rust
pub fn utf16_length(text: &str) -> u32 {
    text.chars().map(|ch| ch.len_utf16() as u32).sum()
}
```

For strings containing more than ~2 billion UTF-16 code units (i.e., strings with >1B characters that are all surrogate pairs), the sum wraps around to a small value via standard wrapping arithmetic. This is silently wrong — the function returns an incorrect value with no error signal.

This matters for LSP integration: the sole production caller at `server.rs:777` uses `utf16_length()` to compute diagnostic span end characters. A wrapped value could produce spans that appear to start after they end, violating the "never lies" invariant for user-facing LSP diagnostics.

The same file already uses `saturating_add` for an identical accumulation pattern at line 140 in `byte_offset_at_position()`.

## Decision

Replace `.sum()` with a `fold` using `saturating_add`:

```rust
pub fn utf16_length(text: &str) -> u32 {
    text.chars().map(|ch| ch.len_utf16() as u32).fold(0u32, |acc, v| acc.saturating_add(v))
}
```

This ensures that for extremely long strings, the function returns `u32::MAX` instead of a wrapped-around incorrect value. The return type remains `u32` — no API change.

## Consequences

**Benefits:**
- Overflow now saturates to `u32::MAX` instead of silently wrapping to a wrong value
- Matches the established pattern already used at line 140 in the same file
- No API change — drop-in replacement
- O(n) time complexity unchanged

**Tradeoffs:**
- Extremely long strings (>2B UTF-16 code units) now return `u32::MAX` instead of wrapping. This is a correctness improvement, not a regression.
- `fold` vs `sum` may have marginally different performance characteristics in the LLVM-generated code, but both are O(n)

## Alternatives Considered

1. **Return `Option<u32>`** — Would propagate `Overflow` error via `Result`. Rejected because the issue explicitly requires saturating semantics, and the same file already uses saturating at line 140.

2. **Return `u64`** — Would increase the overflow ceiling but not eliminate it for truly massive strings. Would also change the API (return type), propagating to callers. The saturating approach is more correct for this use case since LSP positions are u32.

3. **Leave as-is** — Rejected because silent wrong values violate the "never lies" invariant. The issue correctly identifies this as a bug.
