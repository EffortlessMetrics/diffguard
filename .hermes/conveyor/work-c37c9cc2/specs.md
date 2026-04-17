# Spec: `#[must_use]` on `utf16_length()` — work-c37c9cc2

## Feature Description

Add the `#[must_use]` attribute to the `utf16_length()` function in `crates/diffguard-lsp/src/text.rs` to enforce that callers handle the UTF-16 code unit count return value.

**Status: Already implemented** — The fix was delivered in PR #511 (commit `a8974d5`, merged to `main` on 2026-04-15).

## Function Signature

```rust
#[must_use]
pub fn utf16_length(text: &str) -> u32
```

Returns the number of UTF-16 code units in `text`. This is used for LSP column position calculations.

## Acceptance Criteria

1. **Attribute present:** `crates/diffguard-lsp/src/text.rs` line ~121 contains `#[must_use]` immediately before `pub fn utf16_length`.

2. **Compiles cleanly:** `cargo check -p diffguard-lsp` produces no warnings or errors related to `utf16_length`.

3. **Clippy clean:** `cargo clippy -p diffguard-lsp` does not report `must_use_candidate` for `utf16_length`.

4. **Existing callers use return value:** All existing call sites (e.g., `server.rs:777`) use the return value (via `.max(1)`), confirming no caller is broken by the annotation.

## Non-Goals

- This does not change the runtime behavior of `utf16_length()`
- This does not add new tests — the fix is purely a compiler annotation
- This does not modify any callers

## Dependencies

- None. The fix is self-contained and purely additive.

## Verification

The acceptance criteria above are already satisfied on `origin/main`:
- `grep -B1 "pub fn utf16_length" crates/diffguard-lsp/src/text.rs` → shows `#[must_use]`
- `cargo check -p diffguard-lsp` → exits 0
- `grep -n "must_use" crates/diffguard-lsp/src/text.rs` → confirms attribute on line 121

## Issue Reference

- Issue: #497
- Fix PR: #511 (commit `a8974d5`)
- Status: Merged to `main` on 2026-04-15
