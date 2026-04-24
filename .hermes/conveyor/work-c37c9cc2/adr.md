# ADR-0497: Add `#[must_use]` to `utf16_length()` in diffguard-lsp

## Status
**Accepted** (implemented in PR #511, merged to `main`)

## Context

Issue #497 reported that `utf16_length()` in `crates/diffguard-lsp/src/text.rs` lacks the `#[must_use]` attribute. This function returns the count of UTF-16 code units in a string, which is used for LSP column position calculations. Without `#[must_use]`, callers can silently discard the return value, potentially causing incorrect column reporting in LSP diagnostics.

The LSP protocol requires column positions in UTF-16 code units. If a caller discards the `utf16_length()` result and instead uses a naive byte/char count, diagnostics will be misaligned for strings containing non-ASCII characters.

## Decision

Add `#[must_use]` to the `utf16_length()` function declaration:

```rust
#[must_use]
pub fn utf16_length(text: &str) -> u32 {
    text.chars().map(|ch| ch.len_utf16() as u32).sum()
}
```

This annotation was added in commit `a8974d5` (PR #511) and is already present on `origin/main`.

## Consequences

**Benefits:**
- Compiler enforces that callers handle the return value, preventing silent discard
- Consistent with the codebase pattern — `build_synthetic_diff()` and 8 functions in `unified.rs` already use `#[must_use]`
- Zero runtime cost — purely a compile-time annotation

**Tradeoffs:**
- None. This is a purely additive annotation with no behavioral change.

**Risks:**
- Low. The annotation is purely compile-time; it cannot cause runtime regressions.
- No risk of breaking existing callers — all current callers use the return value.

## Alternatives Considered

1. **Document the return value requirement in doc comments only.** Rejected because documentation can be ignored; the compiler cannot enforce it.

2. **Change the function to panic if the result is unused.** Rejected — overly aggressive. `#[must_use]` is the idiomatic Rust approach that produces a lint warning rather than a hard error.

3. **No action (leave as-is).** Rejected — the LSP column correctness risk is real and the fix is trivial.

## Relationship to Broader Patterns

This decision is consistent with the existing `#[must_use]` adoption strategy in the codebase:
- `build_synthetic_diff()` in the same file has `#[must_use]`
- 8 predicate functions in `crates/diffguard-diff/src/unified.rs` have `#[must_use]`
- The pattern follows the established discipline: functions whose return values represent meaningful side-effect-free computations that callers must not ignore should be annotated.
