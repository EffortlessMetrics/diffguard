# ADR — work-bc6e41f0

## Use `ToString::to_string` instead of redundant closure in `nth_string_arg`

**Status:** Proposed

**Work Item:** work-bc6e41f0  
**GitHub Issue:** #441  
**File:** `crates/diffguard-lsp/src/server.rs`  
**Line:** 819

---

## Context

Clippy's `redundant_closure_for_method_calls` lint (enabled via `clippy::pedantic`) flags the
following pattern in `nth_string_arg`:

```rust
.map(|value| value.to_string())
```

The closure `|value| value.to_string()` is redundant because `ToString::to_string` can be used
directly as a method reference. This is a code-quality improvement that aligns with the existing
precedent set in `clippy_refactor_test.rs:116`, where the same pattern was fixed for
`str::to_ascii_lowercase`.

---

## Decision

Replace `.map(|value| value.to_string())` with `.map(ToString::to_string)` on line 819 of
`crates/diffguard-lsp/src/server.rs`.

The `ToString::to_string` trait method reference is semantically identical to the closure for
`&str` values, but is more idiomatic and eliminates the pedantic lint warning.

---

## Consequences

| | |
|---|---|
| **Benefit** | Eliminates pedantic clippy warning; more idiomatic Rust |
| **Risk** | None — purely syntactic, zero behavioral change |
| **Scope** | Single line in one function (`nth_string_arg`); call sites unaffected |

---

## Alternatives Considered

1. **Leave the closure as-is.** Rejected — the lint is valid and the codebase already has a
   precedent for fixing this pattern.

2. **Fix `config.rs:96` in the same commit.** Rejected — GitHub issue #441 explicitly scopes
   this fix to `server.rs:819` only. Scope discipline is important for small, focused PRs.

3. **Use `.to_owned()` instead of `.to_string()`** — This would change the return type from
   `String` to `&str` or require additional handling, and does not satisfy the lint which
   specifically targets the `to_string()` pattern on method calls.
