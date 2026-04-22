# ADR-012: Fix Redundant Closures in diffguard-testkit

**Status:** Accepted

**Date:** 2026-04-18

**Work Item:** work-ece459be

---

## Context

The `diffguard-testkit` crate contains three `clippy::redundant_closure_for_method_calls` warnings in `crates/diffguard-testkit/src/arb.rs`. These occur when closures forward a method call on their argument without additional transformation. The project's CI enforces `cargo clippy --workspace --all-targets -- -D warnings`, making these warnings build failures.

The affected functions are:
- `arb_file_extension()` at line ~214
- `arb_dir_name()` at line ~223
- `arb_language()` at line ~253

Each uses `.prop_map(|s| s.to_string())` where `proptest::prop_oneof!` returns `&str` references that must be converted to `String`.

## Decision

Replace the redundant closures with method references:

```rust
// Before
.prop_map(|s| s.to_string())

// After
.prop_map(std::string::ToString::to_string)
```

This is the idiomatic Rust form for method references, avoids unnecessary closure allocation, and makes the intent explicit.

## Consequences

### Benefits
- Resolves CI failure from `clippy::redundant_closure_for_method_calls`
- More idiomatic Rust — method references are preferred over single-argument closures
- Zero behavioral change — the fix is purely stylistic

### Tradeoffs
- Slightly longer syntax (`std::string::ToString::to_string` vs `|s| s.to_string()`)
- The type annotation makes the conversion explicit rather than implicit

### Risks
- Low: No behavioral change, purely mechanical replacement
- Low: Line numbers may drift if file is edited before fix is applied (mitigated by anchoring to function names)

## Alternatives Considered

1. **Use `ToString::to_string` without full path** — Shorter, but requires importing `ToString` trait in scope. Full path is more explicit and avoids import changes.

2. **Use `String::from` instead** — Would work but `ToString::to_string` is the direct equivalent of the original `.to_string()` call, maintaining the same semantics.

3. **Ignore the warnings** — Not viable because CI enforces `-D warnings` and these become hard errors.

4. **Apply same fix to `diffguard-lsp` proactively** — Out of scope for this issue. Two warnings exist in `config.rs:96` and `server.rs:819` but will be tracked separately.

## Non-Goals
- Fixing `diffguard-lsp` warnings (out of scope)
- Fixing `fixtures.rs` (has zero warnings despite being mentioned in issue)
- Any behavioral changes beyond style compliance
