# ADR-2026-0411-001: Remove `CompiledRule` from Public API Export

**Status:** Proposed  
**Date:** 2026-04-11  
**Gate:** DESIGNED  

---

## Context

`CompiledRule` is a struct defined in `diffguard_domain::rules` that represents a compiled rule with pre-built regex patterns, glob sets, and language filters. It is currently publicly re-exported from the crate root via:

```rust
// crates/diffguard-domain/src/lib.rs:19
pub use rules::{CompiledRule, RuleCompileError, compile_rules, detect_language};
```

However, `CompiledRule` is an **internal implementation detail**. Users of the crate should interact with the public API at a higher level (`compile_rules` function, `Evaluation` struct, etc.). Exposing `CompiledRule` breaks encapsulation and makes it difficult to evolve the internal rule representation without breaking downstream consumers.

## Problem Statement

The public re-export of `CompiledRule` at `diffguard_domain::` level creates a leaky abstraction:

1. `CompiledRule` is documented as internal (CLAUDE.md refers to it as internal implementation)
2. Public consumers may depend on its internal structure, making refactoring costly
3. The struct contains regex and globset internals that should remain opaque

## Decision

**Remove `CompiledRule` from the public re-export in `lib.rs` and update internal consumers to use the direct module path `diffguard_domain::rules::CompiledRule`.**

### Affected Consumers (3 files)

| File | Line | Current Import | Required Import |
|------|------|----------------|-----------------|
| `crates/diffguard/src/main.rs` | 756 | `diffguard_domain::CompiledRule` | `diffguard_domain::rules::CompiledRule` |
| `crates/diffguard-domain/tests/properties.rs` | 1973 | `diffguard_domain::CompiledRule` | `diffguard_domain::rules::CompiledRule` |
| `bench/benches/evaluation.rs` | 32 | `diffguard_domain::rules::CompiledRule` | (already correct) |

### Documentation Update

| File | Line | Change |
|------|------|--------|
| `docs/architecture.md` | 109 | Update to clarify `CompiledRule` is internal |

## Alternatives Considered

1. **#[non_exhaustive] + documentation** — Signals API intent but doesn't prevent compilation dependency
2. **Deprecation window** — Adds churn without benefit since no external consumers are known
3. **Two-tier API** — Over-engineering for an internal detail

## Consequences

- **Positive:** Encapsulation improved; internal representation can evolve independently
- **Positive:** Public API surface reduced to intentionally stable interfaces
- **Risk:** Any unknown external consumers would break (mitigation: this is an internal crate with controlled consumers)
- **Risk:** Documentation may reference the removed export (mitigation: update architecture.md)

## Verification

1. `cargo check -p diffguard-domain` succeeds
2. `cargo check -p diffguard` succeeds  
3. `cargo check -p bench` succeeds
4. `cargo test -p diffguard-domain` succeeds
5. No remaining references to `diffguard_domain::CompiledRule` in code (only `diffguard_domain::rules::CompiledRule`)
