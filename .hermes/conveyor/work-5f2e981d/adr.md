# ADR-047: Add #[must_use] to CompiledRule::applies_to()

**Status:** Proposed

**Date:** 2026-04-18

**Work ID:** work-5f2e981d

## Context

The `CompiledRule::applies_to()` method in `crates/diffguard-domain/src/rules.rs:58` returns a `bool` that gates whether a rule should be evaluated against a file. If callers discard this return value (which compiles without warning without `#[must_use]`), the rule's include/exclude glob filters and language filters are silently bypassed — the rule will appear to match regardless of its scope constraints.

This is a silent correctness failure. Callers that discard the return value believe they are applying rule scope filtering when they are not.

## Decision

Add `#[must_use]` to the `applies_to()` method declaration:

```rust
#[must_use]
pub fn applies_to(&self, path: &Path, language: Option<&str>) -> bool
```

This is purely a compile-time annotation. It emits a warning when the return value is discarded, but does not change runtime behavior.

## Consequences

### Benefits
- Compiler will warn if any future caller discards the `applies_to()` return value
- Prevents the silent bypass of include/exclude glob filters and language filters
- Consistent with existing `#[must_use]` patterns in the codebase (`is_binary_file`, `is_submodule`, `Suppression::suppresses()`, `Override::resolve()`)
- Zero runtime overhead — no behavioral change

### Risks
- If `applies_to()` is later extracted into a trait, `#[must_use]` must be placed on the trait signature as well to avoid a silent regression (low probability)
- None other — the change is mechanically simple and purely compile-time

## Alternatives Considered

### 1. Document the requirement without `#[must_use]`
- Rejected: Documentation can be overlooked and does not prevent violations at compile time
- The entire value of `#[must_use]` is that it enforces the constraint automatically

### 2. Return `()` instead of `bool` and panic on mis-use
- Rejected: This would change the API contract and add runtime overhead
- Would break existing callers that correctly check the return value
- Panicking is a disproportionate response for a boolean gate

### 3. Wrap return value in a newtype with `#[must_use]`
- Rejected: Overengineered for a one-line fix
- Adds unnecessary API surface area and cognitive load
- The existing `#[must_use]` pattern on `bool`-returning functions in the codebase is the established solution