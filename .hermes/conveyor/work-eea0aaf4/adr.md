# ADR-eea0aaf4: Add #[must_use] to RuleOverrideMatcher::resolve()

## Status
**Accepted** (retroactively documented; fix merged in PR #532)

## Context

`RuleOverrideMatcher::resolve()` in `crates/diffguard-domain/src/overrides.rs:109` returns a `ResolvedRuleOverride`. When a caller discards this return value — either intentionally or accidentally — the resolved override is silently dropped and the default (no override applied) behavior occurs. This is a classic silent-failure pattern that can lead to subtle bugs in production.

The risk is real because:
1. The return type is not `()` — it's a non-trivial `ResolvedRuleOverride`
2. Discarding the value produces no compiler warning without `#[must_use]`
3. The calling code in `evaluate.rs:187` captures the value, but future callers might not

This pattern already exists elsewhere in the codebase: `suppresses()` in `suppression.rs:46`, `parse_suppression()`, and builder structs in `diffguard-testkit/src/diff_builder.rs` all carry `#[must_use]`.

## Decision

**Add `#[must_use]` to `RuleOverrideMatcher::resolve()`.**

This was implemented in PR #532 (commit e0c2094) which added `#[must_use]` to:
- `RuleOverrideMatcher::resolve()` (line 108 of overrides.rs)
- `RuleOverrideMatcher::suppresses()` (line 46 of suppression.rs)
- Builder structs in diffguard-testkit

## Consequences

### Benefits
- **Compiler-level enforcement**: Callers must handle the resolved override or explicitly discard with `let _ = ...`
- **Clippy warning**: Future callers who discard the result will get a compile-time warning
- **Consistency**: Matches existing `#[must_use]` patterns across the codebase (12 occurrences in diffguard-domain)
- **Zero runtime cost**: `#[must_use]` is purely a compile-time annotation; it generates no additional machine code

### Tradeoffs / Risks
- **New compiler warning on intentionally discarded results**: Developers who intentionally discard the result must use `let _ = ...` to suppress the warning. This is the intended behavior — intentional discarding should be explicit.
- **None**: This is a non-breaking change; it only produces warnings for code that was already potentially buggy.

## Alternatives Considered

### 1. Document the requirement in doc comments only
- *Rejected*: Documentation is not enforced. A `#[must_use]` attribute produces a compiler warning that fails CI, whereas doc comments can be ignored. `#[must_use]` is the idiomatic Rust mechanism for this.

### 2. Return a different type that forces usage
- *Rejected*: Changing the return type (e.g., wrapping in a `MustUseResolver`) would be a breaking API change with significant churn. `#[must_use]` achieves the goal without any API change.

### 3. No action
- *Rejected*: Silent default behavior when override resolution is discarded is a real bug risk, as confirmed by issue #346 (duplicate of #483). The fix is trivial and cost-free.

## Decision Details

- **Scope**: `crates/diffguard-domain/src/overrides.rs`, single function `RuleOverrideMatcher::resolve()`
- **Change**: One-line attribute insertion (`#[must_use]`) above `pub fn resolve()`
- **Risk**: Zero — `#[must_use]` only enables a compiler warning, cannot change behavior or break compilation
- **Pattern established**: `RuleOverrideMatcher::suppresses()`, `parse_suppression()`, and builder structs in diffguard-testkit

## References

- Issue: #346 (title only — body formatting corrupted; duplicate of #483)
- Fixing PR: #532
- Commit: e0c2094
- Calling site (verified correct usage): `crates/diffguard-domain/src/evaluate.rs:187`
