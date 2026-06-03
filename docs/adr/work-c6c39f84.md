# ADR-0001: Use explicit `()` in unit result match arms

## Status
Accepted

## Context
GitHub issue #344 reports a `clippy::ignored_unit_patterns` warning in `crates/diffguard-testkit/src/schema.rs:89`. The match arm `Ok(_)` uses a wildcard pattern to ignore the unit value `()` in the `Ok` variant of `schema.validate()`'s return type `Result<(), SchemaValidationError>`.

Using `Ok(_)` for a unit type is misleading because `_` implies "capturing and ignoring a non-unit value." The idiomatic Rust pattern for matching on `Result<T, E>` where `T` is `()` is `Ok(())`.

## Decision
Replace `Ok(_)` with `Ok(())` on line 89 of `crates/diffguard-testkit/src/schema.rs` in the `validate_with_schema()` function.

```rust
// Before
Ok(_) => Ok(()),

// After
Ok(()) => Ok(()),
```

## Consequences

### Benefits
- Eliminates the `clippy::ignored_unit_patterns` pedantic warning
- Aligns with idiomatic Rust for matching on `Result<(), E>`
- Consistent with the codebase's existing pattern of 50+ `Ok(())` match arms
- Reduces noise in CI when running with `clippy::pedantic`

### Tradeoffs
- None — this is a pure stylistic change with identical runtime behavior
- The `diffguard-testkit` crate is `publish = false` with no external consumers, so there are no semver or compatibility concerns

### Risks
- None identified

## Alternatives Considered

### 1. Keep `Ok(_)` and suppress the warning
- **Rejected because:** Adding `#[allow(clippy::ignored_unit_patterns)]` would mask a legitimate pedantic suggestion and add noise to the code.

### 2. Ignore all pedantic warnings in the crate
- **Rejected because:** The workspace runs `cargo clippy --workspace --all-targets -- -D warnings` in CI. Suppressing warnings wholesale would hide real issues. Only the specific warning is addressed.

### 3. Refactor `validate_with_schema` to avoid the match
- **Rejected because:** The function's logic requires a match to distinguish success from failure. Any refactoring would be more complex without benefit.

## Alternatives Summary

| Alternative | Reason for Rejection |
|-------------|---------------------|
| Keep `Ok(_)`, suppress warning | Adds noise, doesn't improve code |
| Ignore all pedantic warnings | Would hide real issues in CI |
| Refactor to avoid match | Over-engineering for a one-character fix |
