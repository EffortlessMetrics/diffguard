# ADR: Fix default_trait_access lint in diffguard-testkit

## Status
Proposed

## Context

Issue #561 reports a `default_trait_access` clippy lint warning in `crates/diffguard-testkit/src/fixtures.rs` (10 occurrences) and `crates/diffguard-testkit/src/arb.rs` (2 occurrences). These files use `Default::default()` instead of the more explicit `MatchMode::default()` when constructing `RuleConfig` structs with `match_mode` fields.

The lint triggers when clippy is invoked with `-W clippy::default_trait_access`:
```bash
cargo clippy -p diffguard-testkit -- -W clippy::default_trait_access
```

This produces 12 warnings, one for each unqualified `Default::default()` call on `MatchMode`.

## Decision

We will replace all 12 occurrences of `Default::default()` with `MatchMode::default()` in `fixtures.rs` and `arb.rs`, after adding `MatchMode` to the import lists in both files.

### Changes Required

1. **fixtures.rs** (line 6-9):
   - Add `MatchMode` to the `diffguard_types` import
   - Replace 10 occurrences of `match_mode: Default::default()` with `match_mode: MatchMode::default()`

2. **arb.rs** (line 17-20):
   - Add `MatchMode` to the `diffguard_types` import
   - Replace 2 occurrences of `match_mode: Default::default()` with `match_mode: MatchMode::default()`

## Consequences

### Positive
- Satisfies issue #561 and eliminates the lint warning
- Code is more explicit about which type's default is being invoked
- Aligns with the lint's guidance for qualified trait access

### Negative / Tradeoffs
- The fix still relies on the `Default` trait (just accessed more explicitly)
- `MatchMode::Any` would be more semantically meaningful than `MatchMode::default()` in fixture contexts, but was not the requested fix
- The lint is opt-in (not part of standard CI), so the practical impact is minimal unless explicitly enabled

### Neutral
- No behavioral change; `MatchMode::default()` is semantically identical to `MatchMode::Any`
- `diffguard-testkit` is `publish = false`; no external consumers affected
- Purely mechanical change with no architectural implications

## Alternatives Considered

### Alternative 1: Use `MatchMode::Any` directly
```rust
match_mode: MatchMode::Any,
```
- More explicit and self-documenting in fixture/arb contexts
- No import change required for variants
- Immune to future changes in what `MatchMode`'s default is
- **Rejected**: Issue #561 specifically requests `MatchMode::default()`; adopting a different fix would not fulfill the issue's intent

### Alternative 2: Suppress the lint in clippy.toml
```toml
[lints.clippy]
default_trait_access = "allow"
```
- No code changes required
- **Rejected**: Would suppress the lint project-wide; inconsistent with the culture of addressing reported lints when filed