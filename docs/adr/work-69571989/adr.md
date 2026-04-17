# ADR-015: Document Panic Condition for ConfigFile::built_in()

## Status
Proposed

## Context
`ConfigFile::built_in()` in `diffguard-types` returns the built-in configuration with default rules, loaded from `rules/built_in.json` at compile time via `include_str!`. The function was given a `#[must_use]` attribute in PR #300 (commit `163de8d`), but the accompanying doc comment was not updated to include a `# Panics` section. The function can panic via `.expect()` if `rules/built_in.json` is malformed or cannot be parsed as valid ConfigFile JSON.

Per Rust doc conventions, functions marked with `#[must_use]` that can panic should document this in a `# Panics` section. The `diffguard-types` crate is the foundational public contract for all consumers, so complete documentation reduces surprise and strengthens the crate's quality bar.

## Decision
Add a `# Panics` section to the doc comment of `ConfigFile::built_in()` that documents the `.expect()` panic condition.

The section will state:
```
/// # Panics
///
/// Panics if `rules/built_in.json` is malformed or cannot be parsed as valid
/// ConfigFile JSON.
```

This is inserted inside the existing doc comment block, before the `#[must_use]` attribute.

## Consequences

### Benefits
- Developers using `ConfigFile::built_in()` will know it can panic and under what conditions
- Completes the documentation contract established by `#[must_use]`
- Aligns with Rust doc conventions: `#[must_use]` and `# Panics` are natural companions
- Establishes a norm for `diffguard-types`: `# Panics` should accompany `#[must_use]` when a function can panic
- Zero runtime impact, zero architectural impact

### Tradeoffs / Risks
- None significant — this is a purely additive documentation change
- Risk: Incorrect panic condition description — mitigated by matching the wording to the existing `.expect()` message

## Alternatives Considered

### 1. Do not document the panic
**Rejected.** Violates Rust doc conventions. `#[must_use]` signals that ignoring the return value is dangerous, but if the function can also panic, users deserve to know. Leaving the panic undocumented is a disservice to consumers of `diffguard-types`.

### 2. Remove `#[must_use]` instead of adding `# Panics`
**Rejected.** The `#[must_use]` attribute was added intentionally in PR #300 to signal that callers must handle the return value. Removing it would lose this signal entirely, which was the whole point of the earlier fix.

### 3. Change `.expect()` to return a `Result` instead
**Rejected.** This would be a breaking API change for all consumers of `ConfigFile::built_in()`. The function is used throughout the pipeline and changing its return type would require updates in multiple crates. The issue explicitly asks for documentation, not an API change.

## Technical Notes
- The panic condition originates from `serde_json::from_str::<ConfigFile>(include_str!("rules/built_in.json")).expect(...)`
- `include_str!` guarantees the file is valid UTF-8, but does NOT guarantee valid JSON or matching schema
- The existing test `must_use_attribute_consistency` only checks for `#[must_use]` presence, not for `# Panics` documentation, so it will not be affected by this change
