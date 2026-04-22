# ADR: Add # Panics documentation to ConfigFile::built_in()

## Status
Proposed

## Context

The `ConfigFile::built_in()` function in `crates/diffguard-types/src/lib.rs` calls `.expect()` on `serde_json::from_str` when parsing the embedded `built_in.json` file. The `clippy::missing_panics_doc` lint (pedantic) requires documenting any public function that may panic.

The function was recently refactored from hardcoded Rust to a JSON data file loaded via `include_str!` + `serde_json`. This refactoring introduced the `.expect()` call that can panic if the JSON is malformed.

The `diffguard-types` crate intentionally has no runtime I/O — `built_in.json` is embedded via `include_str!` at compile time. The crate's API contract should accurately describe this behavior.

## Decision

Add a `# Panics` section to the `ConfigFile::built_in()` doc comment:

```rust
/// Returns the built-in configuration with default rules.
///
/// Rules are loaded from `rules/built_in.json` at compile time via `include_str!`.
/// This ensures the JSON is embedded in the binary and avoids any I/O at runtime.
///
/// # Panics
///
/// Panics if `built_in.json` cannot be parsed as valid JSON.
#[must_use]
pub fn built_in() -> Self {
```

This follows the established codebase style used in `diff_builder.rs:48-50`.

## Consequences

### Benefits
- Documentation accurately describes the panic condition
- API contract is clear to callers
- Resolves `clippy::missing_panics_doc` warning
- Follows established style used elsewhere in the codebase

### Tradeoffs
- None — this is a documentation-only change with no behavioral impact

## Alternatives Considered

1. **Suppress the lint with `#[allow(clippy::missing_panics_doc)]`** — Rejected because the function genuinely can panic and should be documented, not suppressed.

2. **Change `.expect()` to `unwrap_or_else()` with a fallback** — Rejected because there is no meaningful fallback `ConfigFile` to return; the panic is intentional to fail fast on corrupt embedded data.

3. **Audit all functions for similar issues** — Rejected because the issue is narrowly scoped to `ConfigFile::built_in()`. Verification confirmed no other functions in `lib.rs` trigger this lint.
