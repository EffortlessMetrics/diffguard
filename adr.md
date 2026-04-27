# ADR-XXX: Add `# Panics` Section to `ConfigFile::built_in()`

## Status
Proposed

## Context

GitHub issue #587 reports that `ConfigFile::built_in()` in `crates/diffguard-types/src/lib.rs` is missing a `# Panics` section in its doc comment. The function uses `.expect()` when parsing `built_in.json`, which can panic at runtime if the embedded JSON is malformed. The `clippy::missing_panics_doc` lint fires because of this gap.

Rust API Guidelines C409 requires that public functions that can panic must document the panic condition in a `# Panics` section.

## Decision

Add a properly formatted `# Panics` section to the `ConfigFile::built_in()` doc comment that documents the panic condition: parsing failure of `built_in.json`.

```rust
/// Returns the built-in configuration with default rules.
///
/// Rules are loaded from `rules/built_in.json` at compile time via `include_str!`.
/// This ensures the JSON is embedded in the binary and avoids any I/O at runtime.
///
/// # Panics
///
/// Panics if `rules/built_in.json` is malformed or cannot be parsed as valid
/// ConfigFile JSON.
#[must_use]
pub fn built_in() -> Self {
    serde_json::from_str(include_str!("rules/built_in.json"))
        .expect("built_in.json must be valid UTF-8 and parseable as ConfigFile JSON")
}
```

## Alternatives Considered

1. **Use `#[allow(clippy::missing_panics_doc)]` to suppress the lint** — Rejected by prior ADR. This bypasses the lint rather than fixing the root cause and sets a poor precedent for other functions.

2. **Change `.expect()` to `Result` return type** — Rejected because it would change the API contract. `built_in()` is intended to be infallible at runtime since the JSON is compile-time validated. Returning `Result` would force all callers to handle an error that can never occur.

3. **Use `unwrap()` instead of `.expect()` with descriptive message** — The `.expect()` already has a descriptive message. The issue is the missing documentation, not the panic mechanism.

## Consequences

**Benefits:**
- `clippy::missing_panics_doc` lint is satisfied
- Follows Rust API Guidelines C409
- Documents a realistic panic path (malformed embedded JSON during development)
- No runtime behavior change

**Tradeoffs:**
- If `built_in.json` is ever modified to be malformed, the binary will panic with a clear message — this is the intended behavior (fail fast on broken embedded config)

**Risks:**
- None identified — the fix is minimal and purely documentary

## System Note

This same fix has been applied on at least 6 prior occasions (commits `be69270`, `3ffff12`, `075659d`, `21d54b5`, `ecdb5fc`, `1c628bf`) on different feature branches. None of those branches were merged to `main`. This ADR represents the authoritative decision for work item `work-7e610c3b`.
