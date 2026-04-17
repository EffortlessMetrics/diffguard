# Specs: Add # Panics Section to ConfigFile::built_in()

## Feature / Behavior Description

Add a `# Panics` documentation section to the `ConfigFile::built_in()` function in `diffguard-types` to document the panic condition from the `.expect()` call on `serde_json::from_str`.

## Acceptance Criteria

1. **Build succeeds**: `cargo build -p diffguard-types --lib` completes without errors. The new doc comment must be valid Rustdoc syntax.

2. **Doc comment renders correctly**: `cargo doc -p diffguard-types --no-deps` produces no warnings or errors related to the new `# Panics` section.

3. **`# Panics` section is present in source**: The `ConfigFile::built_in()` doc comment contains a properly formatted `# Panics` section that describes the panic condition: "Panics if `rules/built_in.json` is malformed or cannot be parsed as valid ConfigFile JSON."

4. **Tests pass**: `cargo test -p diffguard-types` passes all tests, including `must_use_attribute_consistency` which verifies `#[must_use]` presence (this test is unaffected since the attribute's position relative to `pub fn` is unchanged).

## Non-Goals

- This change does NOT modify the function's behavior or return type
- This change does NOT add, remove, or modify any tests
- This change does NOT modify `rules/built_in.json` or the JSON parsing logic
- This change does NOT add `# Panics` to other `#[must_use]` functions that do not panic (e.g., `as_str` methods on `Severity`, `Scope`, `FailOn`)

## Dependencies

- `serde_json` for `serde_json::from_str` (already a dependency)
- `schemars` for `JsonSchema` derive (already a dependency)
- No new dependencies required

## Implementation

The fix is a single doc comment addition to `crates/diffguard-types/src/lib.rs` inside the `impl ConfigFile` block, inserting the `# Panics` section before the `#[must_use]` attribute on `pub fn built_in()`.

## Verification

Run the following commands to verify:
```bash
cargo build -p diffguard-types --lib
cargo doc -p diffguard-types --no-deps
cargo test -p diffguard-types
```
