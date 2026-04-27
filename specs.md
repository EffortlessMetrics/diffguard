# Specs: Add `# Panics` Section to `ConfigFile::built_in()` — work-7e610c3b

## Feature/Behavior Description

Document the panic condition of `ConfigFile::built_in()` in `crates/diffguard-types/src/lib.rs` by adding a `# Panics` section to its doc comment. This silences the `clippy::missing_panics_doc` lint and follows Rust API Guidelines C409.

## Acceptance Criteria

1. **`ConfigFile::built_in()` doc comment includes a `# Panics` section** that states: "Panics if `rules/built_in.json` is malformed or cannot be parsed as valid ConfigFile JSON."

2. **`cargo clippy -p diffguard-types -- -W clippy::missing_panics_doc` passes with zero warnings** on the feature branch.

3. **`cargo test -p diffguard-types` passes** with all 40 tests green.

4. **Branch `feat/work-7e610c3b/diffguard-types-configfile-built-in` is pushed to origin** with the fix.

## Non-Goals

- Does NOT modify any function logic (`.expect()` remains unchanged)
- Does NOT add `#[allow(...)]` suppression
- Does NOT change any other functions or files
- Does NOT add project-wide lint configuration

## Dependencies

- `diffguard-types` crate must compile with `cargo check`
- `built_in.json` must exist at `crates/diffguard-types/rules/built_in.json` (compile-time asset)

## Scope

**In scope:**
- `crates/diffguard-types/src/lib.rs` — only the doc comment of `ConfigFile::built_in()`

**Out of scope:**
- Any other functions in the crate
- Any logic changes
- Any test changes
