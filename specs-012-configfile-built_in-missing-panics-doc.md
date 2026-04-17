# Specs: ConfigFile::built_in() # Panics documentation

## Feature/Behavior Description

Add a `# Panics` section to the `ConfigFile::built_in()` function's doc comment to satisfy the `clippy::missing_panics_doc` lint. This is a documentation-only change that makes the API contract accurate.

## Acceptance Criteria

1. **Doc comment has `# Panics` section**: The `ConfigFile::built_in()` function in `crates/diffguard-types/src/lib.rs` has a `# Panics` section in its doc comment.

2. **Panic text matches expect message**: The `# Panics` section states "Panics if `built_in.json` cannot be parsed as valid JSON." which matches the `.expect()` message.

3. **Clippy warning resolved**: Running `cargo clippy -p diffguard-types -- -W clippy::missing_panics_doc` produces zero warnings for `ConfigFile::built_in()` after the fix.

4. **Style matches codebase conventions**: The `# Panics` section follows the established style used in `diff_builder.rs:48-50`:
   ```rust
   /// # Panics
   ///
   /// Panics if ...
   ```

## Non-Goals

- This does NOT change any code logic or behavior
- This does NOT add `.unwrap_or_else()` or error handling — the panic is intentional
- This does NOT audit other functions for similar issues
- This does NOT change the `include_str!` or JSON loading mechanism

## Dependencies

- `serde_json` crate for JSON parsing
- `clippy::missing_panics_doc` lint (pedantic) enabled in the project
- `built_in.json` file exists at `crates/diffguard-types/src/rules/built_in.json`
