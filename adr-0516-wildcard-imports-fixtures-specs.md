# Specification: Replace Wildcard Imports in fixtures.rs

## Feature / Behavior Description

Replace the two `use super::*;` wildcard imports in `crates/diffguard-testkit/src/fixtures.rs` with explicit imports listing only the types actually used in each submodule.

### Target Locations

1. **`sample_configs` submodule (line 17)**: Replace `use super::*;` with explicit imports for `ConfigFile`, `Defaults`, `RuleConfig`, `Severity`, `Scope`, `FailOn`.

2. **`sample_receipts` submodule (line 608)**: Replace `use super::*;` with explicit imports for `CheckReceipt`, `CHECK_SCHEMA_V1`, `ToolMeta`, `DiffMeta`, `Finding`, `Severity`, `Scope`, `Verdict`, `VerdictCounts`, `VerdictStatus`.

## Acceptance Criteria

1. **Compilation succeeds**: After the change, `cargo check -p diffguard-testkit` completes without errors.

2. **Tests pass**: `cargo test -p diffguard-testkit` completes successfully, confirming all fixtures remain functional.

3. **Explicit imports are complete**: All types used in `sample_configs` and `sample_receipts` are covered by the new explicit import lists.

4. **No `wildcard_imports` lint warnings**: Running `cargo clippy -p diffguard-testkit -- -W clippy::wildcard_imports` on the modified lines produces no warnings for the replaced imports.

5. **Branch created and pushed**: A feature branch `feat/work-0bd76b5e/testkit/fixtures.rs:-wildcard-imports-ri` is created from the current `main` and pushed to origin.

## Non-Goals

- This fix does **not** address other wildcard imports elsewhere in `diffguard-testkit` (`arb.rs`, `diff_builder.rs`, `schema.rs`, or the `#[cfg(test)]` module in `fixtures.rs`).
- This does **not** modify any types or behavior in `diffguard_types` itself.
- This does **not** add new test fixtures or modify existing fixture data — only the import style changes.

## Dependencies

- `diffguard_types` must be compilable (it is the foundational crate, always available).
- No new crate dependencies or feature flags are introduced.
