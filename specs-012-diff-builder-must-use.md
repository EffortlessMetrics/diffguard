# Specs-012: Add #[must_use] to diff_builder Self-returning methods

## Feature / Behavior Description
Add `#[must_use]` annotations to 8 Self-returning builder methods in `crates/diffguard-testkit/src/diff_builder.rs` so that calling them without chaining or assignment produces a compiler warning.

The affected methods are on `FileBuilderInProgress` and `HunkBuilderInProgress`. Both structs already carry `#[must_use]` at the struct level, but per-method annotations are required for the attribute to fire on method call return values.

## Acceptance Criteria

1. **Build succeeds**: `cargo build -p diffguard-testkit` compiles without errors.
2. **Tests pass**: `cargo test -p diffguard-testkit` runs all tests successfully (all existing tests already chain correctly).
3. **Clippy pedantic clean (stretch)**: `cargo clippy -p diffguard-testkit -- -W clippy::return_self_not_must_use` produces no new warnings for the 8 targeted methods. (Note: the struct-level `#[must_use]` may suppress the lint on some of these, but the per-method attribute is still correct annotation hygiene.)

## Non-Goals (Out of Scope)

- Adding `#[must_use]` to `FileBuilder` and `HunkBuilder` Self-returning methods — same bug pattern but separate scope.
- Adding `#[must_use]` to extension trait methods (`add_lines_from_slice`, `add_hunk_directly`) — not listed in issue #512.
- Any behavioral changes — purely an annotation-only change.

## Dependencies

- No new dependencies required.
- No changes to any other crates in the workspace.
- Crate `diffguard-testkit` is `publish = false` (internal dev-dependency only), so this change has no external API impact.

## File Changes

Only one file is modified:
- `crates/diffguard-testkit/src/diff_builder.rs`

Methods to annotate (8 total):
- `FileBuilderInProgress::binary()` — line ~113
- `FileBuilderInProgress::deleted()` — line ~119
- `FileBuilderInProgress::new_file()` — line ~125
- `FileBuilderInProgress::mode_change()` — line ~131
- `FileBuilderInProgress::rename_from()` — line ~137
- `HunkBuilderInProgress::context()` — line ~159
- `HunkBuilderInProgress::add_line()` — line ~165
- `HunkBuilderInProgress::remove()` — line ~171
