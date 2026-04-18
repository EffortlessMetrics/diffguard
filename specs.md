# Specification — Add #[must_use] to split_lines()

## Feature / Behavior Description

Add the `#[must_use]` Rust attribute to the public `split_lines()` function in `crates/diffguard-lsp/src/text.rs`. This causes the Rust compiler to emit a warning if any caller discards the return value of `split_lines()` rather than capturing it.

**Change:** Insert `#[must_use]` on its own line directly above `pub fn split_lines(text: &str) -> Vec<&str> {` at line 6 of `crates/diffguard-lsp/src/text.rs`.

## Acceptance Criteria

1. **`#[must_use]` is present on `split_lines()`** — The attribute appears on the line immediately preceding `pub fn split_lines(text: &str) -> Vec<&str> {` in `crates/diffguard-lsp/src/text.rs`.

2. **Crate builds cleanly** — `cargo build --package diffguard-lsp` completes with no errors.

3. **Clippy passes** — `cargo clippy --package diffguard-lsp` reports no warnings or errors.

4. **All tests pass** — `cargo test --package diffguard-lsp` passes all 19 tests with no regressions.

5. **No new compiler warnings introduced within the crate** — Since all three internal callers (lines 15, 16, 37) properly capture the return value with direct assignment, adding `#[must_use]` should not produce any new warnings in the crate itself.

## Non-Goals

- No changes to function signature, behavior, or public API
- No new tests for the `#[must_use]` attribute itself (this is a compile-time convention, not a behavioral change)
- No changes to other functions or files beyond `split_lines()` in `text.rs`
- No changes to documentation or changelog

## Dependencies

- Rust compiler (standard `#[must_use]` attribute — no external dependencies)
- The crate's existing CI/CD pipeline (cargo build, clippy, test) serves as verification
