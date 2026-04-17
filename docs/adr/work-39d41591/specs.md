# Spec: Deduplicate `escape_md` — work-39d41591

## Feature/Behavior Description

Eliminate the duplicate `escape_md` function by making it a public, crate-root-exported function in `diffguard-core`, then importing it in `diffguard`'s `main.rs` instead of maintaining a private copy.

## Acceptance Criteria

1. **`diffguard-core` exports `escape_md` at crate root**
   - `pub fn escape_md(s: &str) -> String` is declared in `crates/diffguard-core/src/render.rs`
   - `pub use render::escape_md;` is added to `crates/diffguard-core/src/lib.rs`
   - The function compiles and is accessible as `diffguard_core::escape_md`

2. **`diffguard` imports `escape_md` from `diffguard-core`**
   - The private `escape_md` function definition is removed from `crates/diffguard/src/main.rs`
   - `escape_md` is added to the existing `diffguard_core::` import block in `main.rs`
   - `cargo build -p diffguard` succeeds without errors
   - `cargo test -p diffguard` and `cargo test -p diffguard-core` both pass

3. **Baseline mode renders correctly**
   - `escape_md` is called from `render_finding_row_with_baseline` in `--baseline` mode
   - Markdown table output in baseline mode is identical to output before this change

## Non-Goals

- This spec does NOT deduplicate `render_finding_row_with_baseline` with `render_finding_row` — they differ functionally (baseline annotation)
- This spec does NOT refactor `render_markdown_with_baseline_annotations` to reuse `diffguard_core`'s rendering pipeline
- This spec does NOT change the markdown escaping logic or the list of characters escaped
- This spec does NOT make the `render` module public in `diffguard-core`

## Dependencies

- No new dependencies required
- No Cargo.toml changes needed
- Only refactoring within existing public API surface (adding a re-export)
