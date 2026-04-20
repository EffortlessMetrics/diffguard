# Specs — work-a59eb6b6

## Feature: Deduplicate `escape_md` by Hoisting to `diffguard-types`

Remove the duplicate `escape_md` implementations from `diffguard-core` and `diffguard` by hoisting to their shared dependency `diffguard-types`.

## Background

`escape_md` escapes special Markdown characters (`|`, `` ` ``, `#`, `*`, `_`, `[`, `]`, `>`, `\r`, `\n`) for safe inclusion in table cells. It exists identically in two places:
- `crates/diffguard-core/src/render.rs`
- `crates/diffguard/src/main.rs`

## Acceptance Criteria

1. **Single definition** — `escape_md` is defined exactly once in `crates/diffguard-types/src/lib.rs` and is `pub`.

2. **Both consumers import from `diffguard-types`** — Both `diffguard-core/src/render.rs` and `diffguard/src/main.rs` use `use diffguard_types::escape_md;` (or `pub use diffguard_types::escape_md;` if re-exporting through a public module).

3. **No duplicate `escape_md` definitions remain** — The private definitions in `diffguard-core` and `diffguard` are removed.

4. **Build succeeds** — `cargo build -p diffguard-types -p diffguard-core -p diffguard` completes without errors.

5. **Tests pass** — `cargo test -p diffguard-types -p diffguard-core -p diffguard` passes with no new failures.

6. **Snapshot tests unchanged** — Any markdown rendering snapshots in `diffguard-core` and `diffguard` remain byte-identical after the change (confirmed by `cargo insta test` review or `RUST_BACKTRACE=1 cargo test` output comparison).

## Non-Goals

- This does NOT change the markdown escaping logic (characters escaped, order, etc.)
- This does NOT add new tests for `escape_md` specifically (existing snapshot tests cover it)
- This does NOT deduplicate any other functions

## Dependencies

- `diffguard-types` is already a dependency of both `diffguard-core` and `diffguard`
- No new dependencies required
