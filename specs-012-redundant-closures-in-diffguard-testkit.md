# Specifications: Fix Redundant Closures in diffguard-testkit

**Work Item:** work-ece459be

**Issue:** GitHub #371 — `clippy::redundant_closure_for_method_calls` warnings in `diffguard-testkit`

## Feature Description

Replace redundant closures with method references in `crates/diffguard-testkit/src/arb.rs` to resolve `clippy::redundant_closure_for_method_calls` warnings.

## Scope

**In scope:**
- `crates/diffguard-testkit/src/arb.rs`: Replace `|s| s.to_string()` with `std::string::ToString::to_string` at three locations:
  - `arb_file_extension()` function (line ~214)
  - `arb_dir_name()` function (line ~223)
  - `arb_language()` function (line ~253)

**Out of scope:**
- `crates/diffguard-testkit/src/fixtures.rs` — has no warnings
- `crates/diffguard-lsp` — has separate warnings at `config.rs:96` and `server.rs:819`
- Any other clippy warnings or lints

## Acceptance Criteria

1. **Clippy passes** — Running `cargo clippy -p diffguard-testkit -- -W clippy::redundant_closure_for_method_calls` produces zero warnings.

2. **Tests pass** — Running `cargo test -p diffguard-testkit` completes successfully with no regressions.

3. **Behavior unchanged** — The generated string strategies produce identical output before and after the fix (no behavioral change).

4. **Single commit** — All three replacements are committed in a single commit on branch `feat/work-ece459be/diffguard-testkit-redundant-closures`.

## Non-Goals
- No import changes required (using fully qualified `std::string::ToString::to_string`)
- No test modifications needed (this is a pure style fix)
- No documentation changes required

## Dependencies
- Rust 1.92+ (required for the `redundant_closure_for_method_calls` lint)
- `proptest` crate (the `prop_map` method is from proptest's strategy combinator API)
