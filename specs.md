# Spec: Inline Format Arguments in main.rs

## Feature/Behavior Description

Fix `clippy::uninlined_format_args` warnings in `crates/diffguard/src/main.rs` by converting uninlined format arguments to inline form. This is a syntactic refactor that changes how format strings are written but produces identical runtime output.

**Before (examples):**
```rust
format!("Rule compilation error: {}", e)
println!("git: PASS ({})", version)
bail!("{}", msg)
format!("  - {}\n", s)
```

**After:**
```rust
format!("Rule compilation error: {e}")
println!("git: PASS ({version})")
bail!("{msg}")
format!("  - {s}\n")
```

## Acceptance Criteria

1. **`cargo clippy -p diffguard --all-targets -- -W clippy::uninlined_format_args` produces zero warnings for `main.rs`**
   - All 20 identified locations are fixed
   - Verification: `grep -c main.rs` on clippy output returns 0 for uninlined warnings

2. **No behavioral changes**
   - Runtime output of all changed format strings is identical before/after
   - The fix compiles without errors (`cargo build -p diffguard` succeeds)
   - Tests pass (`cargo test -p diffguard --lib` succeeds)

3. **Scope discipline maintained**
   - Only `crates/diffguard/src/main.rs` is modified
   - Files outside scope (`diffguard-core/`, `diffguard-types/`, `presets.rs`) are not modified by this work item

4. **Semantic bug at line 2880 is addressed**
   - `bail!("No rules match filter '{filter}'")` now actually displays the filter value (was silently ignored before due to literal `'{}'`)

## Non-Goals

- Does not fix the ~94 `uninlined_format_args` warnings in other crates (separate work items)
- Does not fix the pre-existing compile error in `green_tests_work_d4a75f70.rs:119`
- Does not add `clippy::uninlined_format_args` to the CI lint pipeline (the lint is currently allowed_by_default)

## Dependencies

- Rust toolchain (MSRV: 1.92)
- `cargo clippy` with the `uninlined_format_args` lint available
- No external dependencies required

## Verification Plan

1. Run `cargo clippy -p diffguard --fix --lib -- -W clippy::uninlined_format_args` to auto-fix library target
2. Run `cargo clippy -p diffguard --fix --tests -- -W clippy::uninlined_format_args` to auto-fix test target
3. Run `cargo clippy -p diffguard --all-targets -- -W clippy::uninlined_format_args | grep main.rs | wc -l` — must return 0
4. Run `cargo build -p diffguard` — must compile without errors
5. Run `cargo test -p diffguard --lib` — tests must pass
