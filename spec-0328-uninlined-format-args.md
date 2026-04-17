# Spec — work-22c2dc77: Inline Format Arguments

## Feature/Behavior Description

Convert all `clippy::uninlined_format_args` violations in `crates/diffguard/src/main.rs` and `crates/diffguard-core/src/` to inline format argument style (`{var}`), matching the existing codebase convention.

**Example transformation:**
```rust
// Before
println!("git: PASS ({})", version);
format!("Rule compilation error: {}", e)
bail!("{}", msg)

// After
println!("git: PASS ({version})");
format!("Rule compilation error: {e}")
bail!(msg)
```

**Edge cases requiring manual handling:**
- `bail!("{}", msg)` → `bail!(msg)` (line 1083) — remove unnecessary format wrapper
- `'{}'` quoted-string patterns at lines 2880 and 3079 — must use named `var = var` form to keep literal quotes

## Acceptance Criteria

1. **`cargo clippy --package diffguard -- -W clippy::uninlined_format_args` emits zero warnings**

2. **`cargo clippy --package diffguard-core -- -W clippy::uninlined_format_args` emits zero warnings**

3. **`bail!("{}", msg)` simplified to `bail!(msg)`** at line 1083 in `cmd_explain()` — `msg` is a `String`, no format wrapper needed

4. **`'{}'` edge cases handled correctly** — lines 2880 (`cmd_rules()`) and 3079 (`cmd_rules()`) preserve the single-quoted literal while inlining the variable reference

5. **All changes in a single PR** targeting the branch `feat/work-22c2dc77/uninlined-format-args`

6. **`cargo test --package diffguard --package diffguard-core` passes** — confirms no behavioral regression

## Non-Goals

- No changes to any other clippy lints or warnings
- No refactoring beyond format argument inlining
- No changes to other crates in the workspace (only `diffguard` and `diffguard-core`)
- No public API changes

## Dependencies

- Rust 1.70+ (edition 2021)
- Clippy 1.92 (to get the `uninlined_format_args` lint)
- No new external dependencies
