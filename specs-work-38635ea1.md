# Specification: Inline Named Format Arguments in `bail!` Macro Calls

## Feature Description

Convert 5 `bail!` macro invocations in `xtask/src/conform_real.rs` from old-style positional format arguments (`{}` with trailing separate argument) to Rust 2021+ inline named format arguments (`{variable}` with `variable = expr` binding at call site).

## Behavior

This is a pure syntactic transformation with no behavioral change. The `anyhow::bail!` macro accepts named inline format arguments via the same mechanism as `format!()`. The named arguments are forwarded directly to `format_args!()` by the macro.

### Transformations

| Line | Before | After |
|------|--------|-------|
| 368-371 | `bail!("cockpit mode did not exit 0 and no receipt was written: {}", String::from_utf8_lossy(&output.stderr));` | `bail!("cockpit mode did not exit 0 and no receipt was written: {stderr}", stderr = String::from_utf8_lossy(&output.stderr));` |
| 620-623 | `bail!("sensor report failed schema validation:\n{}", error_messages.join("\n"));` | `bail!("sensor report failed schema validation:\n{errors}", errors = error_messages.join("\n"));` |
| 769-772 | `bail!("cockpit mode did not exit 0: {}", String::from_utf8_lossy(&output.stderr));` | `bail!("cockpit mode did not exit 0: {stderr}", stderr = String::from_utf8_lossy(&output.stderr));` |
| 1105-1108 | `bail!("cockpit mode did not exit 0: {}", String::from_utf8_lossy(&output.stderr));` | `bail!("cockpit mode did not exit 0: {stderr}", stderr = String::from_utf8_lossy(&output.stderr));` |
| 1167 | `bail!("expected 7 artifacts, got {}: {:?}", artifacts.len(), paths);` | `bail!("expected 7 artifacts, got {n}: {paths:?}", n = artifacts.len(), paths = paths);` |

## Acceptance Criteria

1. **All 5 `bail!` calls use inline named format arguments**
   - Each `{}` placeholder is replaced with a named `{name}` placeholder
   - Each format argument is bound at the call site as `name = expr`
   - The `anyhow::bail!` named-argument syntax is used correctly

2. **Code compiles without errors**
   - `cargo check -p xtask` passes with no errors
   - No type mismatches between placeholders and bound expressions

3. **Formatting is clean**
   - `cargo fmt -- --check` passes with no violations
   - The four multi-line `bail!` calls are reformatted appropriately

4. **No semantic changes**
   - Expression evaluation order is unchanged
   - Borrowing semantics are unchanged
   - Error messages remain identical

## Non-Goals

- This fix does **not** address `format!()` calls inside `.context()` invocations (lines 528, 549, 1011, 1237, 1238-1240, 1251-1253) — those are out of scope per the issue title
- This fix does **not** apply to other files in the codebase
- This fix does **not** change any `bail!` calls that already use inline format syntax

## Dependencies

- Rust 2024 edition (project already uses this)
- `anyhow = "1.0.101"` (project already uses this)
- `cargo` toolchain with `cargo fmt` available