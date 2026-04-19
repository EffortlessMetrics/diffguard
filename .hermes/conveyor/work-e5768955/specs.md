# Spec: Change `exit_code` from `i32` to `u8`

## Feature / Behavior Description

Change the type of `exit_code` from `i32` to `u8` throughout the diffguard codebase to make the type invariant (exit codes are 0..=255) compile-time enforced rather than relying on a runtime `clamp` in `main()`.

The change affects the following call chain:
```
main()
  └── run_with_args() -> Result<u8>
        └── cmd_check() -> Result<u8>
              └── cmd_check_inner() -> Result<u8>
                    └── run.exit_code: u8   (was i32)
                          └── ExitCode::from(code)  (no clamp needed)

Other handlers: cmd_validate(), cmd_doctor(), cmd_test() also return Result<u8>
```

## Acceptance Criteria

1. **`cargo build --workspace` succeeds without errors** — All type changes compile cleanly. The `as u8` lossy cast is eliminated from `main()`.

2. **`cargo test --workspace` succeeds** — All unit and integration tests pass. The `#[cfg(not(test))]` guard on `main()` means tests use a separate entry point unaffected by the lossy cast.

3. **`cargo clippy --workspace --all-targets -- -D warnings` passes** — No new clippy warnings introduced by the type changes.

4. **Exit code values unchanged** — The fix is purely type-level. All documented exit codes (0 = Pass, 1 = Tool error, 2 = Policy fail, 3 = Warn-fail) remain unchanged in behavior. Exit code 1 continues to come from the `Err` path in `main()`.

5. **The `clamp` in `main()` is eliminated** — `ExitCode::from(code)` is used directly (line 646), not `code.clamp(...).as_u8()`. The `clamp` is unnecessary since `code` is already `u8`.

## Non-Goals

- This fix does not introduce a newtype enum for exit codes
- This fix does not change the behavior of any exit code value
- This fix does not affect `DiffguardResult.exit_code` in integration tests (OS-level exit code, separate from `CheckRun.exit_code`)
- This fix does not modify `Result<()>` command handlers (`cmd_rules`, `cmd_explain`, `cmd_sarif`, `cmd_junit`, `cmd_csv`, `cmd_init`, `cmd_trend`)

## Scope

### Files to Modify

1. **`crates/diffguard-core/src/check.rs`**:
   - Line 52: `pub exit_code: i32` → `pub exit_code: u8`
   - Line 309: `fn compute_exit_code(...) -> i32` → `-> u8`

2. **`crates/diffguard/src/main.rs`**:
   - Line 1651: `fn compute_baseline_exit_code(...) -> i32` → `-> u8`
   - Lines ~669, 673, 678, 682, 686, 690, 695: `Ok(0)` → `Ok(0u8)` (wrapped `Ok(0)` for `Result<()>` handlers)
   - Line ~951: `Ok(1)` → `Ok(1u8)` in `cmd_validate`
   - Line ~1003: `Ok(1)` → `Ok(1u8)` in `cmd_doctor`
   - Line ~3007: `Ok(1)` → `Ok(1u8)` in `cmd_test`
   - Line 655: `run_with_args()` return type `Result<i32>` → `Result<u8>`
   - Line 2237: `cmd_check_inner()` return type `Result<i32>` → `Result<u8>`
   - Line 1911: `cmd_check()` return type `Result<i32>` → `Result<u8>`
   - Line 863: `cmd_validate()` return type `Result<i32>` → `Result<u8>`
   - Line 956: `cmd_doctor()` return type `Result<i32>` → `Result<u8>`
   - Line 2863: `cmd_test()` return type `Result<i32>` → `Result<u8>`
   - Line 646: Simplify `ExitCode::from(code.clamp(...))` → `ExitCode::from(code)`

### Dependencies
- MSRV: Rust 1.92
- No new dependencies required
- No changes to `diffguard-core` public API beyond the type of an existing field
