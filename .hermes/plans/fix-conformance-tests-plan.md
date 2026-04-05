# Fix Conformance Tests Blocking PR #5

## Goal

Fix the 2 failing conformance tests (Survivability and Tool error code field) in `xtask/src/conform_real.rs` that are blocking PR #5 from merging.

## Current Context

- **Branch**: `feat/v0.2-enhancements-v2` (PR #5)
- **Build**: Passing (cargo clippy clean)
- **Tests**: 3 failures in xtask crate (2 conformance + 1 derived test)
- **CI**: `test` check failing, blocking PR merge

## Root Cause

`test_survivability()` and `test_tool_error_code()` in `xtask/src/conform_real.rs` use `Command::new(cargo_bin_path())` directly. The `cargo_bin_path()` function returns `CARGO_BIN_EXE_diffguard` env var if set, else falls back to `"diffguard"`. Since xtask doesn't depend on the diffguard binary, the env var is never set, and `"diffguard"` is not on PATH, causing the `Command::new()` call to fail.

Other working conformance tests use `run_diffguard()` which properly handles binary discovery via `ensure_diffguard_built()` + `target/debug/diffguard` path.

## Fix

Change `test_survivability()` and `test_tool_error_code()` to use `run_diffguard()` instead of `Command::new(cargo_bin_path())`.

### File: `xtask/src/conform_real.rs`

**test_survivability() (line ~354-370):**
- Replace `Command::new(cargo_bin_path()).args([...]).current_dir(temp_dir.path()).output()` with `run_diffguard(temp_dir.path(), &[...])`

**test_tool_error_code() (line ~764-780):**
- Replace `Command::new(cargo_bin_path()).args([...]).current_dir(temp_dir.path()).output()` with `run_diffguard(temp_dir.path(), &[...])`

## Verification

```bash
# Run the failing conformance tests
cargo run -p xtask -- conform --quick

# Run full test suite
cargo test --workspace

# Run clippy
cargo clippy --workspace -- -D warnings
```

## Impact

- Fixes CI failures on PR #5
- Unblocks PR merge
- No behavior change, only test infrastructure fix
