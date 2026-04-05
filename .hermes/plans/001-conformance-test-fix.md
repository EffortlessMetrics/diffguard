# Plan: Fix xtask Test Failures

**Created:** 2026-04-04
**Updated:** 2026-04-04
**Priority:** P0 (blocking CI / PR #5)
**Status:** ready-for-execution

## Problem

3 tests in `xtask` fail, blocking CI and PR #5 merge:```
tests::run_with_args_dispatches_ci_with_fake_cargo - FAIL
tests::run_with_args_dispatches_conform_quick - FAIL
tests::run_with_args_dispatches_mutants_with_fake_cargo - FAIL
```

## Root Cause Analysis

### Issue 1: Missing Binary for Conformance Tests

`run_with_args_dispatches_conform_quick` calls `conform::run_conformance(true)` which runs conformance tests. Tests 3 (Survivability) and 9 (Tool error code) need the `diffguard` binary, but:

- `CARGO_BIN_EXE_diffguard` is set by `cargo test` to point to the xtask binary, not diffguard
- `cargo_bin_path()` returns wrong path
- `run_diffguard()` fails to find the binary

### Issue 2: Mutex Poisoning Cascade

When `run_with_args_dispatches_conform_quick` panics, subsequent tests that use `ENV_LOCK.lock().unwrap()` fail with `PoisonError`.

The panic happens in `main.rs::tests` but doesn't use `ENV_LOCK`. However, the panic still affects test state.

### Issue 3: `cargo_bin_path()` Resolution

In `conform_real.rs`, `cargo_bin_path()` prefers `CARGO_BIN_EXE_diffguard` env var, but when running `cargo test -p xtask`, this points to the xtask test binary, not diffguard.

## Solution

### Task 1: Fix Binary Path Resolution

**File:** `xtask/src/conform_real.rs`
**Lines:** 1296-1330

Modify `cargo_bin_path()` to:
1. Check for `CARGO_BIN_EXE_diffguard` env var first
2. Fall back to workspace-relative `target/debug/diffguard` path
3. Build binary if missing

```rust
fn cargo_bin_path() -> String {
    // Prefer env var if set and valid (points to actual diffguard binary)
    if let Ok(bin) = std::env::var("CARGO_BIN_EXE_diffguard") {
        // Verify it's the diffguard binary, not xtask
        if bin.contains("diffguard") && !bin.contains("xtask") {
            return bin;
        }
    }
    // Fall back to workspace-relative path
    workspace_root()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "diffguard.exe" } else { "diffguard" })
        .to_str()
        .unwrap()
        .to_string()
}
```

### Task 2: Add Build Step in `run_conformance`

**File:** `xtask/src/conform_real.rs`

At the start of `run_conformance()`, call `ensure_diffguard_built()`:

```rust
pub fn run_conformance(quick: bool) -> Result<()> {
    ensure_diffguard_built()?; // Add this line
    // ... rest of function
}
```

### Task 3: Implement `ensure_diffguard_built`

```rust
fn ensure_diffguard_built() -> Result<()> {
    let binary = cargo_bin_path();
    if !std::path::Path::new(&binary).exists() {
        eprintln!("Building diffguard binary for conformance tests...");
        let status = Command::new("cargo")
            .args(["build", "--bin", "diffguard"])
            .current_dir(workspace_root())
            .status()
            .context("cargo build --bin diffguard")?;
        if !status.success() {
            bail!("Failed to build diffguard binary");
        }
    }
    Ok(())
}
```

### Task 4: Handle Poisoned Mutex

**Files:** `xtask/src/main.rs`, `xtask/src/conform_real.rs`

Replace `.unwrap()` with recovery pattern:

```rust
// Before:
let _guard = ENV_LOCK.lock().unwrap();

// After:
let _guard = ENV_LOCK.lock().unwrap_or_else(|e| {
    // Clear poison and continue
    e.into_inner()
});
```

This allows tests to continue even if a previous test panicked while holding the lock.

### Task 5: Fix Test Isolation

**File:** `xtask/src/main.rs`

The test `run_with_args_dispatches_conform_quick` should not panic when conformance fails. It should return a result or handle the error gracefully:

```rust
#[test]
fn run_with_args_dispatches_conform_quick() {
    // Build first
    let binary = workspace_root()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "diffguard.exe" } else { "diffguard" });
    if !binary.exists() {
        let status = Command::new("cargo")
            .args(["build", "--bin", "diffguard"])
            .status()
            .expect("cargo build");
        assert!(status.success(), "Failed to build diffguard");
    }
    
    run_with_args(["xtask", "conform", "--quick"]).expect("run conform");
}
```

## Verification Steps

1. Run `cargo build --bin diffguard`
2. Run `cargo test -p xtask -- --test-threads=1`
3. Run `cargo run -p xtask -- conform`
4. Run `cargo run -p xtask -- ci`

## Success Criteria

- [ ] All 13 xtask tests pass
- [ ] All 15 conformance tests pass
- [ ] `cargo run -p xtask -- ci` passes
- [ ] No changes to actual diffguard logic (only test harness)

## Notes

- This is blocking PR #5
- The fix is isolated to xtask test infrastructure
- No production code changes needed