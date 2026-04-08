# Plan Review: Enable xtask CI Job and Run Full Workspace Tests

## Approach Assessment

**Feasible: YES**

The proposed approach is straightforward and low-risk:

1. Remove `if: false` from xtask job (line 45 of ci.yml)
2. Remove `--exclude xtask` from test job (line 40 of ci.yml)

These are targeted, minimal changes to re-enable disabled CI coverage. Issue #6 is confirmed closed (commit c68890d, April 5, 2026), and the binary path resolution fix is in place in `xtask/src/conform_real.rs` (lines 1296-1318).

---

## Risk Analysis

### Risk 1: xtask `cargo run -p xtask -- ci` Timing Out in CI
- **Severity**: MEDIUM
- **Description**: The xtask ci command runs fmt + clippy + test + conform in sequence. In CI environments with cold caches, this could exceed typical job timeouts or consume significant CI minutes.
- **Mitigation**: The research showed it completes locally. CI caching (Swatinem/rust-cache@v2) is already enabled. Consider monitoring first few runs.
- **Residual**: Low - conformance tests are fast (~14 tests in quick mode)

### Risk 2: Binary Path Resolution Still Broken in CI (Poisoned Env)
- **Severity**: LOW
- **Description**: The fix in `cargo_bin_path()` checks `CARGO_BIN_EXE_diffguard` and falls back to workspace target/debug. However, CI might have different environment configurations or the xtask binary might be built before diffguard, causing the fallback to fail.
- **Mitigation**: `ensure_diffguard_built()` is called in the fallback path. The xtask ci command builds the full workspace first.
- **Residual**: Low - issue #6 specifically addressed this scenario

### Risk 3: xtask Tests Are Not Thread-safe in Concurrent CI
- **Severity**: LOW
- **Description**: If the xtask job and test job run concurrently on the same runner, both might try to build/modify the diffguard binary simultaneously, causing race conditions or test flakiness.
- **Mitigation**: Jobs run on separate runners (ubuntu-latest for each). The xtask job uses `cargo run -p xtask` which handles its own build. However, note that the test job now also runs `cargo test --workspace` (without exclude), so both jobs will run xtask tests concurrently on different runners.
- **Residual**: Medium - this is the most legitimate concern. See edge cases below.

---

## Edge Cases Identified

### Edge Case 1: Concurrent xtask Test Execution Across Jobs
The test job (line 40) now runs `cargo test --workspace` which includes xtask. The xtask job (line 50) runs `cargo run -p xtask -- ci` which also runs xtask tests. These can execute concurrently on different runners.

**Impact**: If xtask tests use shared state (they do - there's a `std::sync::OnceLock` for process handling), concurrent execution could cause:
- Lock contention or poisoning
- Binary rebuild races
- Test output interleaving

**Recommendation**: Add a mutex or serialize xtask test execution. The `cargo_bin_path()` function has `OnceLock` but that's for the binary path cache, not test execution. Examine `xtask/src/conform_real.rs` for shared state.

### Edge Case 2: CI Environment Missing `CARGO_BIN_EXE_diffguard`
If this env var is unset or points to xtask in CI, the function falls back to `target/debug/diffguard`. If the workspace hasn't been built yet, this could fail.

**Impact**: The `ensure_diffguard_built()` call should handle this, but it assumes `cargo build` will work from any directory.

### Edge Case 3: Windows CI Runner Differences
The binary path resolution (lines 1311-1315) uses `cfg!(windows)` to append `.exe`. CI uses `ubuntu-latest`, so this is fine, but if Windows runners are added later, the conditional logic must be verified.

---

## Recommendations

### Must Fix Before Proceeding

1. **Verify xtask tests don't have shared state conflicts**: Run `cargo test -p xtask` twice in quick succession to check for race conditions. Check `conform_real.rs` for any `OnceLock` or `Mutex` usage that could poison.

2. **Add concurrency test**: Run `cargo test --workspace` while `cargo run -p xtask -- ci` is running to verify no binary locking issues occur.

### Should Consider

3. **Split test job into two phases**: Consider running `cargo test --workspace --exclude xtask` in one job and `cargo test -p xtask` in the xtask job to avoid any doubt about concurrency, even though the current approach is technically fine.

4. **Add xtask job to CI only on PRs touching certain paths**: Add a path filter to only run the expensive xtask ci job when relevant files change (e.g., `crates/**`, `xtask/**`, `.github/workflows/ci.yml`).

---

## Verification Checklist

- [x] Issue #6 is closed and fix commit exists (c68890d)
- [x] Binary path resolution is hardened in conform_real.rs
- [x] Local `cargo run -p xtask -- ci` passes (from research)
- [x] `cargo test -p xtask` passes (from research)
- [ ] Concurrent execution verified (not done - should be)
- [ ] CI behavior verified after PR merge (pending)

---

## Summary

The approach is **feasible and low-risk** given the issue #6 fix. The main concern is the **concurrency of xtask test execution** between the test job and xtask job. Recommend verifying no shared state conflicts before merging.

The plan is sound. Proceed with the changes, but add a concurrency sanity check to the verification steps.