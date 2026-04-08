# Research Analysis: Enable xtask CI Job and Run Full Workspace Tests

## Issue Summary
- **Issue**: #33 - P0: Enable xtask CI job and run full workspace tests
- **URL**: https://github.com/EffortlessMetrics/diffguard/issues/33
- **State**: Open, unassigned

## Problem Description
The xtask CI job in `.github/workflows/ci.yml` is disabled with `if: false` and the comment "disabled until #6 is fixed". The test job also uses `--exclude xtask`, completely skipping xtask tests in CI.

## Root Cause Investigation

### Issue #6 Status
- **#6**: "fix: xtask conformance tests fail — binary path resolution broken"
- **State**: CLOSED (completed) on April 5, 2026
- **Fix Commit**: c68890d (feat/15)
- **Summary**: Fixed `cargo_bin_path()` to check env var actually points to diffguard (not xtask), fall back to workspace target/debug, auto-build if missing.

### Code Evidence
1. **`xtask/src/conform_real.rs`** - `cargo_bin_path()` function (lines 1296-1318):
   - Checks `CARGO_BIN_EXE_diffguard` env var and validates it points to diffguard (not xtask)
   - Falls back to `workspace_root()/target/debug/diffguard`
   - Calls `ensure_diffguard_built()` if binary is missing

2. **CI Workflow** (`.github/workflows/ci.yml`):
   - Line 40: `cargo test --workspace --exclude xtask` - skips xtask tests
   - Line 45: `if: false  # disabled until #6 is fixed` - xtask job disabled

3. **Local Verification** (run during this research):
   - `cargo run -p xtask -- conform --quick`: 14/14 tests pass
   - `cargo test -p xtask`: 13 tests pass
   - `cargo test --workspace --exclude xtask`: passes

## Relevant Codebase Areas

### Workspace Structure
- Cargo workspace with 9 crates + xtask + bench
- Workspace members: `crates/diffguard-analytics`, `crates/diffguard`, `crates/diffguard-core`, `crates/diffguard-diff`, `crates/diffguard-domain`, `crates/diffguard-lsp`, `crates/diffguard-testkit`, `crates/diffguard-types`, `bench`, `xtask`

### Key Files
- `.github/workflows/ci.yml` - CI workflow (91 lines)
- `xtask/src/main.rs` - xtask entry point, defines `ci` command
- `xtask/src/conform.rs` - thin wrapper for conform_real.rs
- `xtask/src/conform_real.rs` - conformance test implementation (1511 lines)

### xtask Commands
- `xtask ci` - runs fmt --check, clippy --workspace, test --workspace, conform --quick
- `xtask conform [--quick]` - runs 15 conformance tests (14 in quick mode)
- `xtask schema [--out-dir]` - generates JSON schemas
- `xtask mutants [-p package]` - runs cargo-mutants

## Dependencies/Constraints

1. **Rust Version**: 1.92 (from rust-toolchain.toml)
2. **Edition**: 2024 (workspace-wide)
3. **No external CI services** - uses GitHub Actions only
4. **xtask is not published** - `publish = false` in xtask/Cargo.toml

## Key Findings

1. **Issue #6 is FIXED** - The original blocking issue was resolved in commit c68890d (April 5, 2026)
2. **xtask CI can now run locally** - `cargo run -p xtask -- ci` completes successfully
3. **Conformance tests are working** - 14/14 pass in quick mode, all 15 in full mode
4. **Two changes needed in CI workflow**:
   - Remove `if: false` from xtask job (line 45)
   - Remove `--exclude xtask` from test job (line 40)
5. **No structural blockers remain** - issue #6 fix is complete and tested

## Acceptance Criteria (from issue)
- [ ] cargo run -p xtask -- ci passes locally ✓ (verified during research)
- [ ] xtask job runs in CI on PR and push (change needed)
- [ ] All test suites (including xtask) run in CI (change needed)