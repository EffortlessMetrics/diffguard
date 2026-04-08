# Initial Plan: Enable xtask CI Job and Run Full Workspace Tests

## Issue
#33 - P0: Enable xtask CI job and run full workspace tests

## Problem
The xtask CI job is disabled with `if: false` and the test job uses `--exclude xtask`, skipping all xtask tests in CI. The issue #6 blocking problem (binary path resolution) has been resolved in commit c68890d.

## Approach

### Why: Enable Full CI Coverage
Issue #6 was closed on April 5, 2026. The fix for binary path resolution is in place. The xtask conformance tests now pass (14/14 in quick mode). Removing these conditions re-enables CI validation for schema changes and conformance regressions.

### Changes Required

**1. Enable xtask job in CI** (`.github/workflows/ci.yml` line 45)
- Remove `if: false  # disabled until #6 is fixed`
- Because: Issue #6 is fixed, the blocking condition no longer applies

**2. Remove --exclude xtask from test job** (`.github/workflows/ci.yml` line 40)
- Change `cargo test --workspace --exclude xtask` → `cargo test --workspace`
- Because: All workspace tests including xtask should run in CI for complete coverage

### Verification
- `cargo run -p xtask -- ci` - runs full local CI pipeline (fmt + clippy + test + conform)
- `cargo test --workspace` - runs all tests including xtask

## Risks

| Risk | Why Low Severity |
|------|------------------|
| Test timing/flakiness | Verified locally - `cargo run -p xtask -- conform --quick` passes |
| Binary path in CI | Issue #6 specifically fixed this with workspace fallback |
| Concurrent execution | xtask tests use mutex guards and handle poison gracefully |

## Task Breakdown

1. **Modify `.github/workflows/ci.yml`**
   - Line 40: Remove `--exclude xtask`
   - Line 45: Remove `if: false` condition

2. **Verify locally**
   - Run `cargo run -p xtask -- ci`
   - Run `cargo test --workspace`

3. **Commit with proper message**
   - Branch: `feat/work-48dac268/p0:-enable-xtask-ci-job-and-run-full-wor`
   - Message: `feat/33-enable-xtask-ci` or similar