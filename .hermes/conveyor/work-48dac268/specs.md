# SPECS-0033: Enable xtask CI Job and Full Workspace Tests

## Feature/Behavior Description

Enable the disabled xtask CI job in `.github/workflows/ci.yml` and remove the `--exclude xtask` flag from the test job. This restores full workspace test coverage and enables the xtask `ci` command (which runs fmt, clippy, test, and conform checks) to execute in CI on pull requests and pushes to main.

### Background

The xtask CI job was disabled (via `if: false`) and xtask tests were excluded from the test job due to issue #6 ("xtask conformance tests fail — binary path resolution broken"). Issue #6 was resolved on April 5, 2026 (commit c68890d), which fixed the `cargo_bin_path()` function to properly validate the binary path and fall back to the workspace target when needed.

### What This Enables

1. **Full workspace tests in CI**: `cargo test --workspace` runs all tests including xtask
2. **xtask CI pipeline in CI**: `cargo run -p xtask -- ci` runs fmt + clippy + test + conform validation
3. **Conformance testing in CI**: Schema and behavior validation re-enabled

## Acceptance Criteria

- [ ] **AC1**: `.github/workflows/ci.yml` line 40 uses `cargo test --workspace` (no `--exclude xtask`)
- [ ] **AC2**: `.github/workflows/ci.yml` line 45-46 xtask job has no `if: false` condition (job is enabled)
- [ ] **AC3**: `cargo test --workspace` passes locally (all tests including xtask)
- [ ] **AC4**: `cargo run -p xtask -- ci` passes locally (fmt + clippy + test + conform)
- [ ] **AC5**: No regressions in existing CI gate jobs (fmt, clippy, gate-linked, gate-branch)

### Verification Commands

```bash
# Test workspace (including xtask)
cargo test --workspace

# Run full xtask CI pipeline locally
cargo run -p xtask -- ci
```

## Non-Goals

- This spec does **not** include adding path filters to limit when the xtask job runs (can be added post-merge if CI time is problematic)
- This spec does **not** include splitting xtask tests into a separate job to avoid concurrent execution
- This spec does **not** modify the Swatinem/rust-cache configuration or CI runner settings
- This spec does **not** address any other disabled CI jobs or test exclusions

## Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| Issue #6 fix (commit c68890d) | ✅ Complete | Fixed binary path resolution in conform_real.rs |
| xtask conformance tests passing | ✅ Complete | 14/14 pass in quick mode, 13/13 unit tests pass |
| Rust 1.92 toolchain | ✅ Available | From rust-toolchain.toml |
| Swatinem/rust-cache@v2 | ✅ Configured | Already in ci.yml |

## Implementation Notes

### Changes to `.github/workflows/ci.yml`

**Line 40** (test job):
```yaml
# Before
- run: cargo test --workspace --exclude xtask

# After
- run: cargo test --workspace
```

**Lines 45-46** (xtask job):
```yaml
# Before
    if: false  # disabled until #6 is fixed
    steps:

# After
    steps:
```

### Concurrency Consideration

Both the test job and xtask job will execute xtask tests concurrently on different runners. This is acceptable because:
- The `ENV_LOCK` mutex in `xtask/src/conform_real.rs` handles poison recovery
- Tests are deterministic and use proper isolation
- Redundancy provides additional confidence in test results

### Branch Naming

Commits should use branch `feat/33-enable-xtask-ci` or similar following the convention: `<type>/<issue-number>-<slug>`

## Files Modified

- `.github/workflows/ci.yml` — Lines 40 and 45

## Testing Strategy

1. **Pre-merge**: Run `cargo test --workspace` and `cargo run -p xtask -- ci` locally
2. **Post-merge**: CI will run all jobs including the newly enabled xtask job
3. **Monitoring**: Watch first few CI runs for timing and flakiness issues
