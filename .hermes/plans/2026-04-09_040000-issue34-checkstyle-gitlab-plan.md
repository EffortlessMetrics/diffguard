# Plan: Issue #34 — Verify & Close (Checkstyle + GitLab Code Quality)

## Goal

Verify that issue #34 (P1: Add GitLab MR integration and Checkstyle XML output) is fully implemented, close it, and add the missing Checkstyle snapshot tests.

## Current Context

- Issue #34 is **open** but the work it describes is **already implemented** in the codebase
- Both `crates/diffguard-core/src/checkstyle.rs` (306 lines) and `crates/diffguard-core/src/gitlab_quality.rs` (303 lines) exist and are wired into `main.rs`
- `--gitlab-quality <path>` and `--checkstyle <path>` CLI flags are implemented in `main.rs`
- GitLab has unit tests + snapshot tests (3 snapshot files)
- Checkstyle has unit tests (10 tests) but **no snapshot tests**
- The CHANGELOG.md `[Unreleased]` section documents both as added
- All workspace tests pass, clippy clean

## Acceptance Criteria from Issue #34

| Criterion | Status |
|-----------|--------|
| `diffguard check --checkstyle <file>` produces valid XML conforming to Checkstyle DTD | ✅ Implemented |
| `diffguard check --gitlab-quality <file>` produces valid GitLab Code Quality JSON | ✅ Implemented |
| Snapshot tests for both formats | ⚠️ GitLab: ✅, Checkstyle: ❌ missing |
| Severity mapping correct (error/warn/info) | ✅ Both have correct mapping |

## Proposed Approach

### Step 1: Verify Checkstyle Implementation
- Review `crates/diffguard-core/src/checkstyle.rs` for correctness
- Verify XML escaping, severity mapping, structure
- Run: `cargo test -p diffguard-core checkstyle`

### Step 2: Add Checkstyle Snapshot Tests
- Add `#[insta::test]` snapshot tests in `checkstyle.rs` analogous to `gitlab_quality.rs`
- Run: `cargo insta test -p diffguard-core --review` to generate snapshots
- Commit snapshots to `crates/diffguard-core/tests/snapshots/`

### Step 3: Verify GitLab Quality Implementation
- Review `crates/diffguard-core/src/gitlab_quality.rs`
- Verify severity mapping: Error→major, Warn→minor, Info→info (per GitLab schema)
- Verify SHA256 fingerprints are stable
- Run: `cargo test -p diffguard-core gitlab_quality`

### Step 4: End-to-End Smoke Test
- `cargo run -- check --checkstyle /tmp/checkstyle-test.xml --gitlab-quality /tmp/gitlab-test.json`
- Verify both files are valid XML/JSON

### Step 5: Close Issue #34
- Post comment: verification results
- Close issue as completed

### Step 6: Apply Stashed Test Fix (Optional)
- The stash `feat/v0.2-enhancements-v2` has an `ENV_LOCK` race condition fix for `cargo_bin_path_prefers_env_var` in xtask
- Consider applying if xtask tests are flaky

## Files Likely to Change

- `crates/diffguard-core/src/checkstyle.rs` — add snapshot tests
- `crates/diffguard-core/tests/snapshots/` — new Checkstyle snapshot files

## Tests / Validation

```bash
# Run Checkstyle tests
cargo test -p diffguard-core checkstyle

# Run GitLab tests
cargo test -p diffguard-core gitlab_quality

# Generate and review Checkstyle snapshots
cargo insta test -p diffguard-core --review

# End-to-end smoke test
cargo run -- check --checkstyle /tmp/checkstyle-test.xml --gitlab-quality /tmp/gitlab-test.json
```

## Risks / Tradeoffs

- **Low risk**: Both features already implemented and tested via unit tests
- Checkstyle snapshot tests are a nice-to-have for regression prevention, not blocking
- Issue #34 should be closed regardless since core feature is delivered

## Open Questions

- Should the xtask `ENV_LOCK` race fix be applied as a separate PR?
- Are the conveyor work directories (`work-09e5782b`, `work-3b090538`) relevant to any ongoing work?
