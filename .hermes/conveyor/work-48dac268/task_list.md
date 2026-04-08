# Task List: Enable xtask CI Job and Run Full Workspace Tests

## Issue
#33 - P0: Enable xtask CI job and run full workspace tests

## Context Summary
- Issue #6 (binary path resolution) is FIXED (commit c68890d, April 5, 2026)
- `cargo run -p xtask -- ci` passes locally (fmt + clippy + test + conform)
- `cargo test -p xtask` passes (13 tests)
- `cargo run -p xtask -- conform --quick` passes (14/14)
- CI workflow needs two changes to re-enable xtask coverage

**Note on `--exclude xtask`**: The adversarial challenge correctly identified that removing `--exclude xtask` from `cargo test --workspace` is technically a no-op (xtask is a binary, not a library). However, it is harmless to remove, and the primary goal is enabling the xtask job itself.

---

## Task 1: Enable xtask CI Job
- [ ] **Description**: Modify `.github/workflows/ci.yml` to remove `if: false` condition from the xtask job (line 45), re-enabling the `cargo run -p xtask -- ci` step in CI
- [ ] **Inputs**: `.github/workflows/ci.yml`, verification_comment.md
- [ ] **Outputs**: Modified `.github/workflows/ci.yml` with xtask job enabled
- [ ] **Depends on**: none
- [ ] **Complexity**: small

## Task 2: Remove --exclude xtask from Test Job
- [ ] **Description**: Modify `.github/workflows/ci.yml` to remove `--exclude xtask` from the test job command (line 40). While this is a no-op for binary targets, it aligns with the stated goal and CONTRIBUTING.md policy of running all workspace tests.
- [ ] **Inputs**: `.github/workflows/ci.yml`
- [ ] **Outputs**: Modified `.github/workflows/ci.yml` with `--exclude xtask` removed
- [ ] **Depends on**: none
- [ ] **Complexity**: small

## Task 3: Verify xtask Tests Are Excluded from Regular Test Run
- [ ] **Description**: Since xtask is a binary target, `cargo test --workspace` does not run xtask tests. The xtask tests are only run via `cargo test -p xtask` or `cargo run -p xtask -- ci`. Verify this behavior is understood and document if a separate conform job is needed.
- [ ] **Inputs**: `xtask/Cargo.toml`, `Cargo.toml` (workspace structure)
- [ ] **Outputs**: Confirmation that xtask tests are only run via xtask job
- [ ] **Depends on**: Task 1, Task 2
- [ ] **Complexity**: small

## Task 4: Run Local Verification
- [ ] **Description**: Run `cargo run -p xtask -- ci` locally to verify the full pipeline passes before committing
- [ ] **Inputs**: `xtask/src/main.rs`, `xtask/src/conform_real.rs`
- [ ] **Outputs**: Verified local execution of full xtask CI pipeline
- [ ] **Depends on**: none (can run independently)
- [ ] **Complexity**: medium

## Task 5: Commit Changes
- [ ] **Description**: Create commit with proper message on branch `feat/work-48dac268/p0:-enable-xtask-ci-job-and-run-full-wor`
- [ ] **Inputs**: Modified `.github/workflows/ci.yml`
- [ ] **Outputs**: Git commit on feature branch
- [ ] **Depends on**: Task 1, Task 2, Task 4
- [ ] **Complexity**: small

## Task 6: Verify Concurrent Execution Safety (Post-Merge Consideration)
- [ ] **Description**: Run `cargo test --workspace` while `cargo run -p xtask -- ci` is running to verify no race conditions occur with shared state (OnceLock, Mutex). This is a post-merge verification task.
- [ ] **Inputs**: `xtask/src/conform_real.rs` (ENV_LOCK usage)
- [ ] **Outputs**: Confirmation of safe concurrent execution
- [ ] **Depends on**: Task 5 (post-merge)
- [ ] **Complexity**: medium

---

## Dependency Graph

```
Task 1 ──┬── Task 3 ──► Task 5
Task 2 ──┘               │
         Task 4 ──┬──────┘
                  │
                  └──────► Task 6 (post-merge)
```

---

## Summary

| Task | Description | Complexity |
|------|-------------|------------|
| 1 | Enable xtask job in CI | small |
| 2 | Remove --exclude xtask | small |
| 3 | Verify xtask test isolation | small |
| 4 | Run local verification | medium |
| 5 | Commit changes | small |
| 6 | Verify concurrent safety (post-merge) | medium |