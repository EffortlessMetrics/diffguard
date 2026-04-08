# ADR-0033: Enable xtask CI Job and Full Workspace Tests

## Status

**Proposed** — Awaiting implementation and approval.

## Context

The xtask CI job in `.github/workflows/ci.yml` is currently disabled, and the test job explicitly excludes xtask from test execution. This situation arose from issue #6 ("fix: xtask conformance tests fail — binary path resolution broken"), which caused the xtask CI job to be disabled with `if: false` and the test command to use `--exclude xtask`.

Issue #6 was **closed on April 5, 2026** (commit c68890d). The fix:
- Modified `cargo_bin_path()` in `xtask/src/conform_real.rs` (lines 1296-1318) to validate the `CARGO_BIN_EXE_diffguard` env var points to diffguard (not xtask)
- Added fallback to `workspace_root()/target/debug/diffguard`
- Added `ensure_diffguard_built()` call when binary is missing

With issue #6 resolved, the blocking condition no longer applies. The xtask conformance tests now pass:
- `cargo run -p xtask -- conform --quick`: 14/14 tests pass
- `cargo test -p xtask`: 13 tests pass
- `cargo run -p xtask -- ci`: complete pipeline passes

The CONTRIBUTING.md states `cargo test --workspace` for "All tests", and AGENTS.md documents `cargo run -p xtask -- ci` as the "Full CI suite". The current exclusion is a deviation from documented policy.

## Decision

We will enable the xtask CI job and include xtask tests in the workspace test job by making the following changes to `.github/workflows/ci.yml`:

1. **Line 40**: Change `cargo test --workspace --exclude xtask` → `cargo test --workspace`
2. **Line 45**: Remove `if: false  # disabled until #6 is fixed` condition from the xtask job

### Changes Summary

| Location | Before | After |
|----------|--------|-------|
| Line 40 | `cargo test --workspace --exclude xtask` | `cargo test --workspace` |
| Line 45 | `if: false  # disabled until #6 is fixed` | (condition removed) |

## Consequences

### Positive
- Full workspace test coverage restored per CONTRIBUTING.md documentation
- xtask `ci` command (fmt + clippy + test + conform) runs as the "Full CI suite" per AGENTS.md
- Issue #6 engineering investment honored — fix was specifically designed to enable this
- Conformance tests validate diffguard against itself (dogfooding governance)
- Branch protection "Test" status check becomes more comprehensive

### Negative / Tradeoffs
- **CI time increase**: The xtask `ci` job runs fmt, clippy, test, and conform sequentially. In CI with cold caches, this adds time. Mitigation: Swatinem/rust-cache@v2 is already enabled.
- **Concurrent xtask test execution**: Both the test job (running `cargo test --workspace`) and the xtask job (running `cargo run -p xtask -- ci`) will execute xtask tests on different runners. The `ENV_LOCK` mutex with poison recovery mitigates this risk.
- **Potential redundancy**: xtask tests run in both jobs concurrently. This is acceptable for now; optimization can happen post-merge if problematic.

### Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Test timing/flakiness | LOW | Verified locally; tests are deterministic |
| Binary path in CI | LOW | Issue #6 specifically addressed this scenario |
| Concurrent execution | MEDIUM | mutex guards and poison recovery in place; acceptable redundancy |

## Alternatives Considered

### Alternative 1: Keep `--exclude xtask` in test job
- **Tradeoff**: Only run xtask tests in the xtask job, not in the general test job
- **Pros**: Avoids potential concurrent execution issues
- **Cons**: Deviates from documented `cargo test --workspace` policy; xtask tests only run in one job
- **Decision**: Not chosen — the documented policy is `cargo test --workspace`

### Alternative 2: Add path filters to xtask job
- **Tradeoff**: Only run xtask CI job when relevant files change
- **Pros**: Skip expensive xtask CI on doc-only changes
- **Cons**: Additional complexity; may miss transitive dependencies
- **Decision**: Not chosen for initial implementation — can be added post-merge if CI time becomes problematic

### Alternative 3: Split xtask tests into separate job
- **Tradeoff**: Run `--exclude xtask` in test job and run xtask tests separately
- **Pros**: Cleaner separation of concerns
- **Cons**: More CI configuration complexity for marginal benefit
- **Decision**: Not chosen — the redundancy is acceptable given the low risk

## References

- Issue #33: https://github.com/EffortlessMetrics/diffguard/issues/33
- Issue #6 (closed): https://github.com/EffortlessMetrics/diffguard/issues/6
- Fix commit: c68890d (feat/15)
- CONTRIBUTING.md line 57: `cargo test --workspace  # All tests`
- AGENTS.md line 58: `cargo run -p xtask -- ci  # Full CI suite`
