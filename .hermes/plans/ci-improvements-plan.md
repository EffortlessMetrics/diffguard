# Plan: CI Pipeline Improvements for diffguard

## Goal

Address CI gaps identified in issues #106-#111, improving the automated quality gates for the v0.2 release cycle.

## Issues

| # | Issue | Priority |
|---|-------|----------|
| #106 | CI: cargo test --workspace only runs on Linux — no macOS or Windows testing | P1 |
| #107 | CI: No cargo-audit — no automated vulnerability scanning | P1 |
| #108 | CI: Fuzz targets exist but are never run in CI | P1 |
| #109 | CI: Mutation testing is manual-only — cargo-mutants not in CI | P1 |
| #110 | CI: No test coverage reporting — cargo-llvm-cov not in CI | P2 |
| #111 | CI: No benchmark regression checks | P2 |

## Current Context

- Repo uses GitHub Actions (`.github/workflows/`)
- `cargo test --workspace` passes cleanly
- Fuzz targets exist in `fuzz/fuzz_targets/`
- `mutants.toml` exists but mutation testing is manual only
- ROADMAP.md phases 1-9 all marked complete

## Proposed Approach

### #108 — Fuzz Targets in CI (High Value, Low Effort)

**Approach:** Add a nightly GitHub Actions job that runs fuzz targets for a limited time (e.g., 30 minutes). This is already a known pattern for `cargo-fuzz`.

```yaml
jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rust-lang/rustup@master
        with:
          components: rustfmt, clippy
      - name: Run fuzz_unified_diff_parser
        run: cargo +nightly fuzz run unified_diff_parser -- hours=4
```

### #109 — Mutation Testing in CI (High Value, Medium Effort)

**Approach:** Add `cargo mutants` to the CI pipeline. Run after tests pass. Use `--allow-empty` for empty test suites.

**Note:** Mutation testing is slow. Consider running on a schedule (nightly) rather than on every PR, or limiting to changed packages via `--package`.

### #107 — cargo-audit (High Value, Low Effort)

**Approach:** Add `cargo audit` GitHub Action step as a required check.

```yaml
- name: Security audit
  uses: rustsec/audit-check@v2
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
```

### #110 — Test Coverage Reporting (Medium Value, Medium Effort)

**Approach:** Add `cargo-llvm-cov` to generate coverage reports. Post as a PR comment. Store trend data in artifact.

### #106 — Multi-platform Testing (Medium Value, High Effort)

**Approach:** Use `cargo-hack` or matrix strategy to run tests on ubuntu-latest, macos-latest, windows-latest. This is more involved — requires matrix CI configuration and may have platform-specific failures in existing code.

### #111 — Benchmark Regression (Lower Priority)

**Approach:** Add `cargo bench` with `git diff` against baseline. Store results in artifact. Run nightly or on-demand.

## Step-by-Step Plan

**Phase 1 (Quick Wins — under 1 hour each):**
1. Add `cargo audit` to existing CI workflow (30 min)
2. Add fuzz targets to nightly CI (1 hour)
3. Add mutation testing to nightly CI (1 hour)

**Phase 2 (Medium Effort):**
4. Add coverage reporting to PR checks (2-3 hours)
5. Add multi-platform testing matrix (half day)

**Phase 3 (Lower Priority):**
6. Add benchmark regression tracking (half day)

## Files Likely to Change

| File | Change |
|------|--------|
| `.github/workflows/ci.yml` | Add cargo-audit, fuzz, mutation jobs |
| `.github/workflows/coverage.yml` | New coverage reporting workflow |
| `mutants.toml` | Verify config is correct for CI |
| `fuzz/fuzz_targets/` | Verify targets compile and run |

## Tests / Validation

1. CI passes on this PR
2. Fuzz target actually runs (not just compiles)
3. Mutation testing finds at least some surviving mutants (confirms it's working)

## Risks and Tradeoffs

- **Mutation testing CI** can be flaky if test suite is incomplete (too many surviving mutants = noisy CI)
- **Multi-platform testing** may reveal platform-specific bugs that are hard to fix
- **Fuzz targets in CI** can be expensive — limit runtime with `hours=N`

## Open Questions

1. Should mutation testing run on every PR (slow) or nightly/weekly?
2. Should fuzz targets run indefinitely or time-limited in CI?
3. Should coverage reporting block merges or just be informational?
