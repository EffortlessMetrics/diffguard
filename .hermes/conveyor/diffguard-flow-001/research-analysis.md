# Diffguard Repository Research Analysis

**Date:** 2026-04-05
**Repo:** ~/repos/diffguard (https://github.com/EffortlessMetrics/diffguard)
**Version:** 0.2.0 (Unreleased changes on HEAD)

---

## 1. Overall Codebase Health

### Score: 7.5/10 — GOOD, approaching maturity

### Structure

Clean microcrate workspace with 9 crates + xtask automation:

```
diffguard (CLI)          I/O boundary: clap, file I/O, git subprocess
       |
       v
diffguard-core           Engine: run_check(), run_sensor(), render outputs
       |
       +----------------+----------------+
       v                                 v
diffguard-domain                   diffguard-diff
  Business logic                      Diff parsing
       |                                 |
       +----------------+----------------+
                        v
                diffguard-types
                  Pure DTOs

diffguard-analytics      False-positive baselines + trend history
diffguard-lsp            LSP server (diagnostics, code actions)
diffguard-testkit        Shared test utilities (proptest, fixtures)
xtask                    CI, schema generation, conformance tests
```

**Total code:** ~37,316 lines Rust (source), ~10,305 lines (tests)
**Test functions:** ~918 `#[test]` across workspace
**Fuzz targets:** 7 (unified_diff_parser, preprocess, rule_matcher, evaluate_lines, config_parser, regex_pattern, glob_pattern)
**Snapshot tests:** ~40 insta snapshots for output formats

### Maturity Indicators

| Indicator | Status | Notes |
|-----------|--------|-------|
| Clean architecture | Strong | I/O at edges, pure core, strict dep direction |
| Test coverage | Good | Property tests, snapshot tests, fuzz, BDD integration |
| Documentation | Good | Per-crate READMEs + CLAUDE.md, design docs, architecture docs |
| CI | Basic | fmt + clippy + test + conformance, but minimal |
| Changelog | Good | Keep a Changelog format, semver adherence |
| Release readiness | Partial | No publish workflow, no binary releases |

---

## 2. Crate-by-Crate Assessment

### diffguard-types (3,051 lines, 37 tests)
**Health: Excellent.** Pure DTOs with serde + schemars. Frozen vocabulary constants. Schema validation. Property tests for round-trip serialization. Well-tested.

### diffguard-diff (3,799 lines, property tests)
**Health: Excellent.** Pure diff parsing, no I/O. Fuzz target. Handles binary/submodule/rename detection. Robust.

### diffguard-domain (8,759 lines, 324 tests)
**Health: Excellent.** Largest crate by test count. Rule compilation, evaluation, preprocessing, suppression handling, directory overrides. I/O-free. 5 test modules. Comprehensive property tests.

### diffguard-core (4,671 lines, snapshot tests)
**Health: Very Good.** Orchestration engine. 8 output format modules. Sensor API for cockpit integration. Snapshot tests for all formats. 8 `#[cfg(test)]` modules.

### diffguard-analytics (405 lines, 4 tests)
**Health: Fair.** Small crate with minimal test coverage. Only 4 unit tests for baseline/merge/trend logic. Missing property tests for normalization, merge edge cases.

### diffguard (CLI) (10,210 lines, 16 test files)
**Health: Very Good.** Comprehensive CLI with check, rules, explain, validate, init, test, trend subcommands. BDD integration tests. 12 integration test files covering path filters, config loading, directory overrides, suppressions, etc.

### diffguard-lsp (1,788 lines, 10 unit tests, 0 integration tests)
**Health: Fair — NEEDS WORK.** See detailed analysis below.

### diffguard-testkit (2,719 lines, 4 `#[cfg(test)]` modules)
**Health: Good.** Shared proptest strategies, fixtures, diff builder. Supports other crates' tests.

### xtask (~800 lines, 13 tests)
**Health: Good with issues.** CI, schema, conformance, mutants commands. **3 tests are currently FAILING** (see Section 4).

---

## 3. LSP Server Crate — Detailed Analysis

### Current State: Functional but Under-Tested

The LSP crate (`diffguard-lsp`) is a **recently added** component (latest commit). It provides:

- **Server lifecycle:** stdio-based LSP via `lsp-server` crate
- **Document management:** didOpen/didChange/didClose with full sync
- **Diagnostics:** Runs `diffguard-core::run_check()` on document changes
- **Code actions:** "Explain rule" and "Open docs" quick fixes
- **Execute commands:** `diffguard.explainRule`, `diffguard.reloadConfig`, `diffguard.showRuleUrl`
- **Config loading:** Supports includes, env var expansion, directory overrides
- **Git integration:** Falls back to `git diff` when in-memory changes are clean

### Strengths
- Good module separation (config.rs, server.rs, text.rs)
- Config loading reuses logic from CLI (includes, env vars, directory overrides)
- Smart rule explanation with fuzzy matching for typos
- Synthetic diff generation for in-memory changes
- Handles both staged and unstaged git diffs

### Gaps
1. **No integration tests** — Zero files under `tests/`. The 10 unit tests only cover config helpers and code action building.
2. **No protocol-level tests** — No tests for initialize/shutdown lifecycle, diagnostic publishing, notification handling
3. **No test for `text.rs` edge cases** — `byte_offset_at_position` has complex UTF-16 logic but only 2 basic tests
4. **No error path tests** — Server error handling paths untested
5. **No conformance test for LSP output** — Other output formats have snapshot/conformance tests; LSP diagnostics do not

### Dependencies
- `lsp-server = "0.7"` — mature, well-tested
- `lsp-types = "0.97"` — standard LSP types
- Internal: diffguard-core, diffguard-domain, diffguard-types

---

## 4. CI Pipeline Analysis

### Current ci.yml
```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: rustfmt, clippy }
      - run: cargo run -p xtask -- ci
```

The xtask `ci` command runs: `cargo fmt --check` → `cargo clippy` → `cargo test --workspace` → `conform (quick mode)`

### What's Covered
- Formatting (rustfmt)
- Linting (clippy with -D warnings)
- Unit + integration + snapshot tests
- Conformance tests (schema validation, vocabulary, required fields)

### What's Missing

| Gap | Impact | Priority |
|-----|--------|----------|
| No caching (Swatinem/rust-cache) | Slow CI (~5-10min per run) | High |
| No MSRV pin/verification | Breakage on older Rust possible | Medium |
| No cross-platform testing | Windows/macOS untested | Medium |
| No code coverage (tarpaulin/llvm-cov) | Unknown coverage gaps | Medium |
| No cargo-audit / cargo-deny | Supply chain risk | High |
| No release/publish workflow | Manual release process | Medium |
| No binary artifact builds | No downloadable releases | Medium |
| No LSP-specific CI | LSP crate changes untested in CI | Medium |
| No fuzz CI (scheduled) | Fuzz regressions undetected | Low |
| No doc build check | Broken doc links possible | Low |

### Failing Tests (at time of research)
3 xtask tests fail:
1. `run_with_args_dispatches_conform_quick` — conformance reports 12/14 passing (2 conformance sub-tests fail)
2. `run_with_args_dispatches_ci_with_fake_cargo` — env var isolation issue
3. `run_with_args_dispatches_mutants_with_fake_cargo` — env var isolation issue

The conformance failures suggest 2 of the 15 conformance checks have regressions.

---

## 5. Gaps vs Best Practices for Rust CLI with Microcrate Layout

### Missing Best Practices

1. **No `.rustfmt.toml`** — Using default rustfmt config. Custom config ensures consistency.
2. **No `clippy.toml`** — No project-specific clippy configuration.
3. **No `deny.toml` (cargo-deny)** — No license/advisory/duplicate/source checks.
4. **No CHANGELOG entry for LSP** — Latest commit adds LSP but CHANGELOG [Unreleased] doesn't mention it.
5. **No VS Code extension that uses LSP** — The existing `editors/vscode-diffguard` is a basic shell-out stub, not an LSP client.
6. **No `rust-version` enforcement in CI** — MSRV 1.92 declared but not tested.
7. **No pre-built binary releases** — No GitHub Releases workflow.
8. **No integration between VS Code extension and LSP server** — Extension calls `diffguard check --staged` via execFile instead of connecting to the LSP.

### Present Best Practices (well done)
- Workspace-level dependency management
- Per-crate CLAUDE.md for AI context
- Frozen vocabulary constants
- JSON schema generation
- Fuzz testing infrastructure
- Property-based testing with proptest
- Snapshot testing with insta
- Clean dependency direction (no cycles)
- I/O-free core crates

---

## 6. Summary of Findings

### Strengths
- Excellent architecture with clear crate boundaries
- Comprehensive test infrastructure (property, snapshot, fuzz, BDD)
- Well-documented (per-crate READMEs, design docs, CLAUDE.md)
- Multiple output formats with conformance validation
- Active development with clear changelog

### Critical Gaps
1. LSP crate has zero integration tests
2. 3 xtask tests are failing (CI regressions)
3. CI pipeline lacks caching, audit, and MSRV checks
4. diffguard-analytics is undertested (4 tests for 405 lines)

### Opportunities
1. LSP integration tests would significantly improve confidence in the most complex new feature
2. CI caching would cut build times dramatically
3. VS Code extension + LSP integration would complete the IDE story
4. cargo-audit/deny would address supply chain security
