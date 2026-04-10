# Plan: Scout Scan Report — 2026-04-10 Afternoon

## Goal
Execute SCAN + PRIORITIZE phases for diffguard repository on `feat/v0.2-enhancements-v2` branch.

## Context
- PR #5 (v0.2) **MERGED** — all phases 1-9 of ROADMAP.md marked complete
- Build: **PASSING** (cargo clippy clean)
- Tests: **ALL PASSING** (43 test suites, ~1000+ tests total)
- 20 open issues since PR #5 merged
- Existing plan files: `security-fixes-plan.md`, `junit-xml-escaping-plan.md`, `main-rs-decompose-plan.md`, `ci-improvements-plan.md`

## SCAN Results

### Build & Tests
- `cargo clippy --all-targets --all-features` — **CLEAN** (0 warnings)
- `cargo test --workspace` — **ALL PASSING** (43 test suites)
- No TODOs/FIXMEs in code (search returned only intentional TODO-pattern test fixtures)

### Open Issues (20 total, most recent first)
| # | Title | Priority |
|---|-------|----------|
| 129 | core public APIs missing # Errors section in doc comments | Medium |
| 128 | diffguard-types: built_in() is 533 lines — should be data-driven | Medium |
| 127 | JUnit XML failure text content does not escape XML special characters | **High** |
| 125 | diffguard-types/src/lib.rs is 1758 lines — consider splitting | Medium |
| 124 | clippy: Severity/Scope/FailOn::as_str methods missing #[must_use] | Low |
| 123 | dx: main.rs cmd_test is 126 lines — should be decomposed | Medium |
| 122 | dx: main.rs cmd_check_inner is 465 lines — should be decomposed | Medium |
| 121 | api: CompiledRule exported from diffguard-domain but appears to be internal | Low |
| 120 | doc: diffguard-lsp has no library API documented | Medium |
| 119 | Git diff base/head ref arguments are passed to git without validation | Medium |
| 117 | Directory override loading traverses parent directories without scope limit | Medium |
| 116 | dx: RuleCompileError messages don't tell users how to fix problems | Medium |
| 115 | **User-supplied regex patterns lack complexity/timing attack protection** | **High** |
| 114 | **Environment variable expansion in config files lacks output sanitization** | **High** |
| 113 | doc: run_check and run_sensor lack usage examples | Low |
| 112 | **Config path traversal: relative override paths with .. components are not validated** | **High** |
| 111 | CI: No benchmark regression checks | Medium |
| 110 | CI: No test coverage reporting | Medium |
| 109 | CI: Mutation testing is manual-only | Medium |

### Open PRs
- **#68** — `docs(adr): Use Display format for CLI error output (work-cac2f34f)` — DRAFT

## PRIORITIZATION

### Tier 1 — Security (Act Now)
1. **#127** JUnit XML escaping — XML well-formedness bug, clear fix in `diffguard-core/src/junit.rs`
2. **#115** Regex ReDoS protection — Timing attack vector on user-supplied patterns
3. **#114** Env var injection sanitization — Command/path injection risk
4. **#112** Path traversal in override paths — Directory escape vulnerability

### Tier 2 — Code Health (Important)
5. **#124** `#[must_use]` on `as_str` methods — Quick fix, prevents clippy warnings
6. **#122** `cmd_check_inner` 465 lines — Decompose to smaller functions
7. **#123** `cmd_test` 126 lines — Decompose to smaller functions
8. **#125** `lib.rs` 1758 lines — Module split needed

### Tier 3 — DX Improvements (Nice to have)
9. **#119** Git ref validation — Validate refs before passing to git
10. **#117** Override directory scope limit — Limit parent traversal
11. **#110/#109/#111** CI improvements — Coverage, mutation testing, benchmarks

### Tier 4 — Documentation (Lower urgency)
12. **#129** `# Errors` section in doc comments
13. **#128** `built_in()` 533 lines → data-driven
14. **#120** LSP library API docs
15. **#113** Usage examples for `run_check`/`run_sensor`

## Recommendation

**Execute in this order:**
1. **#127 JUnit XML escaping** — Self-contained fix, clear scope, existing plan
2. **Security batch** (#115, #114, #112) — Use `security-fixes-plan.md`, all have clear fixes
3. **#124 `#[must_use]` fix** — Trivial patch
4. **CI improvements** (#110, #109, #111) — Can run independently

## Notes
- No new work items found from code scanning (all phases complete)
- Existing plan files already cover the highest-priority work
- No blockers to proceeding immediately on #127
