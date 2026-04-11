# Diffguard Scout Report

**Repository:** `/home/hermes/repos/diffguard`
**Branch:** `feat/work-d1531005/api--compiledrule-exported-from-diffguar`
**Scanned:** 2026-04-11

---

## Status

- **Build:** Passing
- **Tests:** 59 passed, 0 failed, 2 ignored (across all workspace crates)
- **Clippy:** Clean (0 warnings)
- **PR #5 (v0.2 enhancements):** ✅ MERGED
- **Open Issues:** 25 open issues
- **Open PRs:** 6 open (1 DRAFT, 5 OPEN)

---

## Work Found

### Priority 1 — Quick Wins (Low Effort, High Value)

| # | Title | Type | Effort | Rationale |
|---|-------|------|--------|-----------|
| **155** | `bench/Cargo.toml`: Hardcoded version instead of `version.workspace = true` | Workspace | S | Single line fix — no brainer |
| **152** | Intra-workspace deps use bare `version = "0.2"` specifiers | Workspace | S | One pattern repeated ~10 times |
| **153** | External crate versions not centralized in `workspace.dependencies` | Workspace | S | Enables #155 and #152 fix |
| **154** | `diffguard-testkit`: Unused dependency on `diffguard-domain` | Workspace | S | Remove dead dep |

**Status:** A cleanup plan already exists at `.hermes/plans/workspace-dependency-cleanup-plan.md`. These 4 issues are a cluster — fixing one enables the others.

---

### Priority 2 — Security / Input Validation (High Impact)

| # | Title | Type | Effort | Rationale |
|---|-------|------|--------|-----------|
| **115** | User-supplied regex patterns lack complexity/timing attack protection | Security | M | ReDoS / ReDoS timing attacks are a real production threat |
| **114** | Environment variable expansion lacks output sanitization | Security | M | Could allow injection if config is user-controlled |
| **127** | JUnit XML failure text does not escape XML special characters | Bug | S | `escape_xml` already exists — just need to use it |

---

### Priority 3 — Code Quality / DX

| # | Title | Type | Effort | Rationale |
|---|-------|------|--------|-----------|
| **147** | `uninlined_format_args` clippy warning in `main.rs` | DX | S | Simple `#[allow]` or format! fix |
| **132** | `needless_range_loop` clippy warning in `checkstyle.rs` (4 instances) | DX | S | Replace with `.chars()` iteration |
| **124** | `Severity/Scope/FailOn::as_str` missing `#[must_use]` | DX | S | Add attribute to 3 methods |
| **122** | `cmd_check_inner` is 465 lines — should be decomposed | DX | L | Large but well-defined refactor |
| **123** | `cmd_test` is 126 lines — should be decomposed | DX | M | Smaller than #122 |
| **131** | Duplicated `escape_xml` in `checkstyle.rs` and `junit.rs` | DX | S | Already extracted to `xml_utils.rs` — just need to delete old copies |

---

### Priority 4 — Documentation / API

| # | Title | Type | Effort | Rationale |
|---|-------|------|--------|-----------|
| **129** | Core public APIs missing `# Errors` section in doc comments | Doc | M | 4-5 functions still need it |
| **120** | `diffguard-lsp` has no library API documented | Doc | S | Add basic crate-level docs |
| **118** | Bare URLs in doc comments should be hyperlinks | Doc | S | Search and replace |
| **113** | `run_check` and `run_sensor` lack usage examples | Doc | S | Add `cargo doc --document-private-items` examples |

---

### Priority 5 — CI / Testing

| # | Title | Type | Effort | Rationale |
|---|-------|------|--------|-----------|
| **111** | No benchmark regression checks — `bench/` never compared vs baseline | CI | M | Set up periodic bench comparison |
| **110** | No test coverage reporting — `cargo-llvm-cov` not in CI | CI | M | Add to CI pipeline |
| **109** | Mutation testing is manual-only — `cargo-mutants` not in CI | CI | M | Add to CI pipeline |

---

### Priority 6 — Architectural / Design

| # | Title | Type | Effort | Rationale |
|---|-------|------|--------|-----------|
| **121/149** | `CompiledRule` exported from `diffguard-domain` but appears to be internal | API | M | Mark `CompiledRule` as `#[non_exhaustive]` or move to internal module; #149 is the duplicate |
| **128** | `diffguard-types`: `built_in()` is 533 lines — should be data-driven | Refactor | L | Already partially done — built_in.json now used; the remaining refactor is nearly complete |
| **125** | `diffguard-types/src/lib.rs` is 1758 lines — consider splitting | Refactor | L | Module split could proceed incrementally |

---

### Already Addressed (Recent Commits)

| Item | Status |
|------|--------|
| `escape_xml` duplication (#131) | ✅ Extracted to `xml_utils.rs` in `eb9f979` |
| `built_in()` data-driven (#128) | ✅ Refactored in `fcd3768` / `900bfd5` |
| `# Errors` sections (#129) | ✅ Added in `ccb2ff0`, `f1fb07b` |
| `escape_xml` control chars (#127) | ✅ Fixed in `eb9f979` |
| CompiledRule export (#149) | ✅ Removed from public exports in `48d0d2a` |

---

## Plans Created

- `.hermes/plans/workspace-dependency-cleanup-plan.md` — Already existed when scanned. Covers issues #155, #152, #153, #154.

---

## Recommendation

**Immediate action:** The workspace hygiene cluster (issues #155, #152, #153, #154) is the highest-value next item:
- **Effort:** S (small) — purely declarative Cargo.toml changes
- **Impact:** P1 (high priority) — aligns with v0.2.1 patch release hygiene
- **Risk:** None — plan already exists, tests pass, no behavioral changes
- **Plan:** Already written at `.hermes/plans/workspace-dependency-cleanup-plan.md`

After that, the **XML escape bug (#127)** and **clippy quick fixes (#147, #132, #124)** are S-tier quick wins with zero risk.

**Security items (#115, #114)** should be addressed before any v0.3 planning given their severity.

---

## Branch Context

Current branch `feat/work-d1531005/api--compiledrule-exported-from-diffguar` is 13 commits ahead of `origin/main`. Recent commits show:
- CompiledRule API cleanup (ADR + removal from public exports)
- built_in() data-driven refactoring (JSON + include_str!)
- escape_xml extraction to xml_utils module
- # Errors section documentation

The branch is clean and ready for its next logical work item.
