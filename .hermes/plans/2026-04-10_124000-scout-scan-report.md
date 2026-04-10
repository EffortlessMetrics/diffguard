# Scout Scan Report — Diffguard

**Scanned:** 2026-04-10 12:40 UTC
**Branch:** feat/work-8d7001a2/verify-parallel-pipeline
**Repository:** EffortlessMetrics/diffguard
**Scout Role:** Scout (scan + prioritize only, no execution)

---

## Status

- **Build:** Passing (`cargo clippy --workspace` clean)
- **Tests:** Passing (900+ tests across workspace, all pass)
- **PR #5:** Merged 2026-04-09 — "feat: v0.2 enhancements — LSP, multi-base diffs, directory overrides, analytics"
- **Open Issues:** 20 issues (#106–#125)

---

## Work Found

### Already Planned (3 Active Plans)

| Plan File | Issues | Status | Priority |
|-----------|--------|--------|----------|
| `security-fixes-plan.md` | #112, #114, #115 | Planned | P1 Security |
| `ci-improvements-plan.md` | #106–#111 | Planned | P1 CI |
| `main-rs-decompose-plan.md` | #122, #123 | Planned | P1 DX |

### New Unplanned Work (Priority Order)

| # | Issue | Type | Justification |
|---|-------|------|---------------|
| **#124** | `Severity/Scope/FailOn::as_str` missing `#[must_use]` | clippy | **Quick Fix** — 3 one-line attribute additions. Trivial effort, high clarity improvement. |
| **#117** | Directory override traverses parent dirs without scope limit | Security | Related to #112 (path traversal). LSP `config.rs` `collect_override_candidates_for_path` walks unbounded up directory tree. Attacker-controlled parent dirs can inject malicious `.diffguard.toml`. |
| **#119** | Git diff base/head refs passed to git without validation | Security | `git_diff()` in main.rs accepts arbitrary refs. Malformed refs could cause resource exhaustion. |
| **#116** | `RuleCompileError` messages don't tell users how to fix problems | DX | Error messages lack fix hints. Users must trial-and-error or read source. |
| **#121** | `CompiledRule` exported from `diffguard-domain` but appears internal | API Design | Exposing internal compilation artifact limits refactoring flexibility. Should either be truly private or documented as stable API. |
| **#113** | `run_check` and `run_sensor` lack usage doc examples | Documentation | Primary programmatic integration points have no doc comments — external contributors must read source. |
| **#120** | `diffguard-lsp` has no library API documented | Documentation | LSP crate is new (PR #5). Missing consumer-facing API docs. |
| **#118** | Bare URLs in doc comments should be hyperlinks | Documentation | Cosmetic doc improvement. |
| **#125** | `diffguard-types/src/lib.rs` is 1758 lines | Refactoring | Large file — consider splitting into focused modules (similar to main.rs decomposition). |

---

## Prioritization Analysis

### Vision Alignment (v0.2 Release)

The v0.2 release (PR #5) is **merged**. These issues are **post-v0.2 hardening**:

1. **Security fixes** (#117, #119) — Critical for production hardening
2. **DX improvements** (#116, #124) — Usability before wider adoption
3. **Documentation** (#113, #118, #120) — Polish for external consumers
4. **API design** (#121) — Architectural cleanup before API stabilizes
5. **Refactoring** (#125) — Technical debt, lower urgency

### Impact vs. Effort

| Issue | Impact | Effort | Ratio |
|-------|--------|--------|-------|
| #124 | Low (clippy warning) | Very Low (3 lines) | **Best** |
| #116 | Medium (user experience) | Medium (error message improvements) | Good |
| #117 | High (security) | Medium (path validation) | Good |
| #119 | Medium (security) | Low (ref validation) | Good |
| #121 | Medium (architecture) | Low (remove re-export or document) | Good |
| #113 | Medium (docs) | Medium (write doc examples) | Medium |
| #120 | Low (docs) | Medium (document LSP API) | Medium |
| #118 | Low (cosmetic) | Low (add hyperlinks) | Medium |
| #125 | Low (refactoring) | High (file split) | Low |

---

## Plans Created

No new plans created — existing plan files adequately cover the highest-priority work:

1. **`security-fixes-plan.md`** — Security issues #112, #114, #115 (and by extension #117, #119 share similar patterns)
2. **`ci-improvements-plan.md`** — CI gaps #106–#111
3. **`main-rs-decompose-plan.md`** — main.rs DX #122, #123

### Recommended New Plan: #124 Quick Fix

**File to create:** `.hermes/plans/clippy-must-use-fix.md`

**Changes needed:**
- `crates/diffguard-types/src/lib.rs` line 52 — add `#[must_use]` to `Severity::as_str()`
- `crates/diffguard-types/src/lib.rs` line 71 — add `#[must_use]` to `Scope::as_str()`
- `crates/diffguard-types/src/lib.rs` line 90 — add `#[must_use]` to `FailOn::as_str()`

---

## Recommendation

**Execute in priority order:**

1. **Immediate (trivial):** Create and execute plan for #124 — `#[must_use]` attributes
2. **Next sprint:** Execute `security-fixes-plan.md` for #112, #114, #115 (includes #117, #119 path/scope validation patterns)
3. **Medium term:** Execute `main-rs-decompose-plan.md` for #122, #123
4. **Parallel:** Address #116 (RuleCompileError messages) — low-risk DX improvement
5. **Backlog:** #113, #118, #120, #121, #125

**No blockers found.** Build passes cleanly, all tests pass, PR #5 merged successfully.

---

*Generated by Scout agent — Hermes cron*
