# Scout Scan Report — Diffguard

**Scanned:** 2026-04-10 13:15 UTC
**Branch:** feat/work-8d7001a2/verify-parallel-pipeline
**Repository:** EffortlessMetrics/diffguard
**Scout Role:** Scout (scan + prioritize, no execution)

---

## Status

- **Build:** Passing (`cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo fmt --check` clean)
- **Tests:** All passing (473 unit/integration + 38 doc = 511+ tests, all crates pass)
- **Open PRs:** PR #5 merged (v0.2.0 — "feat: v0.2 enhancements")
- **Open Issues:** Unknown (gh curl blocked by security policy, will retrieve via scheduled scan)

### Branch Status
- 4 commits ahead of `origin/main`: `9f75131` through `b817023` (docs: claim_item retry, ADR per-item state isolation, Error::source() regression tests)
- Working tree: clean (no modified files, only untracked plan files)

---

## Work Found

### P1 — Already Planned (Covered by Existing Plans)

| Plan File | Covers | Priority |
|-----------|--------|----------|
| `security-fixes-plan.md` | #112, #114, #115 (and related #117 path traversal, #119 ref validation) | P1 Security |
| `ci-improvements-plan.md` | #106–#111 | P1 CI |
| `main-rs-decompose-plan.md` | #122, #123 | P1 DX |

### P2 — New Trivial Quick Fix (New Today)

| # | Issue | Type | Justification |
|---|-------|------|---------------|
| **#124** | `Severity::as_str`, `Scope::as_str`, `FailOn::as_str` missing `#[must_use]` | Clippy | 3 one-line attribute additions. Trivial effort, eliminates `must_use` clippy warnings. |

### P3 — Post-Scan Findings (From Code Review)

| # | Issue | Type | Justification |
|---|-------|------|---------------|
| **#117** | Directory override traverses parent dirs without scope limit | Security | `collect_override_candidates_for_path` in LSP `config.rs` walks unbounded up directory tree. Malicious `.diffguard.toml` in parent dirs could inject policy. |
| **#119** | Git diff base/head refs passed to git without validation | Security | `git_diff()` accepts arbitrary refs — malformed refs or very long commit chains could cause resource exhaustion. |
| **#116** | `RuleCompileError` messages lack fix hints | DX | Users cannot determine how to resolve compile errors without trial-and-error or reading source. |
| **#121** | `CompiledRule` exported from `diffguard-domain` but appears internal | API Design | Limits future refactoring flexibility. Should either document as stable public API or remove export. |
| **#113** | `run_check` and `run_sensor` lack usage doc examples | Documentation | Primary programmatic integration points have no doc comments. |
| **#120** | `diffguard-lsp` has no library API docs | Documentation | New crate (PR #5) needs consumer-facing documentation. |
| **#118** | Bare URLs in doc comments should be hyperlinks | Documentation | Cosmetic — adds `[text](url)` formatting to doc comments. |
| **#125** | `diffguard-types/src/lib.rs` is 1758 lines | Refactoring | Large single file — consider splitting into focused sub-modules. |

---

## Prioritization Analysis

### Vision Alignment (Post-v0.2 Hardening)

The v0.2.0 release (PR #5) is **merged**. Post-v0.2 hardening priorities:

1. **Security** (#117, #119) — Critical before production adoption
2. **DX** (#116, #124) — Usability before wider community adoption
3. **Documentation** (#113, #118, #120) — Polish for external consumers
4. **API Design** (#121) — Architectural cleanup before API stabilizes
5. **Refactoring** (#125) — Technical debt, lower urgency

### Impact vs. Effort

| Issue | Impact | Effort | Ratio |
|-------|--------|--------|-------|
| #124 | Low (clippy warning) | Very Low (3 attrs) | **Best** — do immediately |
| #119 | Medium (security) | Low (ref validation) | Good |
| #117 | High (security) | Medium (path bounds) | Good |
| #116 | Medium (user experience) | Medium (error messages) | Good |
| #121 | Medium (architecture) | Low (document or remove) | Good |
| #113 | Medium (docs) | Medium (write examples) | Medium |
| #120 | Low (docs) | Medium (LSP API docs) | Medium |
| #118 | Low (cosmetic) | Low (hyperlink formatting) | Medium |
| #125 | Low (refactoring) | High (file split) | Low |

---

## Plans Already Existing

| Plan File | Created | Status |
|-----------|---------|--------|
| `security-fixes-plan.md` | 2026-04-10 11:05 | Active |
| `ci-improvements-plan.md` | 2026-04-10 11:05 | Active |
| `main-rs-decompose-plan.md` | 2026-04-10 11:05 | Active |
| `clippy-must-use-fix.md` | 2026-04-10 13:05 | Active (created by previous scout) |
| `regex-redos-protection.md` | 2026-04-10 13:05 | Active |

**Note:** `2026-04-10_130000-clippy-must-use-fix.md` already exists covering issue #124 — no need to recreate.

---

## Recommendation

**Execute in priority order:**

1. **Immediate (trivial):** Verify + execute existing `clippy-must-use-fix.md` for #124 — 3 `#[must_use]` attrs
2. **Next sprint:** Execute `security-fixes-plan.md` for #112, #114, #115 (includes #117, #119 path/ref validation)
3. **Medium term:** Execute `main-rs-decompose-plan.md` for #122, #123
4. **Parallel:** Address #116 (RuleCompileError messages) — low-risk DX improvement
5. **Backlog:** #113, #118, #120, #121, #125

**No blockers found.** Build passes cleanly, all tests pass, fmt/clippy clean.

---

*Generated by Scout agent — Hermes cron*
