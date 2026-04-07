# Vision Review: Diffguard LSP Integration Test Plan

**Reviewer:** Hermes Maintainer Vision Agent
**Date:** 2026-04-05
**Plan:** initial-plan.md
**Verification:** verification.md
**Plan Review:** plan-review.md

---

## 1. Does this align with the project's stated goals and roadmap?

**YES -- strong alignment.**

The README explicitly lists IDE integration as a first-class feature:
- "LSP diagnostics/code-action server crate: crates/diffguard-lsp"
- "VS Code extension scaffold: editors/vscode-diffguard"

The ROADMAP.md marks Phase 6.7 "LSP server for IDE integration" as complete,
but the crate has zero integration tests. This is a contradiction: the feature
is shipped but unverified at the integration level.

The plan directly addresses this gap by extending the project's existing test
philosophy (property tests, snapshot tests, BDD integration tests, fuzz tests)
to the LSP crate. This is fully consistent with the project's stated
commitment to comprehensive testing (Phase 1 of the roadmap is entirely test
coverage completion, all marked complete).

The plan also correctly identifies that the VS Code extension (currently a stub
that shells out to `diffguard check --staged`) cannot be meaningfully completed
without reliable LSP tests. This is forward-looking and aligns with the
project's integration tooling goals.

**Verdict: ALIGNED**

---

## 2. Is this the right priority given the project's current state?

**YES -- this is the highest-value test investment right now.**

Evidence:
- Every other output format (JSON, Markdown, SARIF, JUnit, CSV, sensor report)
  has snapshot or conformance tests. LSP diagnostics are the one format with
  zero integration-level validation.
- The LSP crate is the newest (~1,800 lines), most complex feature with the
  least test coverage (10 unit tests, 0 integration tests).
- The CHANGELOG Unreleased section shows active work on per-directory overrides
  and scope expansion -- both changes that affect the rule evaluation pipeline
  that the LSP server depends on. Without LSP integration tests, these core
  changes could silently break the LSP diagnostics path.
- The VS Code extension cannot progress beyond its current stub state without
  confidence in the LSP server.

The roadmap shows Phase 1 (test coverage) complete, but this crate was likely
added after Phase 1 closed. Adding integration tests now is a natural
continuation of the project's test-first philosophy.

**Priority assessment: HIGH -- justified.**

---

## 3. Does this fit the project's quality standards (testing patterns, code style)?

**YES -- the plan mirrors established conventions well.**

Alignment with existing patterns:

| Project Convention | Plan Compliance |
|-------------------|-----------------|
| Snapshot tests with insta | Plan includes Phase 6 for `findings_to_diagnostics()` snapshots |
| Integration test structure (tests/ directory with modules) | Plan mirrors `crates/diffguard/tests/integration/` layout |
| `tempfile::TempDir` for workspace setup | Plan explicitly calls this out |
| `diffguard-testkit` fixtures (DiffBuilder, FixtureRepo) | Plan reuses these (though see gap below) |
| Property tests with proptest | Not applicable to LSP integration tests -- correct omission |
| BDD-style integration tests | Plan's phased approach is analogous |

One quality concern: the LSP crate's Cargo.toml is missing
`diffguard-testkit` in `[dev-dependencies]`. The plan assumes testkit fixtures
are available but does not address this dependency gap. The plan-review.md
correctly flags this as a required pre-implementation correction.

The plan's use of `lsp-server::Connection::memory()` is the standard, documented
approach for testing LSP servers. This is the right call -- it avoids subprocess
complexity and matches how `lsp-server` itself is tested.

**Verdict: FITS QUALITY STANDARDS (with one required correction: add testkit dev-dependency)**

---

## 4. Are there any conflicts with ongoing work or planned features?

**NO -- no conflicts identified.**

Analysis of current activity:
- CHANGELOG Unreleased: per-directory overrides, evaluate_lines fuzz target,
  scope expansion (deleted/modified). These are core engine changes that the LSP
  consumes but does not compete with. LSP integration tests would actually
  validate that these changes don't break the LSP diagnostic path.
- No other test infrastructure work is in progress that would overlap.
- The plan does not modify any existing code paths -- it adds new test files only.
- The plan does not introduce new runtime dependencies (only test dev-dependencies).

Potential future synergy: once LSP integration tests exist, they serve as a
regression safety net for ongoing rule system enhancements (Phase 8 items in
roadmap, all marked complete but subject to iteration).

**Verdict: NO CONFLICTS**

---

## 5. Would the maintainer approve this work?

**YES -- with minor required corrections.**

The plan demonstrates:
- Correct understanding of the project's architecture and test philosophy
- Sound technical approach (Connection::memory(), in-process testing)
- Appropriate scope (25-30 tests, not over-engineered)
- Realistic effort estimate (7-11 hours, adjusted to 8-13 by plan-review)
- Clear success criteria

Required corrections before implementation:
1. Add `diffguard-testkit = { path = "../diffguard-testkit" }` to
   `[dev-dependencies]` in `crates/diffguard-lsp/Cargo.toml`
2. Fix phase numbering inconsistency in the effort estimate section
3. Add `test_did_change_configuration_reloads` test case (server handles this
   notification but plan omits it)

Recommended improvements (non-blocking):
1. Design an RAII test helper for server lifecycle (auto-shutdown on drop)
2. Add `byte_offset_at_position` and `utf16_length` unit tests to text.rs
   (separate PR acceptable)
3. Clarify snapshot storage location to match workspace convention

**Verdict: APPROVE WITH MINOR CORRECTIONS**

---

## Summary

| Question | Answer |
|----------|--------|
| Aligned with project goals? | YES -- fills a visible test gap for an advertised feature |
| Right priority? | YES -- highest-impact test investment, blocks downstream work |
| Fits quality standards? | YES -- mirrors existing test patterns and conventions |
| Conflicts with ongoing work? | NO -- complements active development, provides regression safety |
| Would maintainer approve? | YES -- with 3 required pre-implementation corrections |

**Overall Assessment: STRONG APPROVAL**

This is well-scoped, well-reasoned work that directly addresses the most
significant test coverage gap in the project. The approach is technically sound,
the scope is appropriate, and the effort estimate is realistic. The identified
gaps are minor and can be resolved before or during implementation.

**Confidence Level:** HIGH
**Risk Level:** LOW
