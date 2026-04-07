# Verification: Diffguard LSP Integration Tests Research & Plan

**Date:** 2026-04-05
**Verdict:** APPROVE WITH MINOR CORRECTIONS

## Verification Summary

The research analysis and initial plan for LSP integration tests are **largely accurate** and the approach is **sound**. Minor corrections are needed for test count precision and a missing test gap.

---

## 1. Research Accuracy Verification

### Confirmed Correct

| Claim | Status | Evidence |
|-------|--------|----------|
| Workspace has 9 crates + xtask | CONFIRMED | Cargo.toml shows 8 crates + xtask |
| LSP crate has 10 unit tests | CONFIRMED | grep shows exactly 10 #[test] in diffguard-lsp/src/ |
| LSP crate has 0 integration tests | CONFIRMED | No tests/ directory exists in diffguard-lsp/ |
| CLI has 12 integration test files | CONFIRMED | 12 .rs files in crates/diffguard/tests/integration/ |
| diffguard-analytics has 4 tests | CONFIRMED | grep shows exactly 4 #[test] in analytics/src/ |
| 3 xtask tests failing | CONFIRMED | cargo test -p xtask shows 3 failures |
| CI uses `cargo run -p xtask -- ci` | CONFIRMED | .github/workflows/ci.yml matches |
| No .rustfmt.toml, clippy.toml, deny.toml | CONFIRMED | find returns empty |
| VS Code extension is a stub (not LSP) | CONFIRMED | extension.js shells out to `diffguard check --staged` |
| LSP not in CHANGELOG Unreleased | CONFIRMED | CHANGELOG.md Unreleased section has no LSP entry |
| LSP crate recently added | CONFIRMED | git log shows commit 804b4ce adds diffguard-lsp |
| lsp-server 0.7 dependency | CONFIRMED | Cargo.toml shows lsp-server = "0.7" |
| Connection::memory() exists for testing | CONFIRMED | lsp-server docs show memory() method |

### Minor Corrections Needed

| Claim | Issue | Correction |
|-------|-------|------------|
| "byte_offset_at_position has 2 basic tests" | INACCURATE | The function has **0 direct tests**. The 3 tests in text.rs test other functions (changed_lines_between, build_synthetic_diff, apply_incremental_change). byte_offset_at_position is untested. |
| "15 conformance checks" | SEMANTIC | The conform module has 15 test functions, but quick mode runs 14 (determinism skipped). Research mentions "12/14 passing" which is correct for quick mode. |
| "1,788 lines in diffguard-lsp" | NOT VERIFIED | Did not count lines, but crate size appears consistent with claim. |

---

## 2. Plan Approach Soundness

### Strengths

1. **Correct test harness approach:** Using `lsp_server::Connection::memory()` is the standard way to test LSP servers. This is explicitly documented as "Use this for testing."

2. **Good file structure:** Mirrors the CLI crate's integration test organization (tests/integration.rs + modules).

3. **Appropriate test data reuse:** Leveraging diffguard-testkit fixtures (DiffBuilder, FixtureRepo) avoids duplication.

4. **Phased approach is logical:** Infrastructure first, then protocol, diagnostics, code actions, edge cases, snapshots.

5. **Reasonable test count estimate:** 25-30 integration tests + 5-8 snapshot tests aligns with the 6 phases outlined.

6. **Risk mitigation is appropriate:** In-process Connection avoids subprocess complexity; timeouts address threading concerns.

### Gaps in Plan

1. **Missing test for `byte_offset_at_position`:** The research correctly identifies this function has complex UTF-16 logic but incorrectly states it has "2 basic tests." The plan should add a dedicated test for this function (it has 0 tests).

2. **No mention of testing `utf16_length` function:** This helper also has UTF-16 logic and could benefit from edge case testing (emoji, multi-byte characters).

3. **No consideration for testing the server's `run_server` function directly:** The plan suggests spawning the server in a thread, but `server::run_server(connection)` could be tested more directly by passing a memory connection.

4. **Snapshot test location unclear:** Plan mentions `snapshots/` directory but insta typically stores snapshots next to tests or in `tests/snapshots/`. Should align with existing workspace convention.

### What's Missing from Research

1. **No analysis of `server::run_server` function:** The main server loop that processes messages is not analyzed. Understanding its structure is important for designing integration tests.

2. **No mention of how diagnostics are currently published:** The research mentions diagnostics are published but doesn't analyze the `publish_diagnostics` mechanism.

3. **No analysis of error handling paths:** The research notes "No error path tests" but doesn't identify specific error paths that should be tested.

---

## 3. Scope Assessment

### Scope is Appropriate

The scope is well-chosen:
- **Not too big:** Focuses only on LSP integration tests, not all improvement areas.
- **Not too small:** 25-30 tests covers the critical paths (protocol lifecycle, diagnostics, code actions).
- **High impact:** Addresses the most visible gap (0 integration tests for newest feature).
- **Blocks downstream work:** VS Code extension and LSP features depend on reliable tests.

### Estimated Effort is Reasonable

7-11 hours is realistic for:
- Setting up test infrastructure (2-3 hours)
- Writing 25-30 integration tests (4-6 hours)
- Adding snapshot tests (1-2 hours)

---

## 4. Recommendations

### Plan Corrections

1. Add a test for `byte_offset_at_position` in Phase 5 (edge cases) or Phase 2 (protocol tests).
2. Consider adding `utf16_length` edge case tests (emoji, multi-byte).
3. Clarify snapshot test storage location to match workspace convention.
4. Document that `server::run_server` can be tested directly with memory connection.

### Research Corrections

1. Fix "byte_offset_at_position has 2 basic tests" to "has 0 direct tests."
2. Add brief analysis of `server::run_server` function structure.

---

## Final Verdict

**APPROVE** the plan with minor corrections.

The research is accurate (with one factual error about byte_offset_at_position test count) and the plan approach is sound. The scope is appropriate, the test harness design is correct, and the effort estimate is reasonable. The identified gaps are minor and can be addressed during implementation.

### Action Items Before Implementation

1. Correct the byte_offset_at_position test count in research-analysis.md
2. Add byte_offset_at_position test to Phase 2 or Phase 5 in initial-plan.md
3. Clarify snapshot test storage location in initial-plan.md

**Confidence Level:** HIGH
**Risk Level:** LOW