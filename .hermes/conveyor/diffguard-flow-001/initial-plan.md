# Diffguard Initial Improvement Plan

**Date:** 2026-04-05
**Scope:** Single most impactful improvement area

---

## Selected Focus: LSP Server Integration Tests

### Why This Area

After analyzing all improvement candidates, **LSP server integration tests** emerge as the single most impactful improvement for these reasons:

1. **Highest risk/impact ratio.** The LSP crate is the newest, most complex feature (~1,800 lines) with the least test coverage (0 integration tests, only 10 unit tests). It handles LSP protocol lifecycle, document state management, diagnostic publishing, code actions, and git integration — all critical paths with no integration-level verification.

2. **Blocks confidence in the feature.** Without integration tests, every LSP change risks silent regressions in protocol compliance, diagnostic accuracy, or error handling. This undermines the entire IDE integration story.

3. **Unlocks downstream work.** Reliable LSP tests are prerequisite to completing the VS Code extension (currently a stub), adding features like autofix code actions, and shipping the LSP as a standalone component.

4. **Complements existing test infrastructure.** The workspace already has excellent test patterns (property tests, snapshot tests, BDD integration tests) — extending these to the LSP crate is natural and follows established conventions.

5. **Addresses a visible gap.** Every other output format (JSON, Markdown, SARIF, JUnit, CSV) has snapshot/conformance tests. LSP diagnostics are the one format with zero integration-level validation.

### Candidates Considered and Rejected

| Candidate | Why Not Selected |
|-----------|-----------------|
| CI pipeline improvements (caching, audit) | Important but mechanical — doesn't improve code quality |
| Fix failing xtask tests | Necessary but small scope — likely env var isolation bugs |
| diffguard-analytics test coverage | Small crate, low risk — 4 tests may be sufficient |
| VS Code extension + LSP integration | Depends on LSP being well-tested first |
| MSRV/cross-platform CI | Infrastructure, not code quality |

---

## Approach: LSP Integration Test Suite

### Phase 1: Test Infrastructure Setup

Create `crates/diffguard-lsp/tests/` directory with integration test harness.

**Key components:**
- LSP test client/server harness using `lsp-server` Connection in-process
- Helper to spin up a server instance with test config
- Helper to send initialize/shutdown lifecycle messages
- Helper to send didOpen/didChange/didClose notifications
- Helper to collect published diagnostics

**Pattern:** Mirror the existing `diffguard/tests/integration/` structure. Use `tempfile::TempDir` for workspace setup (consistent with other crates).

### Phase 2: Core Protocol Tests

| Test | What It Verifies |
|------|-----------------|
| `test_initialize_response` | Server capabilities (text sync, code actions, execute command) |
| `test_shutdown_exit_lifecycle` | Clean shutdown without errors |
| `test_did_open_publishes_diagnostics` | Diagnostics published on file open |
| `test_did_change_updates_diagnostics` | Diagnostics refresh on content change |
| `test_did_close_clears_diagnostics` | Empty diagnostics on file close |
| `test_did_save_refreshes` | Save triggers diagnostic refresh |

### Phase 3: Diagnostic Accuracy Tests

| Test | What It Verifies |
|------|-----------------|
| `test_diagnostics_match_rule_violations` | Correct rule ID, severity, message, range |
| `test_diagnostics_respect_diff_scope` | Only changed lines produce diagnostics |
| `test_diagnostics_use_config_rules` | Custom config rules are applied |
| `test_diagnostics_suppressed_by_directive` | Inline suppressions work in LSP context |
| `test_diagnostics_directory_overrides` | Per-directory overrides apply |

### Phase 4: Code Action and Command Tests

| Test | What It Verifies |
|------|-----------------|
| `test_code_action_explain_rule` | Explain action exists for diagnostic |
| `test_code_action_open_docs` | URL action when rule has `url` field |
| `test_execute_explain_rule` | Explain command returns rule details |
| `test_execute_reload_config` | Config reload works without restart |
| `test_execute_show_rule_url` | URL display command works |

### Phase 5: Edge Cases and Error Handling

| Test | What It Verifies |
|------|-----------------|
| `test_invalid_config_graceful_fallback` | Falls back to built-in rules on bad config |
| `test_missing_workspace_handled` | No crash when workspace_root is None |
| `test_git_unavailable_fallback` | Graceful when git is not available |
| `test_concurrent_document_changes` | Multiple documents updating simultaneously |

### Phase 6: Snapshot Tests for Diagnostic Output

Add insta snapshot tests for `findings_to_diagnostics()` output, consistent with the pattern used for SARIF, JUnit, CSV, and Markdown outputs in diffguard-core.

---

## Implementation Strategy

### File Structure
```
crates/diffguard-lsp/
  tests/
    integration.rs          # Test harness and helpers
    protocol_lifecycle.rs   # Phase 2 tests
    diagnostic_accuracy.rs  # Phase 3 tests
    code_actions.rs         # Phase 4 tests
    edge_cases.rs           # Phase 5 tests
    snapshots/              # Phase 6 insta snapshots
```

### Test Harness Design

The LSP server communicates over stdio. For integration tests:
1. Create a duplex channel (two `std::io::duplex` or pipe pairs)
2. Wrap in `lsp-server::Connection`
3. Spawn server in a thread using the server-side connection
4. Use client-side connection to send requests/notifications
5. Collect responses and diagnostics

This mirrors how `lsp-server` itself is tested and avoids needing a real subprocess.

### Test Data

Reuse `diffguard-testkit` fixtures:
- `DiffBuilder` for constructing test diffs
- `FixtureRepo` for temporary git repos
- Sample `ConfigFile` instances with known rules

### Expected Test Count

~25-30 integration tests across 4 test files, plus ~5-8 snapshot tests.

---

## Success Criteria

1. `cargo test -p diffguard-lsp` passes with all new tests
2. All existing tests still pass (`cargo test --workspace`)
3. Test coverage of LSP crate increases from ~15% to ~70%+ (estimated)
4. CI runs LSP tests without special configuration
5. No new dependencies added (uses existing tempfile, insta from workspace)

## Estimated Effort

- Phase 1 (infrastructure): 2-3 hours
- Phase 2-5 (tests): 4-6 hours
- Phase 6 (snapshots): 1-2 hours
- **Total: 7-11 hours**

## Risks

| Risk | Mitigation |
|------|-----------|
| LSP protocol mocking complexity | Use in-process Connection, not subprocess |
| Test flakiness from threading | Use timeouts, deterministic ordering |
| Existing conformance test failures mask new issues | Fix xtask failures first (separate PR) |
