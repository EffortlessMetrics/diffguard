# LSP Server Integration Test Specifications

**Date:** 2026-04-05
**Work ID:** work-cf4dd66f
**Gate:** DESIGNED

---

## Acceptance Criteria

### AC1: Test Infrastructure
- [ ] `TestServer` RAII helper exists that manages server lifecycle
- [ ] Helper can send initialize and receive capabilities
- [ ] Helper can send didOpen/didChange/didClose notifications
- [ ] Helper can collect published diagnostics
- [ ] Helper properly shuts down server thread on drop

### AC2: Protocol Lifecycle
- [ ] `test_initialize_response` passes — server returns correct capabilities
- [ ] `test_shutdown_exit_lifecycle` passes — clean shutdown without errors
- [ ] `test_did_open_publishes_diagnostics` passes — diagnostics on file open
- [ ] `test_did_change_updates_diagnostics` passes — diagnostics refresh on change
- [ ] `test_did_close_clears_diagnostics` passes — empty diagnostics on close
- [ ] `test_did_save_refreshes` passes — save triggers refresh

### AC3: Diagnostic Accuracy
- [ ] `test_diagnostics_match_rule_violations` passes — correct rule ID, severity, message
- [ ] `test_diagnostics_respect_diff_scope` passes — only changed lines produce diagnostics
- [ ] `test_diagnostics_use_config_rules` passes — custom config applied
- [ ] `test_diagnostics_suppressed_by_directive` passes — inline suppressions work
- [ ] `test_diagnostics_directory_overrides` passes — per-directory overrides apply

### AC4: Code Actions
- [ ] `test_code_action_explain_rule` passes — explain action exists
- [ ] `test_code_action_open_docs` passes — URL action when rule has url
- [ ] `test_execute_explain_rule` passes — explain command returns details
- [ ] `test_execute_reload_config` passes — config reload without restart
- [ ] `test_execute_show_rule_url` passes — URL display works

### AC5: Edge Cases
- [ ] `test_invalid_config_graceful_fallback` passes — falls back to built-in rules
- [ ] `test_missing_workspace_handled` passes — no crash when workspace_root is None
- [ ] `test_git_unavailable_fallback` passes — graceful when git unavailable
- [ ] `test_concurrent_document_changes` passes — multiple docs update simultaneously

### AC6: Snapshot Tests
- [ ] Snapshot tests for `findings_to_diagnostics()` output exist
- [ ] Snapshots stored in `tests/snapshots/` matching workspace convention
- [ ] Snapshots cover at least 3 different diagnostic scenarios

### AC7: Quality Gates
- [ ] `cargo test -p diffguard-lsp` passes with all new tests
- [ ] `cargo test --workspace` passes (no regressions)
- [ ] `cargo clippy --workspace` passes
- [ ] `cargo fmt --check` passes
- [ ] No new dependencies added (uses existing tempfile, insta from workspace)

### AC8: Documentation
- [ ] CHANGELOG.md updated with LSP integration test addition
- [ ] CLAUDE.md in diffguard-lsp crate updated with test instructions
- [ ] Test file comments explain non-obvious test setup

---

## Test Count Targets

| Category | Min Tests | Target Tests |
|----------|-----------|--------------|
| Protocol lifecycle | 6 | 6 |
| Diagnostic accuracy | 5 | 5 |
| Code actions | 5 | 6 |
| Edge cases | 4 | 6 |
| Snapshot tests | 3 | 6 |
| Unit tests (text.rs) | 2 | 4 |
| **Total** | **25** | **33** |

---

## Validation Rules

1. Every test must have a clear `#[test]` attribute
2. Tests must use `TestServer` helper (not raw Connection)
3. Tests must clean up after themselves (TempDir, RAII)
4. No hardcoded paths or environment dependencies
5. Tests must be deterministic (no timing dependencies)
