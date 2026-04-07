# Diffguard LSP Integration Test Suite -- Task Breakdown

**Date:** 2026-04-05
**Scope:** Implement integration test suite for diffguard-lsp crate
**Estimated Total:** 10-14 hours
**Reference:** ADR-001, initial-plan.md, verification.md, plan-review.md, vision-review.md

---

## Pre-Requisites (Must Be Done First)

### T0: Add dev-dependencies to diffguard-lsp Cargo.toml
- **File:** `crates/diffguard-lsp/Cargo.toml`
- **Action:** Add to `[dev-dependencies]`:
  ```toml
  diffguard-testkit = { path = "../diffguard-testkit" }
  tempfile = { workspace = true }
  insta = { workspace = true }
  ```
- **Estimate:** 0.25 hours
- **Acceptance:** `cargo check -p diffguard-lsp --tests` compiles without errors
- **Why:** Plan-review and vision-review flagged missing testkit dev-dependency as a required pre-implementation correction

### T1: Verify existing unit tests still pass
- **Action:** Run `cargo test -p diffguard-lsp` and confirm all 10 existing unit tests pass
- **Estimate:** 0.25 hours
- **Acceptance:** All 10 `#[test]` functions in diffguard-lsp/src/ pass
- **Why:** Establishes baseline before adding new tests

---

## Phase 1: Test Infrastructure Setup (2-3 hours)

### T2: Create test directory structure
- **Files to create:**
  - `crates/diffguard-lsp/tests/integration.rs` -- test harness and helpers
  - `crates/diffguard-lsp/tests/protocol_lifecycle.rs`
  - `crates/diffguard-lsp/tests/diagnostic_accuracy.rs`
  - `crates/diffguard-lsp/tests/code_actions.rs`
  - `crates/diffguard-lsp/tests/edge_cases.rs`
  - `crates/diffguard-lsp/tests/snapshots/` -- directory for insta snapshots
- **Estimate:** 0.25 hours
- **Acceptance:** File structure exists and compiles (empty test modules)

### T3: Implement `TestServer` RAII helper in integration.rs
- **What:** Create the core test harness struct:
  ```rust
  struct TestServer {
      client_conn: Connection,
      server_thread: Option<thread::JoinHandle<()>>,
  }
  impl Drop for TestServer { /* send shutdown + exit */ }
  ```
- **Key behavior:**
  - `TestServer::start()` -- creates `Connection::memory()` pair, spawns server thread with `run_server(server_conn)`, sends initialize request, waits for initialize response
  - `TestServer::shutdown()` -- sends shutdown request + exit notification, joins thread
  - `Drop` impl ensures shutdown/exit sent even on test failure (prevents zombie threads)
- **Estimate:** 1 hour
- **Acceptance:** Can instantiate TestServer and receive valid InitializeResult capabilities
- **Risk note:** `run_server` blocks on `connection.receiver` -- must send shutdown+exit before joining thread

### T4: Implement document helper functions
- **What:** Add helpers to integration.rs:
  - `send_did_open(server, uri, lang_id, version, text)` -- sends didOpen notification
  - `send_did_change(server, uri, version, text)` -- sends didChange notification (full sync)
  - `send_did_close(server, uri)` -- sends didClose notification
  - `send_did_save(server, uri)` -- sends didSave notification
  - `collect_diagnostics(server, timeout) -> Vec<PublishDiagnosticsParams>` -- reads from receiver, filters for diagnostic notifications
- **Estimate:** 0.75 hours
- **Acceptance:** Helpers send correct LSP notification JSON and can collect diagnostics

### T5: Implement request/response helpers
- **What:** Add helpers:
  - `send_code_action_request(server, uri, range) -> Vec<CodeActionOrCommand>` -- sends textDocument/codeAction, parses response
  - `send_execute_command(server, command, args) -> serde_json::Value` -- sends workspace/executeCommand
  - `send_shutdown(server)` -- sends shutdown request
  - `send_exit(server)` -- sends exit notification
- **Estimate:** 0.5 hours
- **Acceptance:** Helpers round-trip requests and parse responses correctly

### T6: Create test fixture helpers
- **What:** Add helpers using diffguard-testkit and tempfile:
  - `create_test_config(dir) -> PathBuf` -- writes a test diffguard config to TempDir
  - `create_test_file(dir, name, content) -> Url` -- writes a file and returns its URI
  - `make_test_diff(old, new) -> String` -- constructs a synthetic unified diff
- **Estimate:** 0.5 hours
- **Acceptance:** Fixture helpers create valid temp files and config that the LSP server accepts

---

## Phase 2: Core Protocol Tests (1.5-2 hours)

Tests go in `crates/diffguard-lsp/tests/protocol_lifecycle.rs`.

### T7: `test_initialize_response`
- **What:** Verify InitializeResult contains expected capabilities:
  - `text_document_sync` = Full (or Incremental)
  - `code_action_provider` = true
  - `execute_command_provider` with `diffguard.explainRule`, `diffguard.reloadConfig`, `diffguard.showRuleUrl`
- **Estimate:** 0.25 hours
- **Acceptance:** Assert on specific capability fields in InitializeResult

### T8: `test_shutdown_exit_lifecycle`
- **What:** Send shutdown request, verify OK response; send exit notification, verify server thread joins cleanly
- **Estimate:** 0.25 hours
- **Acceptance:** Thread join succeeds, no panics or errors

### T9: `test_did_open_publishes_diagnostics`
- **What:** Open a file with content that triggers a rule violation, verify PublishDiagnostics notification is received with at least one diagnostic
- **Estimate:** 0.5 hours
- **Acceptance:** Diagnostics received with correct URI, non-empty diagnostics array
- **Note:** Use `send_did_change` to set synthetic diff content so `run_check` has changed lines to evaluate

### T10: `test_did_change_updates_diagnostics`
- **What:** Open file, then change content to trigger different violations, verify diagnostics update
- **Estimate:** 0.5 hours
- **Acceptance:** Second PublishDiagnostics notification has different diagnostics than first

### T11: `test_did_close_clears_diagnostics`
- **What:** Open file (get diagnostics), close file, verify empty diagnostics published for that URI
- **Estimate:** 0.25 hours
- **Acceptance:** PublishDiagnostics with empty diagnostics array received after didClose

### T12: `test_did_save_refreshes`
- **What:** Save a file, verify diagnostics are re-published (server refreshes on save)
- **Estimate:** 0.25 hours
- **Acceptance:** PublishDiagnostics notification received after didSave

---

## Phase 3: Diagnostic Accuracy Tests (2-3 hours)

Tests go in `crates/diffguard-lsp/tests/diagnostic_accuracy.rs`.

### T13: `test_diagnostics_match_rule_violations`
- **What:** Trigger a specific known rule violation, verify the diagnostic has:
  - Correct `code` (rule ID like "no-todo")
  - Correct `severity` (Error/Warning)
  - Correct `message` (matches rule's message template)
  - Correct `range` (points to the violating line)
- **Estimate:** 0.75 hours
- **Acceptance:** All four diagnostic fields match expected values
- **Requires:** Knowledge of a specific built-in rule and triggering content

### T14: `test_diagnostics_respect_diff_scope`
- **What:** Open a file with violations on both changed and unchanged lines, verify only changed lines produce diagnostics
- **Estimate:** 0.75 hours
- **Acceptance:** Diagnostic ranges only cover lines that appear in the diff
- **Note:** This is the core diffguard behavior -- diagnostics scoped to changed lines only

### T15: `test_diagnostics_use_config_rules`
- **What:** Create a custom config with a specific rule, open a file that violates it, verify the diagnostic appears
- **Estimate:** 0.5 hours
- **Acceptance:** Diagnostic code matches the custom rule ID from the config file

### T16: `test_diagnostics_suppressed_by_directive`
- **What:** Open a file with a suppression comment (e.g., `// diffguard:suppress no-todo`) on a violating line, verify no diagnostic for that line
- **Estimate:** 0.5 hours
- **Acceptance:** No diagnostic with matching rule code for the suppressed line
- **Note:** May need to check what suppression syntax diffguard uses (from diffguard-domain)

### T17: `test_diagnostics_directory_overrides`
- **What:** Configure per-directory rule overrides, verify diagnostics differ for files in different directories
- **Estimate:** 0.5 hours
- **Acceptance:** File under overridden directory gets different severity/filtered diagnostics
- **Note:** Uses temp directory structure with config includes or directory overrides

---

## Phase 4: Code Action and Command Tests (1.5-2 hours)

Tests go in `crates/diffguard-lsp/tests/code_actions.rs`.

### T18: `test_code_action_explain_rule`
- **What:** Trigger a rule violation, send codeAction request for the diagnostic range, verify an "Explain rule" action is returned
- **Estimate:** 0.5 hours
- **Acceptance:** Response contains a CodeAction with title containing "Explain" and command pointing to `diffguard.explainRule`

### T19: `test_code_action_open_docs`
- **What:** Trigger a violation for a rule that has a `url` field, send codeAction request, verify an "Open docs" action is returned with the correct URL
- **Estimate:** 0.25 hours
- **Acceptance:** CodeAction with URL-related title and correct documentation link

### T20: `test_execute_explain_rule`
- **What:** Send executeCommand for `diffguard.explainRule` with a rule ID, verify response contains rule details (name, description, severity)
- **Estimate:** 0.25 hours
- **Acceptance:** Command response contains structured rule explanation

### T21: `test_execute_reload_config`
- **What:** Send executeCommand for `diffguard.reloadConfig`, verify success response and that diagnostics update with new config rules
- **Estimate:** 0.25 hours
- **Acceptance:** Command succeeds, subsequent diagnostics reflect reloaded config

### T22: `test_execute_show_rule_url`
- **What:** Send executeCommand for `diffguard.showRuleUrl` with a rule ID that has a URL, verify response contains the URL
- **Estimate:** 0.25 hours
- **Acceptance:** Command response contains the rule's documentation URL

### T23: `test_did_change_configuration_reloads`
- **What:** Send didChangeConfiguration notification with updated settings, verify diagnostics reflect new configuration
- **Estimate:** 0.5 hours
- **Acceptance:** Diagnostics update after configuration change notification
- **Note:** This was flagged as missing from the initial plan in plan-review.md; server handles this notification at lines 581-606 of server.rs

---

## Phase 5: Edge Cases and Error Handling (1.5-2 hours)

Tests go in `crates/diffguard-lsp/tests/edge_cases.rs`.

### T24: `test_invalid_config_graceful_fallback`
- **What:** Point the server at a malformed config file, verify it falls back to built-in rules instead of crashing
- **Estimate:** 0.5 hours
- **Acceptance:** Server still produces diagnostics using default rules, no panic or error response

### T25: `test_missing_workspace_handled`
- **What:** Initialize server without setting workspace_root (rootUri = null), verify no crash on didOpen
- **Estimate:** 0.25 hours
- **Acceptance:** Server accepts messages and produces diagnostics (possibly using git-less fallback)

### T26: `test_git_unavailable_fallback`
- **What:** Test in a directory that is not a git repository, verify the server uses synthetic diff from didChange instead of crashing
- **Estimate:** 0.5 hours
- **Acceptance:** Diagnostics produced from didChange content without git dependency
- **Note:** Uses TempDir (not a git repo) -- server should fall back to in-memory diff

### T27: `test_concurrent_document_changes`
- **What:** Open multiple documents, send rapid didChange notifications for each, verify diagnostics for all documents are published correctly
- **Estimate:** 0.5 hours
- **Acceptance:** Each URI receives its own correct PublishDiagnostics, no cross-contamination
- **Note:** Plan-review suggests this could be deferred to follow-up PR if too complex

### T28: `test_byte_offset_at_position_utf16_edge_cases` (unit test)
- **What:** Add unit tests in `src/text.rs` for `byte_offset_at_position` with:
  - ASCII characters
  - Multi-byte UTF-8 (e.g., "cafe\u0301")
  - Emoji (surrogate pairs in UTF-16)
  - Mixed content
- **Estimate:** 0.5 hours
- **Acceptance:** 4+ unit tests covering edge cases pass
- **Note:** Verification.md confirmed this function has 0 direct tests; plan-review recommends adding these

### T29: `test_utf16_length_edge_cases` (unit test)
- **What:** Add unit tests for `utf16_length` helper with emoji, multi-byte, empty string
- **Estimate:** 0.25 hours
- **Acceptance:** 3+ unit tests covering edge cases pass

---

## Phase 6: Snapshot Tests (1-2 hours)

Tests go in `crates/diffguard-lsp/tests/diagnostic_accuracy.rs` or a separate `snapshots.rs`.

### T30: Snapshot test for `findings_to_diagnostics()` with basic rule
- **What:** Feed a known set of Findings through `findings_to_diagnostics()`, assert snapshot matches
- **Estimate:** 0.25 hours
- **Acceptance:** Insta snapshot file created and passes

### T31: Snapshot test for `findings_to_diagnostics()` with multiple rules
- **What:** Multiple rule violations producing multiple diagnostics
- **Estimate:** 0.25 hours
- **Acceptance:** Snapshot covers multi-diagnostic output

### T32: Snapshot test for `findings_to_diagnostics()` with severity variants
- **What:** Mix of Error and Warning severity diagnostics
- **Estimate:** 0.25 hours
- **Acceptance:** Snapshot shows correct severity mapping

### T33: Snapshot test for `findings_to_diagnostics()` with suppressed findings
- **What:** Findings where some are suppressed, verify snapshot shows only unsuppressed
- **Estimate:** 0.25 hours
- **Acceptance:** Snapshot reflects suppression correctly

### T34: Snapshot test for code action response format
- **What:** Snapshot the CodeAction response structure for a typical explain-rule action
- **Estimate:** 0.25 hours
- **Acceptance:** Snapshot matches expected CodeAction JSON structure

### T35: Run `cargo insta review` and accept snapshots
- **What:** After all snapshot tests pass, review and accept pending snapshots
- **Estimate:** 0.25 hours
- **Acceptance:** `cargo test -p diffguard-lsp` passes with all snapshots accepted

---

## Post-Implementation Tasks

### T36: Run full workspace test suite
- **Action:** `cargo test --workspace` -- verify no regressions from new tests
- **Estimate:** 0.25 hours
- **Acceptance:** All existing workspace tests continue to pass

### T37: Run clippy on diffguard-lsp
- **Action:** `cargo clippy -p diffguard-lsp --all-targets` -- verify no new warnings
- **Estimate:** 0.25 hours
- **Acceptance:** Zero clippy warnings

### T38: Run rustfmt check
- **Action:** `cargo fmt -p diffguard-lsp --check` -- verify formatting
- **Estimate:** 0.1 hours
- **Acceptance:** No formatting diff

### T39: Verify CI picks up new tests
- **Action:** Confirm `cargo test --workspace` (as run by `cargo run -p xtask -- ci`) includes new tests
- **Estimate:** 0.25 hours
- **Acceptance:** LSP integration tests appear in test output; no CI config changes needed (per ADR)

### T40: Update CHANGELOG
- **Action:** Add entry to CHANGELOG.md Unreleased section noting LSP integration tests added
- **Estimate:** 0.1 hours
- **Acceptance:** CHANGELOG entry present under Unreleased

### T41: Update CLAUDE.md for diffguard-lsp
- **Action:** Update `crates/diffguard-lsp/CLAUDE.md` to document the test structure, harness pattern, and how to run LSP tests
- **Estimate:** 0.25 hours
- **Acceptance:** CLAUDE.md reflects new test files and usage patterns

---

## Summary

| Phase | Tasks | Hours |
|-------|-------|-------|
| Pre-requisites (T0-T1) | 2 | 0.5 |
| Phase 1: Infrastructure (T2-T6) | 5 | 3.0 |
| Phase 2: Protocol (T7-T12) | 6 | 1.75 |
| Phase 3: Diagnostics (T13-T17) | 5 | 2.75 |
| Phase 4: Code Actions (T18-T23) | 6 | 1.75 |
| Phase 5: Edge Cases (T24-T29) | 6 | 2.0 |
| Phase 6: Snapshots (T30-T35) | 6 | 1.5 |
| Post-Implementation (T36-T41) | 6 | 1.25 |
| **Total** | **42** | **14.5** |

## Expected Test Count
- ~28-33 integration tests (protocol + diagnostic + code action + edge cases)
- ~5-8 snapshot tests
- ~7 unit tests (byte_offset_at_position + utf16_length edge cases)
- **Total: ~40-48 new tests**

## Key Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Server thread hangs if test fails before shutdown | RAII drop guard (T3) sends shutdown+exit automatically |
| `run_check()` needs real git repo | Use synthetic diff via didChange (T9-T12 pattern) |
| Snapshot drift from diagnostic format changes | Standard insta review workflow (T35) |
| Concurrency test flakiness (T27) | May defer to follow-up PR if too complex |

## Acceptance Criteria (Overall)
1. `cargo test -p diffguard-lsp` passes with all ~40-48 new tests
2. `cargo test --workspace` passes (no regressions)
3. `cargo clippy -p diffguard-lsp --all-targets` clean
4. `cargo fmt -p diffguard-lsp --check` clean
5. CI runs new tests via existing `cargo test --workspace` (no config changes)
6. CHANGELOG updated
7. CLAUDE.md updated
