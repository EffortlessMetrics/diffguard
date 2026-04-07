# ADR-001: Add LSP Server Integration Tests

**Date:** 2026-04-05
**Status:** Proposed
**Deciders:** Diffguard maintainers
**Category:** Testing / Quality Assurance

---

## Context

The diffguard workspace is a well-architected Rust microcrate project with 9
crates providing static analysis of unified diffs. The codebase has strong test
coverage across most components: property tests, snapshot tests, fuzz targets,
BDD integration tests, and conformance tests.

The `diffguard-lsp` crate (~1,788 lines) is the newest and most complex feature.
It implements an LSP (Language Server Protocol) server that provides real-time
diagnostics and code actions to IDEs. Despite being listed as a first-class
feature in the README and marked complete in the ROADMAP, it has **zero
integration tests**.

Current test state of diffguard-lsp:
- 10 unit tests covering config helpers and code action building
- 0 files under `tests/` directory (no integration tests)
- No protocol-level tests for initialize/shutdown lifecycle
- No tests for diagnostic publishing via didOpen/didChange/didClose
- No tests for code actions or execute commands at the protocol level
- `byte_offset_at_position` (complex UTF-16 logic) has 0 direct tests

Every other output format (JSON, Markdown, SARIF, JUnit, CSV, sensor report)
has snapshot or conformance tests. LSP diagnostics are the one format with zero
integration-level validation.

Risks of the current state:
- Silent regressions in protocol compliance, diagnostic accuracy, or error
  handling with every LSP change
- Blocks downstream work on the VS Code extension (currently a shell-out stub)
- Active core engine changes (per-directory overrides, scope expansion) could
  break the LSP diagnostic path undetected
- Confidence in shipping the LSP as a standalone component is undermined

---

## Decision

We will add a comprehensive integration test suite for the `diffguard-lsp`
crate, covering protocol lifecycle, diagnostic accuracy, code actions, execute
commands, edge cases, and snapshot tests for diagnostic output.

### Approach

Use `lsp-server::Connection::memory()` to create an in-process LSP
client/server pair. This is the standard, documented approach for testing LSP
servers and avoids subprocess overhead.

Test harness design:
1. Create a `Connection::memory()` pair (server-side and client-side)
2. Spawn the server thread with `run_server(server_connection)`
3. Send initialize request from client, wait for response
4. Perform test actions (didOpen, didChange, requests, etc.)
5. Send shutdown request + exit notification
6. Join server thread

An RAII test helper will ensure clean shutdown on test failure (auto-send
shutdown/exit on drop).

### File Structure

```
crates/diffguard-lsp/
  tests/
    integration.rs          # Test harness, helpers, RAII lifecycle guard
    protocol_lifecycle.rs   # Initialize, shutdown, exit, didSave
    diagnostic_accuracy.rs  # Rule violations, diff scope, config, suppression
    code_actions.rs         # Explain rule, open docs, execute commands
    edge_cases.rs           # Invalid config, missing workspace, git fallback
    snapshots/              # insta snapshots for findings_to_diagnostics()
```

### Test Coverage (~28-33 tests)

**Protocol lifecycle (6 tests):**
- `test_initialize_response` -- Server capabilities (text sync, code actions, execute command)
- `test_shutdown_exit_lifecycle` -- Clean shutdown without errors
- `test_did_open_publishes_diagnostics` -- Diagnostics published on file open
- `test_did_change_updates_diagnostics` -- Diagnostics refresh on content change
- `test_did_close_clears_diagnostics` -- Empty diagnostics on file close
- `test_did_save_refreshes` -- Save triggers diagnostic refresh

**Diagnostic accuracy (5 tests):**
- `test_diagnostics_match_rule_violations` -- Correct rule ID, severity, message, range
- `test_diagnostics_respect_diff_scope` -- Only changed lines produce diagnostics
- `test_diagnostics_use_config_rules` -- Custom config rules are applied
- `test_diagnostics_suppressed_by_directive` -- Inline suppressions work in LSP context
- `test_diagnostics_directory_overrides` -- Per-directory overrides apply

**Code actions and commands (6 tests):**
- `test_code_action_explain_rule` -- Explain action exists for diagnostic
- `test_code_action_open_docs` -- URL action when rule has `url` field
- `test_execute_explain_rule` -- Explain command returns rule details
- `test_execute_reload_config` -- Config reload works without restart
- `test_execute_show_rule_url` -- URL display command works
- `test_did_change_configuration_reloads` -- didChangeConfiguration triggers config reload

**Edge cases and error handling (4 tests):**
- `test_invalid_config_graceful_fallback` -- Falls back to built-in rules on bad config
- `test_missing_workspace_handled` -- No crash when workspace_root is None
- `test_git_unavailable_fallback` -- Graceful when git is not available
- `test_concurrent_document_changes` -- Multiple documents updating simultaneously

**Snapshot tests (5-8 tests):**
- `findings_to_diagnostics()` output snapshots for various rule/diff combinations

### Key Technical Decisions

1. **`Connection::memory()` over subprocess.** The `lsp-server` crate provides
   `Connection::memory()` which returns a connected pair of in-process
   connections. This is explicitly documented as "Use this for testing" and
   avoids the complexity, flakiness, and slowness of spawning a subprocess.

2. **RAII lifecycle guard.** Each test will use a drop guard that sends
   shutdown + exit if the test fails early, preventing zombie server threads.

3. **Reuse `diffguard-testkit` fixtures.** Add testkit as a dev-dependency to
   leverage `DiffBuilder`, `FixtureRepo`, and sample `ConfigFile` instances.
   Simpler tests can use inline config and diff construction.

4. **Synthetic diffs via `didChange`.** Most tests will set changed lines via
   `didChange` notifications rather than requiring a real git repo. Git fallback
   tests will use `FixtureRepo` for temp git repo creation.

5. **Snapshot storage in `tests/snapshots/`.** Follow workspace convention for
   insta snapshot locations.

### Required Pre-Implementation Corrections

1. Add `diffguard-testkit = { path = "../diffguard-testkit" }` to
   `[dev-dependencies]` in `crates/diffguard-lsp/Cargo.toml`
2. Add `tempfile` to `[dev-dependencies]` if not already present

---

## Consequences

### Positive

- Provides regression safety for the newest, most complex feature
- Unblocks VS Code extension development (depends on reliable LSP)
- Validates that core engine changes don't break the LSP diagnostic path
- Brings LSP diagnostics in line with other output format test coverage
- Establishes patterns for testing LSP protocol interactions

### Negative

- Adds ~28-33 new tests to the test suite (~2-4 seconds additional CI time)
- Adds `diffguard-testkit` as a dev-dependency (increases initial compile time
  for diffguard-lsp tests, but testkit is already compiled for other crates)
- Thread-based server testing introduces potential flakiness (mitigated by RAII
  guard and timeouts)

### Neutral

- No changes to production code -- purely additive test infrastructure
- No new runtime dependencies -- only dev-dependencies
- CI configuration requires no changes (tests run via `cargo test --workspace`)

### Risks

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| Server thread hangs if test fails before shutdown | Medium | Medium | RAII drop guard ensures shutdown/exit |
| Test flakiness from thread ordering | Low | Low | Deterministic message ordering, timeouts |
| `run_check()` needs real git for diff | Medium | Medium | Use synthetic diff via didChange |
| Snapshot drift from diagnostic format changes | Low | Low | Standard insta review workflow |

---

## Alternatives Considered

### Alternative 1: Subprocess-based LSP testing

Spawn the diffguard-lsp binary as a subprocess and communicate over stdin/stdout.
This would test the full server as end users would run it.

**Rejected because:** `Connection::memory()` provides the same protocol-level
coverage without subprocess complexity, process management overhead, slower test
execution, and cross-platform portability concerns. The `lsp-server` crate
itself uses in-process testing.

### Alternative 2: Mock the diffguard-core engine

Replace `run_check()` with a mock that returns controlled findings, isolating
the LSP layer from the core engine.

**Rejected because:** The most valuable tests verify the full pipeline from
document change through rule evaluation to diagnostic output. Mocking the core
would miss integration bugs between the LSP crate and the engine. The core
engine is already well-tested; we want to verify the LSP correctly invokes it.

### Alternative 3: Extend existing conformance tests

Add LSP diagnostic output as a new format in the conformance test framework
rather than writing separate integration tests.

**Rejected because:** Conformance tests validate output format correctness
against schemas. LSP integration tests need to verify protocol lifecycle,
document synchronization, code actions, and execute commands -- concerns that
don't fit the conformance test model. Both approaches are complementary.

### Alternative 4: Add tests incrementally with each LPR/feature

Rather than a dedicated test suite, add tests as part of future LSP changes.

**Rejected because:** The current gap is too large (0 integration tests for a
shipped feature). Incremental addition would leave critical paths untested for
an extended period and doesn't address the immediate risk from ongoing core
engine changes.

---

## Implementation Notes

### Dependencies to Add

```toml
# In crates/diffguard-lsp/Cargo.toml [dev-dependencies]
diffguard-testkit = { path = "../diffguard-testkit" }
tempfile = { workspace = true }
insta = { workspace = true }
```

### Test Harness Skeleton

```rust
// tests/integration.rs
use lsp_server::{Connection, Message};
use lsp_types::*;
use std::thread;

struct TestServer {
    connection: Connection,
    _thread: thread::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Send shutdown + exit to prevent zombie thread
        let _ = self.connection.sender.send(...);
    }
}

fn start_server() -> TestServer {
    let (client_conn, server_conn) = Connection::memory();
    let thread = thread::spawn(move || {
        diffguard_lsp::server::run_server(server_conn).unwrap();
    });
    // Send initialize, wait for response
    TestServer { connection: client_conn, _thread: thread }
}
```

### Key Patterns

- Use `Connection::memory()` for all tests
- Send `initialize` request before any other messages
- Send `shutdown` request + `exit` notification in teardown (RAII guard)
- Use `didChange` notifications to set synthetic diffs (avoids git dependency)
- Use `tempfile::TempDir` for workspace roots (consistent with CLI tests)
- Filter `connection.receiver` for `PublishDiagnostics` notifications
- Use insta for snapshot tests of `findings_to_diagnostics()` output

### Snapshot Convention

Store snapshots in `crates/diffguard-lsp/tests/snapshots/` to match workspace
conventions. Follow the existing insta workflow: `cargo insta review` to accept
new snapshots.

---

## References

- Research analysis: `research-analysis.md`
- Initial plan: `initial-plan.md`
- Verification: `verification.md`
- Plan review: `plan-review.md`
- Vision review: `vision-review.md`
- `lsp-server` crate docs: https://docs.rs/lsp-server/0.7/lsp_server/struct.Connection.html#method.memory
- diffguard README: Lists LSP as first-class feature
- diffguard ROADMAP: Phase 6.7 "LSP server for IDE integration" marked complete
