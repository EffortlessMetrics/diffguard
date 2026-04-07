# Plan Review: Diffguard LSP Integration Tests

**Reviewer:** Hermes Plan Reviewer
**Date:** 2026-04-05
**Plan:** initial-plan.md
**Verification:** verification.md

---

## 1. Completeness Assessment

### Test Categories Covered

| Category | Covered | Notes |
|----------|---------|-------|
| Protocol lifecycle (init/shutdown) | YES | Phase 2 covers initialize, shutdown, exit |
| Document sync (didOpen/didChange/didClose/didSave) | YES | Phase 2 covers all four |
| Diagnostic accuracy | YES | Phase 5 covers rule violations, diff scope, config, suppression, directory overrides |
| Code actions | YES | Phase 6 covers explain, open docs |
| Execute commands | YES | Phase 6 covers explain, reload config, show URL |
| Edge cases / error handling | YES | Phase 7 covers invalid config, missing workspace, git fallback, concurrency |
| Snapshot tests | YES | Phase 8 covers findings_to_diagnostics output |

### Gaps Identified

1. **Missing: `byte_offset_at_position` and `utf16_length` unit tests.** The verification doc flags this. These are complex UTF-16 functions in text.rs with 0 direct tests. The plan does not include them. This is a gap, though these are unit tests rather than integration tests and could be a separate PR.

2. **Missing: `run_server` direct testing.** The plan mentions spawning the server in a thread, but `run_server(connection: Connection)` can be tested directly by passing the server-side of a `Connection::memory()` pair. The plan does not explicitly confirm this pattern.

3. **Missing: `diffguard-testkit` dev-dependency.** The plan says to reuse `DiffBuilder`, `FixtureRepo`, and sample configs from diffguard-testkit, but diffguard-lsp's Cargo.toml does not list testkit as a dev-dependency. This must be added.

4. **Minor: `didChangeConfiguration` notification.** The server handles this notification (line 581-606 of server.rs) but the plan does not include a test for it. It triggers config reload, same as `CMD_RELOAD_CONFIG`.

### Completeness Verdict: MOSTLY COMPLETE
The plan covers the major integration test categories well. Gaps are minor and can be addressed during implementation. The missing testkit dev-dependency is a concrete oversight that should be corrected before implementation.

---

## 2. Approach Soundness

### Is `Connection::memory()` the right approach?

**YES.** Confirmed:
- `lsp-server 0.7.9` includes `Connection::memory()` which returns `(Connection, Connection)` - a connected pair.
- The docs explicitly state: "Creates a pair of connected connections."
- The server-side `run_server(connection)` takes `Connection`, calls `connection.initialize(init)`, then iterates `connection.receiver`. The client side can send messages via `connection.sender`.
- This is the standard, recommended approach for testing LSP servers without subprocess overhead.

### Test harness design review

The plan proposes:
1. Create memory connection pair
2. Spawn server thread with server-side connection
3. Use client-side to send requests/notifications
4. Collect responses and diagnostics

This is sound. One consideration: `run_server` calls `connection.initialize()` which is a blocking call that waits for the client to send an initialize request. The test harness must:
- Spawn the server thread first
- Then send the initialize request from the client side
- Wait for the initialize response before proceeding

The plan's Phase 1 description handles this correctly with "Helper to send initialize/shutdown lifecycle messages."

### Dependency chain concern

The plan suggests reusing `diffguard-testkit` fixtures (DiffBuilder, FixtureRepo). However:
- `diffguard-testkit` depends on `diffguard-diff` and `diffguard-domain`
- Adding it as a dev-dependency adds transitive compile time
- The LSP crate's diagnostics flow through `run_check()` which needs a `CheckPlan` and diff text, not a `DiffBuilder`-produced struct directly
- Some testkit utilities (FixtureRepo for git repos) will be valuable for Phase 7 git fallback tests
- The simpler Phase 2-4 tests may not actually need testkit - they can construct `ConfigFile` and diff strings directly

**Recommendation:** Add testkit as dev-dependency but also consider that many tests can work with inline config and diff construction, reducing coupling.

### Approach Verdict: SOUND
The core approach is correct and well-validated. The `Connection::memory()` pattern is the right one.

---

## 3. Risk Assessment

| Risk | Severity | Likelihood | Mitigation | Notes |
|------|----------|------------|------------|-------|
| Server thread blocks on `connection.receiver` iterator | MEDIUM | MEDIUM | Use shutdown+exit sequence in every test | If a test fails to send shutdown, the thread hangs. Consider a test timeout wrapper. |
| Diagnostics published as notifications, not responses | LOW | HIGH | Read from client connection receiver, filter for PublishDiagnostics | This is expected - the plan handles it correctly. |
| `run_check()` needs real git repo for diff | MEDIUM | MEDIUM | Use synthetic diff via didChange notifications (bypasses git) | Phase 2-4 tests should use didChange to set changed_lines, avoiding git dependency. |
| Test flakiness from thread ordering | LOW | LOW | Use deterministic message ordering, timeouts | Connection::memory uses crossbeam channels which are well-behaved. |
| `findings_to_diagnostics` snapshot drift | LOW | LOW | Standard insta workflow | Already established in workspace. |
| Compilation time increase from testkit dependency | LOW | HIGH | Accept it; testkit is already compiled for other crates | Only impacts first build of diffguard-lsp tests. |

### Critical risk: Server lifecycle management in tests

The biggest risk is that `run_server` blocks until it receives an Exit notification. Each test must:
1. Create memory connection pair
2. Spawn server thread with server connection
3. Send initialize request, wait for response
4. Perform test actions
5. Send shutdown request, wait for response
6. Send exit notification
7. Join server thread

If any step fails mid-test, the server thread becomes a zombie. The plan should recommend a `drop` guard or RAII pattern that ensures shutdown/exit are always sent.

### Risk Verdict: LOW-MEDIUM RISK
No blockers identified. The main risk (thread lifecycle) is manageable with proper test infrastructure.

---

## 4. Resource Estimate Validation

### Phase breakdown

| Phase | Estimated | Assessment |
|-------|-----------|------------|
| Phase 1: Infrastructure | 2-3 hours | REALISTIC. Creating harness, helpers, adding dependencies. 2 hours is tight but possible for experienced developer. |
| Phase 2-5: Core tests | 4-6 hours | REALISTIC. ~20 tests at 15-20 min each including debugging. May stretch to 7 hours if diagnostic accuracy tests require config/fixture setup. |
| Phase 6: Code actions | (included above) | See note below |
| Phase 7: Edge cases | (included above) | See note below |
| Phase 8: Snapshots | 1-2 hours | REALISTIC. Snapshot tests are fast to write once infrastructure exists. |
| **Total** | **7-11 hours** | **REALISTIC with caveats** |

### Caveats

1. **The plan has 8 phases but the effort estimate only mentions Phases 1, 2-5, and 6.** The numbering is inconsistent (plan shows phases 1-8 but estimate references phases 1, 2-5, 6). This is a minor documentation issue.

2. **Concurrency test (Phase 7)** could add 1-2 hours if message ordering matters. Consider deferring to a follow-up PR.

3. **Git fallback test** requires `FixtureRepo` from testkit to create a temp git repo. If testkit integration has issues, this test could take longer.

4. **Buffer: Add 1-2 hours for unexpected issues** (e.g., connection lifecycle bugs, diagnostic message format surprises).

### Adjusted estimate: 8-13 hours

### Estimate Verdict: REALISTIC (with minor adjustment)

---

## 5. Additional Observations

### What the plan gets right

1. **Phased approach** is logical and reduces risk of overwhelming scope.
2. **Test file structure** mirrors the existing CLI integration test pattern.
3. **Snapshot tests for `findings_to_diagnostics`** aligns with workspace conventions.
4. **Explicit success criteria** are measurable and appropriate.

### What could be improved

1. **Fix the phase numbering in the effort estimate** (currently says "Phase 2-5" and "Phase 6" but the plan has 8 phases).
2. **Add `diffguard-testkit` to dev-dependencies** before implementation starts.
3. **Add RAII test helper** for server lifecycle (spawn + auto-shutdown on drop).
4. **Consider adding `didChangeConfiguration` test** since the server handles it.
5. **Clarify snapshot directory location** - match workspace convention (likely `tests/snapshots/`).

### What's missing from verification.md

The verification correctly identifies `Connection::memory()` exists but does not note that the LSP crate's Cargo.toml is missing the testkit dev-dependency needed to implement the plan.

---

## 6. Final Recommendation

### VERDICT: APPROVE WITH MINOR CORRECTIONS

The plan is well-structured, the approach is sound, and the scope is appropriate. The identified gaps are minor and can be addressed during implementation or as pre-implementation corrections.

### Required corrections before implementation

1. Add `diffguard-testkit = { path = "../diffguard-testkit" }` to `[dev-dependencies]` in `crates/diffguard-lsp/Cargo.toml`.
2. Fix phase numbering inconsistency in the effort estimate section.
3. Add `test_did_change_configuration_reloads` test case (Phase 2 or Phase 7).

### Recommended improvements (non-blocking)

1. Design an RAII test helper for server lifecycle management.
2. Add `byte_offset_at_position` and `utf16_length` unit tests to text.rs (separate PR is acceptable).
3. Clarify snapshot storage location.

**Confidence Level:** HIGH
**Risk Level:** LOW-MEDIUM
**Recommended Start:** Immediately after applying the 3 required corrections.
