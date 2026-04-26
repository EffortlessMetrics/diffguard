# Spec: Observability Infrastructure for diffguard-lsp

## Feature Description

Add structured logging and debug output to the `diffguard-lsp` crate using the `tracing` ecosystem. The goal is to make the LSP server debuggable when it crashes, hangs, or produces incorrect diagnostics — without changing its behavior or breaking the LSP protocol.

## Non-Goals

- This does NOT add a persistent log file. All tracing output goes to stderr.
- This does NOT change LSP protocol behavior, message formats, or on-screen notifications.
- This does NOT instrument the hot internal utilities `build_synthetic_diff` and `changed_lines_between` — silent failure detection happens at their call sites only.
- This does NOT guarantee `--verbose` works for editor-started LSP servers — `RUST_LOG` env var is the production debugging interface.

## Dependencies

### Required workspace change
Before any LSP crate changes, `tracing` must be promoted to a workspace dependency:

```toml
# Cargo.toml (workspace)
[workspace.dependencies]
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

This is a prerequisite for all subsequent implementation.

## Acceptance Criteria

### AC-1: Workspace dependencies are updated
`tracing = "0.1"` and `tracing-subscriber` with `env-filter` feature are present in `[workspace.dependencies]` in the root `Cargo.toml`.

### AC-2: LSP crate uses workspace tracing
`diffguard-lsp/Cargo.toml` has:
```toml
tracing.workspace = true
tracing-subscriber.workspace = true
```

### AC-3: `RUST_LOG` controls logging at runtime
Setting `RUST_LOG=diffguard_lsp=debug` before starting the LSP produces debug-level trace output on stderr. Without `RUST_LOG`, no trace output is produced (default filter is `error`).

### AC-4: `--verbose` flag sets `RUST_LOG=debug` for local testing
`diffguard-lsp --verbose` on the command line enables `RUST_LOG=debug`-equivalent logging without needing to set the env var. This is for local development and CI testing only.

### AC-5: `run_git_diff` emits trace events
On each invocation, `run_git_diff` traces at `debug` level: the path, whether it's staged, and the timeout. On success, traces the stdout length. On failure, traces the full error and any stderr content.

### AC-6: `refresh_document_diagnostics` emits trace events
Traces at `trace` level (not `debug`, due to hot path): the file path, whether synthetic or git diff was used, and the count of diagnostics published. On error, traces the error message.

### AC-7: `reload_config` emits trace events
Traces at `info` level on success (config path, rule count) and `warn` level on failure (error message).

### AC-8: All `showMessage` calls emit trace events
Every existing `showMessage` call to the user also emits a corresponding `tracing::warn!` or `tracing::error!` with the same message content, so events are captured in logs even after the user dismisses the on-screen notification.

### AC-9: LSP protocol is unaffected
All tracing output goes to stderr only. The stdio connection between LSP server and client is never written to by tracing code.

### AC-10: Existing tests pass
`cargo test -p diffguard-lsp` passes with the new instrumentation code in place.

## Implementation Notes

### Phase 1: Infrastructure
1. Add `tracing` and `tracing-subscriber` to `[workspace.dependencies]` in root `Cargo.toml`
2. Add `tracing` and `tracing-subscriber` to `diffguard-lsp/Cargo.toml` with `workspace = true`
3. Add `clap` argument parsing to `main.rs` — `--verbose` flag before `Connection::stdio()`
4. Initialize `tracing_subscriber::fmt()` with `EnvFilter`, writing to stderr, with `ERROR` as default level

### Phase 2: Core Instrumentation
5. Add `tracing::debug!` to `run_git_diff()` — path, staged, timeout, stdout length on success, error on failure
6. Add `tracing::trace!` to `refresh_document_diagnostics()` — path, diff type, diagnostic count
7. Add `tracing::info!`/`tracing::warn!` to `reload_config()` — success with rule count, failure with error
8. Add trace wrapper to all `showMessage` calls in `server.rs`

### Phase 3: Supporting Instrumentation
9. Add `tracing::debug!` to `git_diff_for_path()` — diff type (staged/unstaged), result length
10. Add `tracing::debug!` to `load_effective_config()` in `config.rs` — config path, rule count, built-in usage
11. Add `tracing::debug!` to `load_directory_overrides_for_file()` in `config.rs` — override count, files read
12. Add `tracing::trace!` to `handle_notification()` and `handle_request()` — method name as field

### Phase 4: Verification
13. Run `cargo test -p diffguard-lsp` to confirm all tests pass
14. Manual verification: run `RUST_LOG=diffguard_lsp=debug diffguard-lsp` and confirm stderr shows startup trace
