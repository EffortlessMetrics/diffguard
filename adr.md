# ADR-057: Observability Infrastructure for diffguard-lsp

## Status
Proposed

## Context

The `diffguard-lsp` crate is a long-running LSP server process that handles user files and spawns `git diff` subprocesses. When it crashes, hangs, or produces incorrect diagnostics, there is no way to inspect its internal state — the crate has zero `tracing`, `log::`, `debug!`, `info!`, `warn!`, `error!`, `println!`, or `eprintln!` calls. All errors surface only as LSP `showMessage` notifications to the user and are never recorded.

The main `diffguard` binary already uses `tracing = "0.1"` and `tracing-subscriber = { version = "0.3", features = ["env-filter"] }` but these are direct dependencies of the binary crate, not promoted to workspace level — making them inaccessible to the LSP crate without first adding them to `[workspace.dependencies]`.

Additionally, the `--verbose` CLI flag approach described in the initial plan is unreliable for the primary use case: LSP servers are started by editors (VSCode, Neovim, etc.), not directly by users. There is no standard mechanism for users to pass CLI arguments to editor-started LSP servers. The `RUST_LOG` environment variable is the actual production debugging mechanism.

## Decision

We will add structured observability to `diffguard-lsp` using the `tracing` ecosystem with the following specifics:

### 1. Promote `tracing` to workspace dependency

Add `tracing = "0.1"` and `tracing-subscriber = { version = "0.3", features = ["env-filter"] }` to `[workspace.dependencies]` in the root `Cargo.toml`. This makes them available to all workspace crates via `tracing.workspace = true`. The LSP crate will use these workspace-managed versions.

### 2. Use `RUST_LOG` as the primary debugging mechanism

The `tracing_subscriber::EnvFilter` will read from the `RUST_LOG` environment variable at startup. This is the standard, editor-agnostic way to enable debug output for LSP servers — users set `RUST_LOG=diffguard_lsp=debug` in their shell environment before starting their editor.

### 3. `--verbose` as a convenience alias (not the primary mechanism)

A `--verbose` flag will be added to `main.rs` for local development and testing convenience. It will be implemented as a wrapper that sets `RUST_LOG=debug` internally, not as a special logging mode. This flag is intentionally limited: it cannot help users debugging an editor-started LSP server.

### 4. All tracing output goes to stderr

The LSP protocol uses stdout/stdin for the message loop. `tracing_subscriber::fmt()` will be configured to write exclusively to stderr, ensuring the protocol stream is never corrupted.

### 5. Default filter: ERROR (silent in production)

When `RUST_LOG` is not set, the default filter is `error` — ensuring zero trace output in normal production use. Users must explicitly opt-in to logging.

### 6. Hot-path discipline: `trace!` in `refresh_document_diagnostics`

`refresh_document_diagnostics()` fires on every keystroke. Using `tracing::debug!` on this hot path has measurable overhead. Instead, we use `tracing::trace!` (level 1, not level 2) so that even trace-level output has near-zero cost when disabled, while still being available at full verbosity when `RUST_LOG` permits.

Functions that fire less frequently (`run_git_diff`, `reload_config`, `git_diff_for_path`) use `tracing::debug!`.

### 7. `showMessage` calls become trace events too

Every existing LSP `showMessage` call will gain a corresponding `tracing::warn!` or `tracing::error!` call (depending on severity) so these events are captured in logs even when a user dismisses the on-screen notification.

### 8. Module-level span context

Key server operations will be instrumented with `tracing::info_span!` or `tracing::debug_span!` to provide structured context (file path, method name, etc.) around trace events.

## Consequences

### Benefits
- **Debuggability**: When the LSP crashes or misbehaves, users can set `RUST_LOG=diffguard_lsp=debug` and reproduce the issue, capturing a trace of exactly what happened.
- **No breaking changes**: stdout is unchanged, the LSP protocol is unaffected, all existing behavior is preserved.
- **Consistency**: Uses the same `tracing` ecosystem as the main `diffguard` binary.
- **Zero cost when disabled**: The `tracing` filter check is a fast path; when filtered to ERROR, instrumentation has no measurable overhead.

### Tradeoffs
- **Dependency addition**: `tracing-subscriber` with `env-filter` pulls in `regex`, increasing compile time and binary size slightly. However, the main `diffguard` binary already uses this, so the size cost is already paid for users with the full workspace installed.
- **`--verbose` is limited**: This flag only works for manual LSP invocation, not editor-started servers. Users must use `RUST_LOG` for real production debugging.
- **`build_synthetic_diff` out of scope for internal instrumentation**: Silent failure detection happens at call sites, not inside the hot utility functions themselves.

## Alternatives Considered

### Alternative 1: Use `log` crate instead of `tracing`
Rejected because `tracing` is already used by the main `diffguard` binary, and `tracing` provides structured spans with field information (`tracing::info!(path = %path, "...")`) rather than just formatted strings. Spans are more inspectable and composable.

### Alternative 2: Add only `--verbose` without `RUST_LOG`
Rejected because `--verbose` is unreachable for the primary use case (editor-started LSP servers). This would give the impression of debuggability without actual utility. `RUST_LOG` is the industry-standard mechanism and must be the primary interface.

### Alternative 3: Write to a log file instead of stderr
Rejected because LSP servers are stdio-based processes managed by editors. Writing to a file requires filesystem access permissions, temp file management, and introduces latency. stderr is the correct destination for LSP server diagnostic output.

### Alternative 4: Use `debug!` in `refresh_document_diagnostics` from the start
Rejected because this function fires on every keystroke. Even with filtering, the filter check itself has cost at that frequency. `trace!` level is more appropriate for the hottest paths; `debug!` is reserved for operations that don't fire on every keystroke.
