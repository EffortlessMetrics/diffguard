# Task List — work-121a7571: Observability Infrastructure for diffguard-lsp

## Phase 1: Infrastructure (prerequisites)
- [ ] Add `tracing = "0.1"` and `tracing-subscriber = { version = "0.3", features = ["env-filter"] }` to `[workspace.dependencies]` in root `Cargo.toml`
- [ ] Add `tracing.workspace = true` and `tracing-subscriber.workspace = true` to `diffguard-lsp/Cargo.toml`
- [ ] Add `clap` argument parsing to `main.rs` — `--verbose` flag processed before `Connection::stdio()`
- [ ] Initialize `tracing_subscriber::fmt()` with `EnvFilter`, stderr writer, default level `error`

## Phase 2: Core Instrumentation
- [ ] Instrument `run_git_diff()` with `tracing::debug!` — path, staged flag, timeout, stdout length on success, error+stderr on failure
- [ ] Instrument `refresh_document_diagnostics()` with `tracing::trace!` — path, diff type, diagnostic count
- [ ] Instrument `reload_config()` with `tracing::info!` (success) and `tracing::warn!` (failure) — config path, rule count
- [ ] Wrap all `showMessage` calls in `server.rs` with corresponding `tracing::warn!` or `tracing::error!`

## Phase 3: Supporting Instrumentation
- [ ] Instrument `git_diff_for_path()` with `tracing::debug!` — staged vs unstaged, result length
- [ ] Instrument `load_effective_config()` in `config.rs` with `tracing::debug!` — config path, rule count, built-in usage
- [ ] Instrument `load_directory_overrides_for_file()` in `config.rs` with `tracing::debug!` — override count, files read
- [ ] Instrument `handle_notification()` and `handle_request()` with `tracing::trace!` — LSP method name as field

## Phase 4: Verification
- [ ] Run `cargo test -p diffguard-lsp` — all tests pass
- [ ] Manual verification: `RUST_LOG=diffguard_lsp=debug diffguard-lsp` shows startup trace on stderr
- [ ] Manual verification: `diffguard-lsp --verbose` shows startup trace on stderr (same output as RUST_LOG variant)
