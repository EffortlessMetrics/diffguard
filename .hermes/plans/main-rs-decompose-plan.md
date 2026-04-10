# Plan: Decompose main.rs CLI Commands

## Goal

Split the oversized `cmd_check_inner` (465 lines) and `cmd_test` (126 lines) functions in `diffguard/src/main.rs` into focused sub-modules, following the existing architecture patterns in the codebase.

## Issue
- **#122**: `cmd_check_inner` is 465 lines — should be decomposed
- **#123**: `cmd_test` is 126 lines — should be decomposed

## Current Context

- `main.rs` is the CLI entry point (~5500 lines)
- PR #5 added multi-base CLI support, env-var expansion, extended arg parsing
- The `cmd_check_inner` function handles the core check workflow; `cmd_test` handles the test subcommand
- The codebase already uses module decomposition (e.g., `overrides.rs`, `preprocess.rs` in domain crate)

## Proposed Approach

### Architecture Pattern
Extract each command handler into its own module under `diffguard/src/cmd/`:

```
diffguard/src/cmd/
├── mod.rs          # Re-exports
├── check.rs        # cmd_check_inner + helpers
├── test.rs         # cmd_test + helpers
└── doctor.rs       # Existing cmd_doctor pattern to follow
```

### Step-by-Step Plan

1. **Create module skeleton**: Create `diffguard/src/cmd/` directory with `mod.rs`, `check.rs`, `test.rs`
2. **Extract cmd_test**: Move `cmd_test` function to `cmd/test.rs` — 126 lines is straightforward
3. **Extract cmd_check_inner**: This is the larger task (465 lines):
   - Identify logical sections within `cmd_check_inner` (arg handling, git fetching, config loading, diff execution, output rendering)
   - Extract each section as a helper function in `cmd/check.rs`
   - Keep `cmd_check_inner` as a thin orchestrator
4. **Wire into main.rs**: Update `main.rs` to call into `cmd::check::run()` and `cmd::test::run()`
5. **Update Cargo.toml**: Add `mod cmd;` to lib.rs/main.rs
6. **Run tests**: Ensure `cargo test --workspace` and `cargo clippy` still pass

## Files Likely to Change

| File | Change |
|------|--------|
| `diffguard/src/main.rs` | Remove extracted functions, import from `cmd` module |
| `diffguard/src/cmd/mod.rs` | New module entry |
| `diffguard/src/cmd/check.rs` | Extracted `cmd_check_inner` + helpers |
| `diffguard/src/cmd/test.rs` | Extracted `cmd_test` |
| `diffguard/src/lib.rs` | Add `mod cmd` if needed |

## Tests / Validation

1. All existing CLI integration tests pass (`cargo test -p diffguard`)
2. `cargo clippy --workspace -- -D warnings` clean
3. Manual verification: `diffguard check --help`, `diffguard test --help` work correctly

## Risks and Tradeoffs

- **Risk**: Extracting functions that share complex implicit state (via closures or captured variables) could make refactoring difficult. May need to thread arguments explicitly.
- **Mitigation**: Start with `cmd_test` (126 lines, simpler) as a trial run before tackling 465-line `cmd_check_inner`.
- **Tradeoff**: This is pure refactoring — no behavior change. Low risk, moderate effort.

## Open Questions

1. Should error handling (e.g., `anyhow` usage) be centralized in the `cmd` module, or stay per-function?
2. Should we also look at other large functions in `main.rs` while we're decomposing (e.g., `cmd_doctor` if it grows)?
