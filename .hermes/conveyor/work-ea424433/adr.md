# ADR-001: Rewrite VS Code Extension as LSP Client

**Date**: 2026-04-06
**Status**: Accepted
**Work ID**: work-ea424433
**Gate**: DESIGNED

## Decision

Replace the existing shell-exec VS Code extension at `editors/vscode-diffguard/` with a
proper Language Server Protocol (LSP) client that connects to the `diffguard-lsp` binary
over stdio. Package the extension for VS Code Marketplace publishing as v0.2.0.

### Key architectural choices:

1. **LSP client over stdio**: The extension will spawn `diffguard-lsp` as a child process
   and communicate via `vscode-languageclient` v9. This replaces the current approach of
   shelling out to `diffguard check --staged` via `child_process.execFile`.

2. **Binary discovery via setting + PATH fallback**: Users can set
   `diffguard.serverPath` in VS Code settings to point to the `diffguard-lsp` binary.
   If unset, the extension looks for `diffguard-lsp` on PATH. A clear error message
   is shown if the binary cannot be found.

3. **Plain JavaScript (no TypeScript)**: The extension stays with plain JS for v0.2.0.
   TypeScript conversion is deferred to a follow-up.

4. **Broad document selectors**: Register for all file types (`{ scheme: 'file' }`)
   since the LSP server is language-agnostic (it operates on diffs, not specific
   programming languages).

5. **Initialization options mapping**: VS Code settings under `diffguard.*` are passed
   to the LSP server as `initializationOptions` using camelCase keys matching the
   server's `InitOptions` struct:
   - `diffguard.configPath` -> `configPath`
   - `diffguard.noDefaultRules` -> `noDefaultRules`
   - `diffguard.maxFindings` -> `maxFindings`
   - `diffguard.forceLanguage` -> `forceLanguage`

6. **Proper lifecycle management**: The `deactivate()` function disposes the
   `LanguageClient` to prevent orphaned LSP child processes.

## Context

### Problem

The current VS Code extension (`editors/vscode-diffguard/`) is a shell-exec stub that
runs `diffguard check --staged` via `child_process.execFile` and parses a JSON report
from a temp file. It provides no real-time diagnostics, no code actions, and no
editor integration beyond a one-shot command.

Meanwhile, a fully-tested LSP server exists at `crates/diffguard-lsp/` (49/49 tests
passing) that provides:

- Real-time diagnostics via `textDocument/publishDiagnostics` (full document sync)
- Code actions for inline suppressions and rule explanations
- Execute commands: `diffguard.explainRule`, `diffguard.reloadConfig`,
  `diffguard.showRuleUrl`
- Configuration-aware rule evaluation with auto-reload

The extension should be a consumer of the LSP server, not an independent CLI wrapper.

### Background

- The workspace version is `0.2.0` (Cargo.toml), but the extension is at `0.1.0`
- The extension has zero npm dependencies, no build pipeline, no `.vscodeignore`
- The publisher is `effortlessmetrics` (already set in extension package.json)
- License: `MIT OR Apache-2.0` (but no LICENSE file in the extension directory)
- The LSP server communicates over stdio via the `lsp-server` crate
- The LSP server's `InitOptions` uses `#[serde(rename_all = "camelCase")]`

### Why now

The LSP server is production-ready (49 passing tests, all capabilities implemented).
The extension stub was always a placeholder. Shipping a proper LSP-client extension
completes the IDE integration story the project already advertises in its README.

## Consequences

### Positive

1. **Real-time diagnostics**: Users get inline error/warning markers as they edit,
   not just on-demand shell checks.
2. **Code actions**: Quick-fix actions for rule explanations and suppression guidance
   appear directly in the editor.
3. **Config reload**: Users can trigger `diffguard.reloadConfig` without restarting
   the editor.
4. **Consistent with project architecture**: The extension composes with the existing
   LSP primitive rather than duplicating logic.
5. **Marketplace distribution**: The extension can be installed from the VS Code
   Marketplace with `vsce publish`.

### Negative

1. **Binary distribution gap**: The `diffguard-lsp` binary must be built for each
   platform (linux, mac, windows) and installed separately. The extension does NOT
   bundle the binary. Users must install it via `cargo install diffguard-lsp` or
   download from GitHub releases.
2. **Plain JS limits scalability**: Without TypeScript, the extension has no
   compile-time type checking. This is acceptable for v0.2.0 but should be revisited
   if the extension grows.
3. **License file duplication**: A LICENSE file must be added to the extension
   directory for `vsce package` to succeed.

### Risks

1. **Binary not found**: Mitigated by the `diffguard.serverPath` setting and a clear
   error notification.
2. **LSP protocol compatibility**: The `lsp-types` version (0.97) in the server is
   compatible with `vscode-languageclient` v9. LSP is backward-compatible.
3. **Publisher access**: Need to verify that the `effortlessmetrics` publisher account
   has API tokens for `vsce publish`. Cannot be resolved by this task alone.

## Implementation Plan (7 Steps)

1. **Init npm + add deps**: `npm init` in `editors/vscode-diffguard/`, add
   `vscode-languageclient` (dependency), `@vscode/vsce` (devDependency)
2. **Rewrite extension.js as LSP client**: New `extension.js` using
   `LanguageClient` from `vscode-languageclient` v9 `Executable` API
3. **Update manifest**: Bump to v0.2.0, add settings contributions, activation events,
   repository field, engine compatibility
4. **Add .vscodeignore**: Exclude node_modules, .vsix, tests from package
5. **Add dev config**: `.vscode/launch.json` and `.vscode/tasks.json`
6. **Add marketplace metadata**: CHANGELOG.md, update README, add LICENSE
7. **Package and validate**: `npx vsce package`, verify .vsix contents

## References

- Research: `research_analysis.md`
- Initial plan: `initial_plan.md`
- Plan review: `plan_review.md` (APPROVED WITH CONDITIONS)
- Verification: `verification_comment.md`
- Vision: `vision_comment.md`
- LSP server: `crates/diffguard-lsp/`
- Extension: `editors/vscode-diffguard/`
