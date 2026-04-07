# Deep Review: diffguard-vscode Extension

**Reviewer**: deep-review-agent
**Work ID**: work-ea424433
**Gate**: HARDENED
**Date**: 2026-04-06

## Summary

The VS Code extension is well-structured and the LSP protocol integration is correctly implemented. I found several minor issues but no critical blockers.

## Security Analysis

### PASS: No command injection risks
- The extension does NOT use `shell: true` in the LanguageClient serverOptions. The `serverPath` from user config is passed directly as the command binary path to the client library, which spawns it via `child_process.spawn`. Arguments are passed as a separate array, not concatenated into a shell string. This is safe.

### PASS: No path traversal from the extension side
- `serverPath` is used only as the binary path for spawning. `configPath` is passed as an initialization option string to the server, which resolves it server-side with proper path validation.

### PASS: Server-side path handling is correct
- In `server.rs`, `uri_to_file_path` uses `url::Url::parse` followed by `.to_file_path()`, which is the standard safe way to convert file URIs.
- `resolve_config_path` in `config.rs` handles both absolute and relative paths, joining relative paths to the workspace root.

### NOTE: No sanitization of `forceLanguage` in init options
- The `forceLanguage` setting is passed verbatim to the server as an initialization option. The server normalizes it by trimming whitespace. This is acceptable since it's only used as a configuration parameter, not executed or injected anywhere.

## Error Handling Analysis

### PASS: Extension error handling
- `extension.js` line 39-46: The `client.start()` promise rejection is caught and a user-friendly error message is shown for ENOENT/not-found errors. Other errors are silently swallowed.

### MINOR ISSUE: Silent error swallowing for non-ENOENT errors
- If the LSP server crashes for reasons other than "not found" (e.g., permission denied, segfault), the user sees no feedback. Consider adding a generic fallback error message or logging the full error.

### PASS: Server-side error handling
- The server handles parse errors for all notification and request types gracefully, showing warning messages to the user instead of crashing.
- Config loading errors fall back to built-in rules with a warning message.
- Git diff failures are caught and the server falls back to in-memory change tracking.
- Document analysis errors clear diagnostics rather than crashing.

## LSP Protocol Compatibility

### PASS: Text document sync
- Extension: Does not specify `synchronize.textDocument` (not needed; the LSP client handles didOpen/didChange/didClose automatically based on server capabilities).
- Server: Declares `TextDocumentSyncKind::FULL` and handles DidOpen, DidChange, DidSave, DidClose notifications.
- COMPATIBLE: The VS Code language client sends full text on each change when server declares FULL sync.

### PASS: Configuration synchronization
- Extension: `synchronize.configurationSection: "diffguard"` -- this tells the client to send `didChangeConfiguration` notifications when the `diffguard` settings change.
- Server: Handles `DidChangeConfiguration` notification and reloads config. COMPATIBLE.

### PASS: Initialization options
- Extension sends `configPath`, `noDefaultRules`, `maxFindings`, `forceLanguage` via `initializationOptions`.
- Server's `InitOptions` struct (line 99-106 of server.rs) has matching fields with `#[serde(default, rename_all = "camelCase")]`.
- COMPATIBLE: camelCase serialization matches.

### PASS: Command registration
- Extension declares commands: `diffguard.explainRule`, `diffguard.reloadConfig`, `diffguard.showRuleUrl` in `contributes.commands`.
- Server registers identical command names in `execute_command_provider.commands`.
- The extension does NOT register VS Code command handlers (no `context.subscriptions.push(vscode.commands.registerCommand(...))`). This is correct because these commands are invoked via LSP code actions (server-side) and executed via the `workspace/executeCommand` LSP request. When the server sends an `executeCommand` request, VS Code routes it to the LSP client which forwards it to the server.

### PASS: Code action provider
- Server declares `code_action_provider: Some(CodeActionProviderCapability::Simple(true))` and handles `textDocument/codeAction` requests.
- The extension does not need to do anything special for code actions -- the LSP client handles this automatically.

## Package Quality (Marketplace Readiness)

### ISSUES TO ADDRESS:

1. **Missing `.vscodeignore` for `node_modules`**: The `.vscodeignore` file excludes `node_modules/.cache/` but NOT the `node_modules/` directory itself. When packaging with `vsce`, the `node_modules/vscode-languageclient` tree will be included, which is necessary for runtime. However, the `vscode-languageclient` dependency pulls in transitive dependencies that bloat the package. The standard approach is to use `esbuild` or `webpack` to bundle the extension into a single file, then exclude `node_modules/` entirely.

2. **No icon**: The marketplace listing would benefit from an icon. Not a blocker but a quality concern.

3. **No `repository` field matches actual GitHub URL**: The `repository.url` is `https://github.com/effortlessmetrics/diffguard` -- verify this is correct.

4. **`onStartupFinished` activation event**: This is fine and appropriate for a language server extension -- it activates after all other startup work is done.

## Documentation Accuracy

### PASS: README matches functionality
- README documents all 5 settings that match `package.json` `contributes.configuration` properties.
- README documents all 3 commands that match `package.json` `contributes.commands`.
- Requirements section correctly states the need for `diffguard-lsp` binary.

### PASS: CHANGELOG is consistent
- CHANGELOG accurately describes the 0.2.0 changes, which match the actual implementation.
- CHANGELOG mentions the old `diffguard.runCheck` command in 0.1.0, which is no longer present -- consistent with the switch to LSP.

## Edge Cases

### 1. Spurious `--stdio` argument
The extension passes `args: ["--stdio"]` to the server (extension.js line 15). However, the server's `main.rs` does NOT parse any command-line arguments -- it always uses `Connection::stdio()`. This means `--stdio` is passed as an unrecognized argument that is silently ignored. While harmless, it could confuse future maintainers.

**Recommendation**: Either remove the argument from the extension, or add argument parsing to the server's main.rs for clarity (even if `--stdio` is the only option and is the default).

### 2. Document URI conversion with non-file schemes
The server calls `uri_to_file_path` on document URIs (server.rs line 501). If a document has a non-file URI scheme (e.g., `untitled:` for new unsaved files), `to_file_path()` returns `None` and the document is silently ignored. This means DiffGuard will not analyze untitled files. This is likely intentional behavior but should be documented.

### 3. maxFindings edge case
The server enforces `max_findings` with `.max(1)` (server.rs line 129), so even if a user sets `maxFindings: 0` in settings, it becomes 1. This is correct defensive coding.

### 4. Full document sync vs. large files
The server uses `TextDocumentSyncKind::FULL`, meaning the entire document text is sent on every change. For very large files, this could cause performance issues. The server handles this correctly (it processes the full text each time), but it's worth noting for future optimization.

## Findings Summary

| Category | Severity | Count |
|----------|----------|-------|
| Critical | 0 | None |
| Security | 0 | None |
| Minor | 2 | Silent error swallowing, spurious --stdio arg |
| Quality | 2 | No bundling, no icon |
| Info | 2 | Untitled files ignored, FULL sync perf note |

## Verdict

**APPROVED** with minor notes. No security issues, no protocol incompatibilities, no blocking bugs. The extension correctly implements the LSP client for diffguard-lsp and the server-side protocol handling is solid. The minor issues identified are cosmetic or optimization concerns that do not affect correctness or security.
