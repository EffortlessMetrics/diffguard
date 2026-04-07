# Specs: VS Code Extension (LSP Client) v0.2.0

**Work ID**: work-ea424433
**Gate**: DESIGNED
**Applies to**: `editors/vscode-diffguard/`

---

## Acceptance Criteria

### AC-1: Extension activates on any file
Given a VS Code workspace with files open, the extension activates automatically
and starts the `diffguard-lsp` server.

### AC-2: Diagnostics appear in real-time
Given a file with diff content that triggers diffguard rules, the user sees
diagnostics (errors, warnings, info) as squiggly underlines in the editor without
running any manual command.

### AC-3: Code actions are available
Given a diagnostic from diffguard, the user can invoke Quick Fix (Ctrl+.) to see
code actions such as "Explain rule" and "Open documentation".

### AC-4: Config reload without restart
Given a running editor session, the user can execute the "diffguard: Reload Config"
command to re-evaluate all open files without restarting VS Code.

### AC-5: Binary not found shows clear error
Given that `diffguard-lsp` is not on PATH and `diffguard.serverPath` is not set,
the extension shows an error notification explaining how to install or configure
the binary.

### AC-6: Package installs without warnings
Given the extension directory, `npx vsce package` produces a `.vsix` file with no
errors about missing LICENSE, repository, or other required fields.

---

## MUST (Requirements)

### M-1: LSP Client Architecture
The extension MUST use `vscode-languageclient` v9 to connect to the `diffguard-lsp`
binary over stdio. It MUST NOT shell out to the `diffguard` CLI for its primary
operation.

### M-2: Binary Discovery Strategy
The extension MUST discover the `diffguard-lsp` binary using this priority:
1. User setting `diffguard.serverPath` (explicit path to binary)
2. Search PATH for `diffguard-lsp`

If neither succeeds, the extension MUST show an error notification with install
instructions.

### M-3: Initialization Options Mapping
The extension MUST pass VS Code settings to the LSP server as
`initializationOptions` with this exact mapping (matching the server's
`#[serde(rename_all = "camelCase")]`):

| VS Code Setting              | initOptions key   | Type     | Default |
|------------------------------|-------------------|----------|---------|
| `diffguard.configPath`       | `configPath`      | `string` | none    |
| `diffguard.noDefaultRules`   | `noDefaultRules`  | `bool`   | `false` |
| `diffguard.maxFindings`      | `maxFindings`     | `number` | none    |
| `diffguard.forceLanguage`    | `forceLanguage`   | `string` | none    |

### M-4: Lifecycle Management
The extension MUST properly dispose the `LanguageClient` in `deactivate()` to
prevent orphaned LSP child processes. The client MUST be pushed to
`context.subscriptions` so it is also disposed on reload.

### M-5: Manifest Requirements
`package.json` MUST contain:
- `"version": "0.2.0"` (matching workspace version)
- `"repository"` field pointing to `https://github.com/effortlessmetrics/diffguard`
- `"engines.vscode": "^1.85.0"` (compatible with vscode-languageclient v9)
- `contributes.configuration` section defining the 4 settings above
- `activationEvents` that trigger on file open (e.g., `"onStartupFinished"`)

### M-6: License File
The extension directory MUST contain a LICENSE file (copy of `LICENSE-MIT` from
workspace root or a combined MIT/Apache file) so that `vsce package` succeeds.

### M-7: vscode-languageclient v9 API
The extension MUST use the v9 `Executable` API pattern:

```js
const serverExecutable = {
  command: 'diffguard-lsp',
  args: [],
};
const serverOptions = {
  run: serverExecutable,
  debug: serverExecutable,
};
```

NOT the deprecated v8 `run`/`debug` binding pattern.

### M-8: Document Selectors
The extension MUST register the language client with a broad document selector
`{ scheme: 'file' }` since the LSP server is language-agnostic.

---

## SHOULD (Recommendations)

### S-1: Error Handling on Spawn Failure
The extension SHOULD catch spawn failures (ENOENT) and show a user-friendly
notification rather than silently failing.

### S-2: Output Channel Logging
The extension SHOULD create a "diffguard" output channel and log server lifecycle
events (started, stopped, error) for debugging.

### S-3: Preserve Legacy Command
The extension SHOULD keep the `diffguard.runCheck` command as a convenience for
one-shot checks (shelling out to the CLI). This is useful for CI-like workflows
within the editor and does not conflict with the LSP client.

### S-4: .vscodeignore Completeness
The `.vscodeignore` SHOULD exclude:
- `node_modules/`
- `.vscode/`
- `.gitignore`
- `*.vsix`
- Source-only files (tests, dev configs)

And include only:
- `extension.js` (or compiled output)
- `package.json`
- `README.md`
- `CHANGELOG.md`
- `LICENSE`

### S-5: CHANGELOG
A `CHANGELOG.md` SHOULD exist with at least a v0.2.0 entry noting the LSP client
rewrite.

### S-6: Dev Launch Config
`.vscode/launch.json` SHOULD exist for Extension Development Host debugging.

---

## WON'T (Out of Scope)

### W-1: No TypeScript Conversion
The extension WON'T be converted to TypeScript in this work. Plain JavaScript is
acceptable for v0.2.0. TypeScript conversion is a future enhancement.

### W-2: No Binary Bundling
The extension WON'T bundle the `diffguard-lsp` binary in the `.vsix` package.
Users must install the binary separately (via `cargo install`, GitHub releases,
or package managers). Cross-platform binary distribution is out of scope.

### W-3: No Extension-side Rule Engine
The extension WON'T implement any rule evaluation logic. All analysis is delegated
to the LSP server. The extension is purely a transport + UI adapter.

### W-4: No Telemetry
The extension WON'T collect or transmit telemetry data.

### W-5: No Pre-release Channel
The extension WON'T publish a pre-release version. v0.2.0 is a standard release.

### W-6: No Multi-root Workspace Support Beyond LSP
The LSP server already handles workspace folders correctly. The extension WON'T add
additional multi-root logic beyond passing the workspace to the server.

---

## File Inventory

### Files to Create
- `editors/vscode-diffguard/LICENSE` (copy of workspace LICENSE-MIT)
- `editors/vscode-diffguard/.vscodeignore`
- `editors/vscode-diffguard/CHANGELOG.md`
- `editors/vscode-diffguard/.vscode/launch.json`
- `editors/vscode-diffguard/.vscode/tasks.json`
- `editors/vscode-diffguard/package-lock.json` (generated by npm)

### Files to Modify
- `editors/vscode-diffguard/extension.js` (full rewrite as LSP client)
- `editors/vscode-diffguard/package.json` (version bump, deps, settings, activation)
- `editors/vscode-diffguard/README.md` (update for LSP features)

### Files to Generate
- `editors/vscode-diffguard/*.vsix` (via `npx vsce package`)

---

## Verification

After implementation, verify:

1. `cd editors/vscode-diffguard && npm install` succeeds
2. `npx vsce package` produces a `.vsix` without errors
3. The `.vsix` contains: extension.js, package.json, README.md, CHANGELOG.md, LICENSE
4. The `.vsix` does NOT contain: node_modules/, .vscode/, .gitignore
5. Extension Development Host launches without errors
6. With `diffguard-lsp` on PATH: diagnostics appear on files
7. Without `diffguard-lsp`: error notification is shown
8. `diffguard.reloadConfig` command executes without error
