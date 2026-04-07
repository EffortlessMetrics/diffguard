# Task List: Ship VS Code Extension to Marketplace

**Work ID**: work-ea424433
**Gate**: DESIGNED -> EXECUTABLE

## Task 1: Initialize npm project and add dependencies

**What to do**:
- Run `npm init -y` in `editors/vscode-diffguard/` to create `package.json` with npm metadata
- Install `vscode-languageclient@^9` as a runtime dependency
- Install `@vscode/vsce` as a devDependency
- Add `package-lock.json`

**Files to touch**:
- `editors/vscode-diffguard/package.json` (created by npm init, then modified)
- `editors/vscode-diffguard/package-lock.json` (created by npm install)

**Success criteria**:
- `package.json` exists with `vscode-languageclient` in `dependencies` and `@vscode/vsce` in `devDependencies`
- `package-lock.json` exists and is parseable
- `npm ls --production` shows no errors

**Dependencies**: None (first task)

---

## Task 2: Rewrite extension.js as an LSP client

**What to do**:
- Replace the entire `extension.js` with a `vscode-languageclient` LSP client that:
  - Reads `diffguard.serverPath` from VS Code config, falls back to `"diffguard-lsp"` (relies on PATH)
  - Creates `LanguageClient` using v9 `Executable` API with command + args (empty), transport `stdio`
  - Sets `documentSelector` to `[{ scheme: 'file' }]` (language-agnostic, LSP server handles detection)
  - Sets `synchronize.configurationSection` to `"diffguard"`
  - Maps VS Code config settings to `initializationOptions` object with camelCase keys: `configPath`, `noDefaultRules`, `maxFindings`, `forceLanguage`
  - Shows an error notification if the server binary cannot be found (wrap `client.start()` in try/catch)
  - Disposes the client in `deactivate()` (store client ref at module level, call `client.dispose()` in deactivate)
  - Pushes client into `context.subscriptions` for cleanup on extension deactivate

**Files to touch**:
- `editors/vscode-diffguard/extension.js` (complete rewrite)

**Success criteria**:
- `extension.js` exports `activate(context)` and `deactivate()` functions
- `activate` creates a `LanguageClient` with `ServerOptions` using `Executable` API (v9), not the old `run`/`debug` pattern
- `deactivate()` calls `client.stop()` or `client.dispose()` (no-op if client never started)
- `initializationOptions` object uses camelCase keys matching LSP server `InitOptions` struct: `configPath`, `noDefaultRules`, `maxFindings`, `forceLanguage`
- Binary discovery uses `config.get('diffguard.serverPath')` with fallback to `'diffguard-lsp'`

**Dependencies**: Task 1

---

## Task 3: Update package.json manifest

**What to do**:
- Bump `version` from `0.1.0` to `0.2.0` (match workspace)
- Add `repository` field: `"type": "git"`, `"url": "https://github.com/effortlessmetrics/diffguard"`
- Update `engines.vscode` to `^1.85.0` (already correct, keep it)
- Replace `activationEvents` with `"onStartupFinished"` (LSP server is language-agnostic, activate on any workspace)
- Replace `contributes.commands` with LSP-aware commands: `diffguard.explainRule`, `diffguard.reloadConfig`, `diffguard.showRuleUrl`
- Add `contributes.configuration` section with properties:
  - `diffguard.serverPath` (string, default `""`, description: "Path to diffguard-lsp binary. Leave empty to search PATH.")
  - `diffguard.configPath` (string, default `""`, description: "Path to diffguard.toml config file.")
  - `diffguard.noDefaultRules` (boolean, default `false`)
  - `diffguard.maxFindings` (number, default `200`, minimum `1`)
  - `diffguard.forceLanguage` (string, default `""`)
- Update `main` field if needed (should still be `./extension.js`)
- Update `description` to mention LSP features

**Files to touch**:
- `editors/vscode-diffguard/package.json`

**Success criteria**:
- `version` is `0.2.0`
- `repository` field present with GitHub URL
- `activationEvents` includes `"onStartupFinished"`
- `contributes.configuration` has all 5 properties with correct types and defaults
- `contributes.commands` has all 3 LSP commands (`explainRule`, `reloadConfig`, `showRuleUrl`)
- `npm ls` still passes (no broken deps)

**Dependencies**: Task 2 (need to know final command names and config surface)

---

## Task 4: Add LICENSE file to extension directory

**What to do**:
- Copy `LICENSE-MIT` from workspace root to `editors/vscode-diffguard/LICENSE`
- This satisfies `vsce package` requirement for a LICENSE file in the extension directory

**Files to touch**:
- `editors/vscode-diffguard/LICENSE` (copied from `/home/hermes/repos/diffguard/LICENSE-MIT`)

**Success criteria**:
- `editors/vscode-diffguard/LICENSE` exists and contains the MIT license text
- `npx vsce package` does not warn about missing LICENSE (verified in Task 7)

**Dependencies**: None (can be done in parallel with Tasks 1-3)

---

## Task 5: Create .vscodeignore

**What to do**:
- Create `editors/vscode-diffguard/.vscodeignore` that excludes source/dev files from the `.vsix` package
- Include: `extension.js`, `package.json`, `README.md`, `CHANGELOG.md`, `LICENSE`, `node_modules/` (runtime deps only)
- Exclude: `.vscode/`, `.vsix`, `.gitignore`, `src/` (if any), test files, `*.ts`, `tsconfig.json`

**Files to touch**:
- `editors/vscode-diffguard/.vscodeignore` (new file)

**Sample content**:
```
.vscode/
.vscodeignore
.gitignore
**/*.map
**/*.ts
node_modules/.cache/
```

**Success criteria**:
- `.vscodeignore` exists
- `npx vsce ls` (dry-run listing) shows only the necessary files: extension.js, package.json, README.md, CHANGELOG.md, LICENSE, and node_modules (vscode-languageclient)

**Dependencies**: Tasks 1-3 (need final file layout)

---

## Task 6: Add dev launch configuration

**What to do**:
- Create `editors/vscode-diffguard/.vscode/launch.json` for Extension Development Host debugging
  - Config: "Launch Extension" -- type `extensionHost`, request `launch`, args `["--extensionDevelopmentPath=${workspaceFolder}/editors/vscode-diffguard"]`
  - Pre-launch task: build LSP server
- Create `editors/vscode-diffguard/.vscode/tasks.json` with a task to build the LSP server binary
  - Task: "Build diffguard-lsp" -- command `cargo build -p diffguard-lsp`, type `shell`, group `build`

**Files to touch**:
- `editors/vscode-diffguard/.vscode/launch.json` (new)
- `editors/vscode-diffguard/.vscode/tasks.json` (new)

**Success criteria**:
- `.vscode/launch.json` exists with valid Extension Development Host config
- `.vscode/tasks.json` exists with build task for `diffguard-lsp`
- Both files are valid JSON (parseable)

**Dependencies**: Task 2 (need working extension to test launch)

---

## Task 7: Add marketplace metadata (CHANGELOG, README update)

**What to do**:
- Create `editors/vscode-diffguard/CHANGELOG.md` with initial v0.2.0 entry describing LSP integration
- Update `editors/vscode-diffguard/README.md` to describe LSP features:
  - Real-time diagnostics from diffguard
  - Code actions (explain rule, open docs)
  - Configuration via VS Code settings
  - Installation: requires `diffguard-lsp` binary on PATH (or set `diffguard.serverPath`)

**Files to touch**:
- `editors/vscode-diffguard/CHANGELOG.md` (new or updated)
- `editors/vscode-diffguard/README.md` (updated)

**Success criteria**:
- `CHANGELOG.md` exists with at least one version entry
- `README.md` describes the LSP features and how to configure `diffguard.serverPath`

**Dependencies**: Task 3 (need final feature set for documentation)

---

## Task 8: Package and validate

**What to do**:
- Run `npx vsce package` in `editors/vscode-diffguard/` to create the `.vsix` file
- Verify package contents: `npx vsce ls` should show only necessary files
- Inspect the generated `.vsix` (it's a zip) to confirm it contains: extension.js, package.json, README.md, CHANGELOG.md, LICENSE, node_modules/vscode-languageclient
- Run `npm ls --production` to verify no missing deps
- Confirm no warnings from `vsce package` about missing fields

**Files touched**:
- `editors/vscode-diffguard/*.vsix` (generated artifact)

**Success criteria**:
- `npx vsce package` exits with code 0 (no errors)
- `.vsix` file is generated with `.vsix` extension
- `npx vsce ls` output contains only: extension.js, package.json, README.md, CHANGELOG.md, LICENSE, and node_modules
- No warnings about missing repository, license, or other required fields

**Dependencies**: All previous tasks (1-7)

---

## Dependency Graph

```
Task 1 (npm init + deps)
  |
  v
Task 2 (rewrite extension.js as LSP client)
  |
  v
Task 3 (update package.json manifest)  <--+
  |                                         |
  v                                         |
Task 4 (LICENSE)  --+                       |
                    |---> Task 5 (.vscodeignore) --+
Task 6 (dev config) --+                          |
                                                   |
Task 7 (CHANGELOG + README) --+                   |
                               |---> Task 8 (package + validate)
                               |
```

Tasks 4 and 6 can run in parallel with Tasks 1-3.
Task 7 depends on Task 3 (need final feature set).
Task 5 depends on Tasks 1-3 (need final file layout).
Task 8 depends on all prior tasks.
