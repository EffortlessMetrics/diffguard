# Plan Review: Ship VS Code Extension to Marketplace

**Reviewer**: plan-reviewer
**Gate**: VERIFIED
**Work ID**: work-ea424433

## Verdict: APPROVED WITH CONDITIONS

The plan is fundamentally sound. The 7 steps are in correct order, the approach of wiring the extension to the existing LSP server via `vscode-languageclient` is the right pattern, and the identified risks are legitimate. However, several issues need clarification or added detail before execution.

## Step Order Assessment

The step ordering is correct:
1. Init npm first (prerequisite for everything)
2. Rewrite extension.js (core work)
3. Update manifest (depends on knowing final API surface)
4. .vscodeignore (knows what files exist after steps 1-3)
5. Dev config (needs working extension to test)
6. Marketplace metadata (polish, can be parallelized)
7. Package and validate (must come last)

No steps are in the wrong order.

## Risks Not Identified

### 1. LICENSE files missing from extension directory
The workspace has `LICENSE-MIT` and `LICENSE-APACHE` at root, but the extension directory has neither. `vsce package` warns (or errors) when no license file is present in the extension directory. The plan should either:
- Copy/symlink LICENSE-MIT into `editors/vscode-diffguard/`
- Add a combined LICENSE file
- Set `"license"` in package.json to point to a file (already has `"MIT OR Apache-2.0"` which is correct for the field, but vsce still wants a LICENSE file on disk)

### 2. `.vsix` bundling of the LSP binary -- plan is silent on this
The plan says "spawn diffguard-lsp binary" but never addresses how users get that binary. Three options exist, none mentioned:
- **Option A**: Expect users to install `diffguard-lsp` on PATH (simplest, but fragile)
- **Option B**: Bundle platform-specific binaries in the .vsix (complex, needs `optionalDependencies` or postinstall script)
- **Option C**: Extension setting for binary path + PATH fallback (best UX)

The plan should explicitly pick an approach. Recommended: Option C (setting + PATH fallback) for v0.2.0, with clear error message if not found.

### 3. Document selectors not specified
The plan mentions "configure ClientOptions with document selectors for relevant languages" but doesn't say which languages. The LSP server is language-agnostic (it works on diffs, not specific languages). The extension should either:
- Register for all file types (`{ scheme: 'file' }`)
- Register for common languages

The LSP server does its own detection, so broad document selectors are correct here.

### 4. `initializationOptions` wiring
The plan says "pass initialization options from VS Code settings" but doesn't detail the mapping. The LSP server expects:
```json
{
  "configPath": "...",
  "noDefaultRules": false,
  "maxFindings": 200,
  "forceLanguage": "..."
}
```
These map 1:1 to the `contributes.configuration` settings, but the casing differs (camelCase in Rust init options vs kebab-case in VS Code settings convention). This needs explicit handling in the extension.js client setup.

### 5. TypeScript conversion decision not addressed
The plan stays with plain JS. This is acceptable for v0.2.0 but should be a conscious decision noted somewhere. The research analysis mentions "should be converted to TypeScript (or at least bundled JS) for marketplace quality" -- the plan should acknowledge this is deferred, not ignored.

### 6. Extension deactivation lifecycle
The current `deactivate()` is a no-op. With a LanguageClient, `deactivate()` must dispose the client properly or the LSP child process may be orphaned. The plan's step 2 should include proper cleanup.

## Items That Are Over-Specified

- **Step 5 (dev launch config)**: `.vscode/launch.json` and `.vscode/tasks.json` are nice-to-have but not strictly required for marketplace shipping. Could be deferred to a follow-up. However, having them aids validation in step 7, so keeping them is fine.

## Items That Are Under-Specified

- **Step 2 (extension rewrite)**: Needs concrete code structure for the `LanguageClient` setup. Key details:
  - `ServerOptions` command: `'diffguard-lsp'` with args `[]`
  - `ServerOptions` transport: `stdio` (not pipe, not socket)
  - `ClientOptions` documentSelector: broad, since LSP is language-agnostic
  - `ClientOptions` synchronize: configurationSection `'diffguard'`
  - Error handling: show error notification if binary not found
  - Disposal: dispose client in `deactivate()`

- **Step 3 (manifest)**: Should list the exact `contributes.configuration` properties matching LSP InitOptions.

## Specific Concerns

1. **`vscode-languageclient` v8 vs v9**: v9 dropped the `ServerOptions` run/binding API in favor of `Executable`. The plan should pin to v9 (current) and use the `Executable` API:
   ```js
   const serverOptions = {
     run: { command: 'diffguard-lsp' },
     debug: { command: 'diffguard-lsp' }
   };
   ```

2. **Activation events**: Should use `"onLanguage:*"` or `"onStartupFinished"` rather than just removing the old command trigger. The research analysis recommends this but the plan is vague.

3. **Publisher access**: Risk is identified but unresolvable by the implementer. This is a pre-condition that should be verified before step 7, not during.

## Recommendation

**APPROVE** with the following conditions added to the plan:
1. Add LICENSE-MIT (or a symlink) to the extension directory
2. Explicitly define the binary discovery strategy (setting + PATH fallback)
3. Add concrete `initializationOptions` mapping specification
4. Include proper `deactivate()` disposal of the LanguageClient
5. Use vscode-languageclient v9 API patterns (Executable, not old run binding)

These conditions are minor and can be incorporated during execution without changing the step order or scope.
