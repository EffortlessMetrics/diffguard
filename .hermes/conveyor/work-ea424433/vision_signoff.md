# Vision Signoff — VS Code Extension (work-ea424433)

**Agent:** maintainer-vision-agent-2
**Date:** 2026-04-06

## Review Summary

Reviewed the final extension.js (60 lines) and package.json for the vscode-diffguard extension.

## Alignment with Project Direction

**"Ship primitives, composable governance"** — PASS.

The extension is a thin LSP transport layer, nothing more:

1. **No business logic in the extension.** All rule evaluation, diff parsing, and governance logic lives in the `diffguard-lsp` Rust crate where it belongs. The extension is pure plumbing: it spawns the LSP server over stdio and wires VS Code settings to initialization options.

2. **Follows the crate dependency direction.** The architecture diagram in DESIGN.md and agent-context.md shows:
   ```
   diffguard (CLI) → diffguard-core → diffguard-domain/diff → diffguard-types
   ```
   The extension sits outside this hierarchy as an I/O boundary consumer of `diffguard-lsp`, exactly as the CLI sits as an I/O boundary consumer of `diffguard-core`. No logic leakage.

3. **Composable, not opinionated.** The extension exposes 5 configuration settings (serverPath, configPath, noDefaultRules, maxFindings, forceLanguage) and 3 LSP commands (explainRule, reloadConfig, showRuleUrl). It does not hardcode governance policy — teams configure their own rules via diffguard.toml, and the LSP server enforces them.

4. **Proper error handling.** The ENOENT/not-found detection gives users a clear message when the diffguard-lsp binary is missing, rather than a cryptic stack trace.

5. **Clean lifecycle.** Activate starts the client, deactivate disposes it. No background watchers, no file system polling, no state management beyond the client handle.

## Concerns

None blocking. One minor note for future consideration:
- The `forceLanguage` setting description says "Force analysis language (e.g. 'en', 'de')" which reads like a locale/i18n setting. If this is actually a programming language override, the description could be clearer. Not a merge blocker.

## Verdict

**approved** — The VS Code extension correctly embodies the project's "primitives, not governance" philosophy. It is a minimal, composable transport layer with no embedded policy logic. Ready to merge.
