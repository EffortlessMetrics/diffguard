# Changelog

## 0.2.0

- Switched to LSP (Language Server Protocol) integration via `diffguard-lsp`.
- Added `diffguard.serverPath` setting to configure the language server binary.
- Added `diffguard.configPath`, `diffguard.noDefaultRules`, `diffguard.maxFindings`, and `diffguard.forceLanguage` settings.
- Added commands: `diffguard.explainRule`, `diffguard.reloadConfig`, `diffguard.showRuleUrl`.
- Extension now activates on startup and provides real-time diagnostics via the language server.

## 0.1.0

- Initial release with shell-exec based `diffguard.runCheck` command.
