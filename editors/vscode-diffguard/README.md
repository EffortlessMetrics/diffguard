# DiffGuard VS Code Extension

DiffGuard provides real-time diagnostics for your diffs via the Language Server Protocol (LSP).

## Requirements

You need the `diffguard-lsp` binary installed and available on your PATH, or set `diffguard.serverPath` in your VS Code settings to point to its location.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `diffguard.serverPath` | `diffguard-lsp` | Path to the diffguard-lsp binary |
| `diffguard.configPath` | `""` | Path to a diffguard.toml config file |
| `diffguard.noDefaultRules` | `false` | Disable built-in default rules |
| `diffguard.maxFindings` | `100` | Maximum number of findings to report |
| `diffguard.forceLanguage` | `""` | Force analysis language (e.g. `en`, `de`) |

## Commands

- **DiffGuard: Explain Rule** - Show documentation for a rule.
- **DiffGuard: Reload Config** - Reload the DiffGuard configuration.
- **DiffGuard: Show Rule URL** - Open the rule documentation URL.

## Development

1. Open this folder in VS Code.
2. Press `F5` to launch an Extension Development Host.
3. Diagnostics will appear automatically in any open file.

## License

MIT
