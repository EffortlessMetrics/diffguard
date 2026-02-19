# diffguard-lsp

Language Server Protocol (LSP) server for diffguard.

## Features

- Handles `initialize`, `shutdown`, and `exit` over stdio (`lsp-server`)
- Publishes `textDocument/publishDiagnostics` findings from `diffguard-core`
- Uses diff-scoped evaluation:
  - In-memory changed lines while editing
  - `git diff` scoped lines when the buffer is clean
- Loads `diffguard.toml` (supports includes and `${VAR}` / `${VAR:-default}` expansion)
- Applies per-directory `.diffguard.toml` overrides
- Provides code actions:
  - `diffguard: Explain <rule-id>`
  - `diffguard: Open docs for <rule-id>` (when rule URL exists)
- Supports execute commands:
  - `diffguard.explainRule`
  - `diffguard.reloadConfig`
  - `diffguard.showRuleUrl`

## Run

```bash
cargo run -p diffguard-lsp
```

The server is intended to be started by an editor client over stdio.

## Initialization Options

`initializationOptions` (all optional):

- `configPath` (`string`): explicit config path
- `noDefaultRules` (`bool`): disable built-in rules
- `maxFindings` (`number`): cap findings per diagnostic pass
- `forceLanguage` (`string`): force preprocessing language
