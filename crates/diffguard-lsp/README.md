# diffguard-lsp

Minimal Language Server Protocol (LSP) server for diffguard.

This crate currently provides the protocol transport/lifecycle layer only:

- Handles `initialize`, `shutdown`, and `exit`
- Communicates over stdio using `lsp-server`
- Advertises `textDocumentSync = Full`

It does not yet publish diagnostics, code actions, or custom requests.

## Run

```bash
cargo run -p diffguard-lsp
```

The server is intended to be launched by an editor client over stdio.

## Scope and Roadmap

`diffguard-lsp` is intentionally small today so protocol scaffolding stays
stable while the rules/engine evolve in the core crates.

Planned expansions include:

- diff-scoped diagnostics from `diffguard-core`
- rule explanations and quick fixes
- workspace/config aware behavior
