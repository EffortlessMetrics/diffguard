# diffguard

[![Crates.io](https://img.shields.io/crates/v/diffguard.svg)](https://crates.io/crates/diffguard)
[![Documentation](https://docs.rs/diffguard/badge.svg)](https://docs.rs/diffguard)
[![CI](https://github.com/effortless-mgmt/diffguard/actions/workflows/ci.yml/badge.svg)](https://github.com/effortless-mgmt/diffguard/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/diffguard.svg)](LICENSE-MIT)

A diff-scoped governance linter: **rules applied to added/changed lines** in a Git diff.

`diffguard` is designed for modern PR automation:

- **Diff-aware** by default (no repo-wide grep noise)
- Emits a stable **JSON receipt** for bots/automation
- Can render a compact **Markdown summary** for PR comments
- Can emit **GitHub Actions annotations** (`::error` / `::warning`)

## Installation

```bash
# From crates.io
cargo install diffguard

# From source
git clone https://github.com/effortless-mgmt/diffguard
cd diffguard
cargo install --path crates/diffguard
```

## Quick start

```bash
# From a feature branch:
diffguard check --base origin/main --head HEAD --github-annotations \
  --out artifacts/diffguard/report.json \
  --md artifacts/diffguard/comment.md
```

### Exit codes

- `0` pass (or only warnings when `fail_on = "error"`)
- `2` policy failure (error-level findings, or warn-level when configured)
- `3` warn-level failure (only when `fail_on = "warn"`)
- `1` tool error (I/O, parse, git failure, invalid config)

## Configuration

Create `diffguard.toml`:

```toml
[defaults]
base = "origin/main"
scope = "added"       # added|changed
fail_on = "error"     # error|warn|never
max_findings = 200
diff_context = 0

[[rule]]
id = "rust.no_unwrap"
severity = "error"
message = "Avoid unwrap/expect in production code."
languages = ["rust"]
patterns = ["\\.unwrap\\(", "\\.expect\\("]
paths = ["**/*.rs"]
exclude_paths = ["**/tests/**", "**/benches/**", "**/examples/**"]
ignore_comments = true
ignore_strings = true
```

You can point `diffguard` at a config file:

```bash
diffguard check --config diffguard.toml
```

## GitHub Actions example

```yaml
- name: diffguard
  run: |
    diffguard check \
      --base origin/main \
      --head HEAD \
      --config diffguard.toml \
      --out artifacts/diffguard/report.json \
      --md artifacts/diffguard/comment.md \
      --github-annotations
```

## Repo layout

This repo uses a clean, microcrate workspace layout:

- `diffguard-types`: receipts + config DTOs
- `diffguard-diff`: unified diff parsing
- `diffguard-domain`: rule evaluation + preprocessing
- `diffguard-app`: orchestration use-cases
- `diffguard` (CLI): clap wiring and I/O
- `xtask`: repo automation (`xtask ci`, `xtask schema`, ...)

## Development

```bash
# typical workflow
cargo test --workspace

# automation
cargo run -p xtask -- ci
cargo run -p xtask -- schema
```

### Mutation testing

This repo is designed to work well with `cargo-mutants`.

### Fuzzing

A `fuzz/` directory is included (libFuzzer). Install `cargo-fuzz` and run:

```bash
cargo fuzz run unified_diff_parser
```

## Minimum Supported Rust Version (MSRV)

Rust 1.75 or later.

## License

MIT OR Apache-2.0
