# diffguard

[![Crates.io](https://img.shields.io/crates/v/diffguard.svg)](https://crates.io/crates/diffguard)
[![Documentation](https://docs.rs/diffguard/badge.svg)](https://docs.rs/diffguard)
[![CI](https://github.com/effortlessmetrics/diffguard/actions/workflows/ci.yml/badge.svg)](https://github.com/effortlessmetrics/diffguard/actions/workflows/ci.yml)
[![License](https://img.shields.io/crates/l/diffguard.svg)](LICENSE-MIT)

A diff-scoped governance linter: **rules applied to scoped lines** in a Git diff.

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
git clone https://github.com/effortlessmetrics/diffguard
cd diffguard
cargo install --path crates/diffguard
```

## Quick start

```bash
# Initialize with a preset
diffguard init --preset minimal

# From a feature branch:
diffguard check --base origin/main --head HEAD --github-annotations \
  --out artifacts/diffguard/report.json \
  --md artifacts/diffguard/comment.md
```

Available presets: `minimal`, `rust-quality`, `secrets`, `js-console`, `python-debug`

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
scope = "added"       # added|changed|modified|deleted (changed kept for compatibility)
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

### Environment Variables

Config files support environment variable expansion:

```toml
[[rule]]
id = "custom.check"
paths = ["${PROJECT_ROOT}/src/**/*.rs"]
message = "Check for ${PROJECT_NAME:-myproject}"
```

### Config Includes

Compose configs from multiple files:

```toml
includes = ["base-rules.toml", "team-overrides.toml"]

[[rule]]
id = "project.specific"
severity = "error"
message = "Project-specific check"
patterns = ["FIXME"]
```

### Per-Directory Overrides

Place `.diffguard.toml` in subdirectories to override rule behavior for that
directory subtree:

```toml
[[rule]]
id = "rust.no_unwrap"
enabled = false
```

Supported override fields:
- `enabled` (bool): enable/disable a rule for that subtree
- `severity` (`info|warn|error`): override severity by directory
- `exclude_paths` (`[]string`): extra excludes scoped to that directory

Deeper directories override parent directories.

### Inline Suppressions

Suppress specific findings with inline comments:

```rust
// Same line
let x = get_value().unwrap(); // diffguard: ignore rust.no_unwrap

// Next line
// diffguard: ignore-next-line rust.no_unwrap
let x = get_value().unwrap();

// Multiple rules
let x = foo(); // diffguard: ignore rule1, rule2

// All rules
let x = foo(); // diffguard: ignore *
```

## Output Formats

diffguard supports multiple output formats for different use cases:

| Format | Flag | Use Case |
|--------|------|----------|
| JSON | `--out` | Automation, bots, downstream processing |
| Markdown | `--md` | PR comments, human-readable summaries |
| SARIF | `--sarif` | GitHub Advanced Security, code scanning |
| JUnit | `--junit` | CI/CD integration (Jenkins, GitLab CI) |
| CSV/TSV | `--csv` / `--tsv` | Spreadsheet import, data analysis |
| Sensor | `--sensor` | R2 Library Contract envelope (`sensor.report.v1`) |

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
      --sarif artifacts/diffguard/report.sarif \
      --github-annotations

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: artifacts/diffguard/report.sarif
```

## Repo layout

This repo uses a clean, microcrate workspace layout with strict dependency direction:

```
diffguard (CLI)          I/O boundary: clap, file I/O, git subprocess
       │
       ▼
diffguard-core           Engine: run_check(), run_sensor(), render outputs
       │
       ├────────────────────────┐
       ▼                        ▼
diffguard-domain         diffguard-diff
  Business logic           Diff parsing
       │                        │
       └──────────┬─────────────┘
                  ▼
          diffguard-types
            Pure DTOs
```

| Crate | Purpose |
|-------|---------|
| `diffguard-types` | Serializable DTOs, severity/scope enums, built-in presets |
| `diffguard-diff` | Parse unified diff format, detect binary/submodule/rename |
| `diffguard-domain` | Compile rules, evaluate lines, preprocess comments/strings |
| `diffguard-core` | Engine: check runs, sensor reports, verdicts, render outputs |
| `diffguard` | CLI binary: arg parsing, config loading, git invocation |
| `diffguard-testkit` | Shared test utilities (proptest strategies, fixtures) |
| `xtask` | Repo automation (`ci`, `schema`, `conform`) |

## Development

```bash
# Build and test
cargo build --workspace
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings

# Full CI suite
cargo run -p xtask -- ci

# Generate JSON schemas
cargo run -p xtask -- schema

# Run conformance tests
cargo run -p xtask -- conform
```

### Testing

| Type | Command |
|------|---------|
| Unit tests | `cargo test --workspace` |
| Snapshot tests | `cargo insta test` |
| Mutation tests | `cargo mutants` |
| Fuzz tests | `cargo +nightly fuzz run unified_diff_parser` |

### Fuzzing

Three fuzz targets are available:

```bash
cargo +nightly fuzz run unified_diff_parser  # Diff parsing
cargo +nightly fuzz run preprocess           # Comment/string masking
cargo +nightly fuzz run rule_matcher         # Rule evaluation
```

## Minimum Supported Rust Version (MSRV)

Rust 1.92 or later.

## License

MIT OR Apache-2.0
