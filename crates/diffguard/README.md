# diffguard

Command-line interface for the [diffguard](https://crates.io/crates/diffguard) governance linter.

This is the main binary crate and I/O boundary — it handles argument parsing, configuration loading, git subprocess invocation, and file output. All domain logic is delegated to the library crates.

## Installation

```bash
# From crates.io
cargo install diffguard

# From source
cargo install --path crates/diffguard
```

## Commands

### `check` — Main linting command

```bash
diffguard check --base origin/main --head HEAD
```

Options:
- `--base <REF>` — Base git ref for diff (default: from config or `origin/main`)
- `--head <REF>` — Head git ref for diff (default: `HEAD`)
- `--config <PATH>` — Config file path (default: `diffguard.toml`)
- `--scope <SCOPE>` — `added` or `changed` (default: from config)
- `--fail-on <LEVEL>` — `error`, `warn`, or `never` (default: from config)
- `--max-findings <N>` — Limit number of findings
- `--include <GLOB>` — Only check matching paths
- `--exclude <GLOB>` — Skip matching paths
- `--out <PATH>` — Write JSON receipt to file
- `--md <PATH>` — Write Markdown summary to file
- `--sarif <PATH>` — Write SARIF report to file
- `--junit <PATH>` — Write JUnit XML to file
- `--csv <PATH>` — Write CSV to file
- `--tsv <PATH>` — Write TSV to file
- `--github-annotations` — Emit GitHub Actions annotations to stdout

### `rules` — List effective rules

```bash
diffguard rules                    # TOML format
diffguard rules --json             # JSON format
diffguard rules --config my.toml   # From specific config
```

### `explain` — Show rule details

```bash
diffguard explain rust.no_unwrap
```

### `init` — Create starter configuration

```bash
diffguard init                     # Interactive preset selection
diffguard init --preset minimal    # Specific preset
diffguard init --preset secrets    # Secret detection rules
```

Available presets: `minimal`, `rust-quality`, `secrets`, `js-console`, `python-debug`

### `sarif` / `junit` / `csv` — Render-only modes

Convert an existing JSON receipt to other formats:

```bash
diffguard sarif --receipt report.json --out report.sarif
diffguard junit --receipt report.json --out report.xml
diffguard csv --receipt report.json --out report.csv
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Pass — no policy violations |
| `1` | Tool error — I/O, parse, git, or config failure |
| `2` | Policy fail — error-level findings (or warn-level when `fail_on: warn`) |
| `3` | Warn-fail — warning-level findings with warn-fail policy |

## GitHub Actions Example

```yaml
- name: Run diffguard
  run: |
    diffguard check \
      --base origin/main \
      --head HEAD \
      --config diffguard.toml \
      --out artifacts/report.json \
      --md artifacts/comment.md \
      --sarif artifacts/report.sarif \
      --github-annotations
```

## Configuration

See `diffguard.toml.example` for full configuration options. The CLI loads configuration from:

1. `--config` flag path (if provided)
2. `diffguard.toml` in current directory (if exists)
3. Built-in defaults

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
