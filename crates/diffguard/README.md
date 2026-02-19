# diffguard

Command-line interface for diff-scoped governance linting.

This crate is the workspace I/O boundary. It owns:

- CLI parsing (`clap`)
- config loading/merge (`diffguard.toml`, includes, env expansion)
- git integration (`base/head`, `--staged`, blame filtering)
- invoking `diffguard-core`
- writing receipts/reports and returning stable exit codes

## Install

```bash
# crates.io
cargo install diffguard

# workspace source
cargo install --path crates/diffguard
```

## Command Surface

`diffguard` commands:

- `check` - evaluate rules on diff-scoped lines
- `rules` - print effective rules (toml/json)
- `explain` - show details for one rule ID
- `validate` - validate config regex/globs and optional strict checks
- `init` - write starter `diffguard.toml`
- `test` - run `rule.test_cases` from config
- `trend` - summarize trend-history files
- `sarif` / `junit` / `csv` - render existing receipt files

## Quick Start

```bash
diffguard init --preset minimal

diffguard check \
  --base origin/main \
  --head HEAD \
  --config diffguard.toml \
  --out artifacts/diffguard/report.json \
  --md artifacts/diffguard/comment.md \
  --sarif artifacts/diffguard/report.sarif.json \
  --github-annotations
```

Non-git input is also supported:

```bash
diffguard check --diff-file patch.diff
git diff --cached | diffguard check --diff-file -
```

## `check` Highlights

Input selection:

- `--base <REF>` (repeatable) and `--head <REF>`
- `--staged`
- `--diff-file <PATH|->`

Policy and filtering:

- `--scope added|changed|modified|deleted`
- `--fail-on error|warn|never`
- `--max-findings <N>`
- `--paths <GLOB>` (repeatable)
- `--only-tags` / `--enable-tags` / `--disable-tags`
- `--language <LANG>` (force preprocessing language)
- `--blame-author` / `--blame-max-age-days`

Outputs:

- `--out` (JSON receipt)
- `--md`
- `--sarif`
- `--junit`
- `--csv` / `--tsv`
- `--sensor`
- `--rule-stats`
- `--false-positive-baseline`
- `--write-false-positive-baseline`
- `--trend-history` / `--trend-max-runs`
- `--github-annotations`

## Exit Codes

Stable exit code contract in standard mode:

- `0` pass
- `1` tool/runtime error
- `2` policy fail
- `3` warn-fail (when `fail_on=warn`)

`--mode cockpit` changes behavior to integration-focused semantics:

- `0` when a receipt is successfully written
- `1` only on catastrophic failure

## Presets

`diffguard init --preset ...` supports:

- `minimal`
- `rust-quality`
- `secrets`
- `js-console`
- `python-debug`

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
