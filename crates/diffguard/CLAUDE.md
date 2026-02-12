# CLAUDE.md - diffguard (CLI)

## Crate Purpose

Command-line interface and I/O boundary. This is the only crate that performs file I/O, subprocess calls, and environment variable access.

## Key Constraint

**This is the I/O boundary** - All file system, subprocess, and environment operations happen here. Domain crates must remain I/O-free.

## File Structure

| File | Purpose |
|------|---------|
| `src/main.rs` | CLI definition, command handlers |
| `src/presets.rs` | Starter configuration generators |

## Commands

| Command | Purpose |
|---------|---------|
| `check` | Main command: evaluate rules against diff |
| `rules` | Print effective rules (TOML or JSON) |
| `explain` | Show details for a specific rule |
| `sarif` | Render-only: convert receipt to SARIF |
| `junit` | Render-only: convert receipt to JUnit XML |
| `csv` | Render-only: convert receipt to CSV/TSV |
| `init` | Create starter configuration file |

## Exit Codes (Stable API)

- `0` - Pass
- `1` - Tool error
- `2` - Policy fail (errors found)
- `3` - Warn-fail

## Common Tasks

### Adding a new CLI flag

1. Add field to appropriate `Args` struct in `main.rs`
2. Use `#[arg(...)]` for clap configuration
3. Wire through to `diffguard-core` if it affects check logic
4. Update `--help` text with clear description

### Adding a new subcommand

1. Add variant to `Commands` enum
2. Create corresponding `Args` struct
3. Add handler in `main()` match
4. Keep I/O in this crate, delegate logic to `diffguard-core`

### Adding a new preset

1. Add variant to `Preset` enum in `presets.rs`
2. Implement `generate()` for the preset
3. Update CLI help text
4. Add example in documentation

## Git Integration

The CLI calls git as a subprocess:
```bash
git diff <base>..<head>
```

Handle edge cases:
- Detached HEAD
- Missing refs
- Large diffs

## Configuration Loading

1. Look for `diffguard.toml` in current directory
2. Or use `--config` flag path
3. Merge with built-in presets if `use_built_in_rules: true`

## Output Files

- `--receipt` - JSON receipt (versioned schema)
- `--markdown` - Markdown summary
- `--sarif` - SARIF 2.1.0 report
- `--junit` - JUnit XML
- `--csv` / `--tsv` - Tabular output

GitHub Actions annotations are always emitted to stdout when running in CI.

## Testing

```bash
cargo test -p diffguard                 # Unit tests
cargo run -p diffguard -- --help        # Manual testing
```

Integration tests use `assert_cmd` and `tempfile` for CLI testing.
