# CLAUDE.md - xtask

## Crate Purpose

Repository automation tasks following the [xtask pattern](https://github.com/matklad/cargo-xtask). Provides a single entry point for common development workflows.

## Usage

```bash
cargo run -p xtask -- <command>
# or via alias if configured:
cargo xtask <command>
```

## Commands

| Command | Purpose |
|---------|---------|
| `ci` | Run full CI suite (fmt, clippy, test, etc.) |
| `schema` | Generate JSON schemas for config and receipt types |

## Common Tasks

### Adding a new xtask command

1. Add variant to the commands enum
2. Implement handler function
3. Update help text
4. Document in this file and root CLAUDE.md

### Modifying CI workflow

1. Update the `ci` command implementation
2. Ensure it matches GitHub Actions workflow
3. Keep commands idempotent

### Updating schema generation

1. Modify `schema` command
2. Ensure schemas are written to correct location
3. Update version constants if schema format changes

## CI Command Details

The `ci` command runs:
1. `cargo fmt --check` - Format verification
2. `cargo clippy --workspace --all-targets -- -D warnings` - Lint
3. `cargo test --workspace` - All tests
4. Additional checks as configured

## Schema Generation

Generates JSON schemas from Rust types using `schemars`:
- `config-schema.json` - For `diffguard.toml` validation
- `receipt-schema.json` - For `CheckReceipt` validation

Schemas are used by:
- IDE autocompletion
- CI validation
- Documentation

## Testing

```bash
cargo test -p xtask
cargo run -p xtask -- ci  # Full CI run
```
