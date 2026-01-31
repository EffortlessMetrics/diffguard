# Tech Stack

## Language & Toolchain

- **Rust** (edition 2021, MSRV 1.75)
- Stable toolchain with `rustfmt` and `clippy` components

## Build System

Cargo workspace with multiple crates. Default member is the CLI binary.

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` | CLI argument parsing (derive mode) |
| `serde` / `serde_json` / `toml` | Serialization for config and receipts |
| `schemars` | JSON Schema generation |
| `regex` | Pattern matching for rules |
| `globset` | Path glob matching |
| `anyhow` / `thiserror` | Error handling |

## Dev Dependencies

| Crate | Purpose |
|-------|---------|
| `assert_cmd` | CLI integration testing |
| `insta` | Snapshot testing |
| `tempfile` | Temporary file handling in tests |

## Common Commands

```bash
# Build
cargo build

# Run all tests
cargo test --workspace

# Format check
cargo fmt --check

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Full CI suite (fmt + clippy + test)
cargo run -p xtask -- ci

# Generate JSON schemas
cargo run -p xtask -- schema

# Run CLI
cargo run -p diffguard -- check --base origin/main --head HEAD

# Mutation testing (requires cargo-mutants)
cargo mutants

# Fuzzing (requires cargo-fuzz, nightly)
cargo fuzz run unified_diff_parser
```

## Testing Strategy

- Unit tests co-located in source files (`#[cfg(test)]` modules)
- Integration tests in `tests/` directories
- Snapshot tests with `insta` for output stability
- Mutation testing with `cargo-mutants` (excludes CLI and xtask)
- Fuzz testing with `libFuzzer` for diff parser
