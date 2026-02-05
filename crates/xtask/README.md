# xtask

Repository automation tasks for the [diffguard](https://crates.io/crates/diffguard) workspace.

This crate follows the [xtask pattern](https://github.com/matklad/cargo-xtask) — a Rust-native approach to build automation that replaces Makefiles and shell scripts with type-safe Rust code.

## Usage

```bash
cargo run -p xtask -- <command>

# Or with cargo alias (if configured in .cargo/config.toml):
cargo xtask <command>
```

## Commands

### `ci` — Run full CI suite

```bash
cargo run -p xtask -- ci
```

Runs the complete CI workflow:
1. `cargo fmt --check` — Format verification
2. `cargo clippy --workspace --all-targets -- -D warnings` — Lint
3. `cargo test --workspace` — All tests
4. Additional validation checks

Use this locally before pushing to catch CI failures early.

### `schema` — Generate JSON schemas

```bash
cargo run -p xtask -- schema
```

Generates JSON schemas from Rust types using `schemars`:
- `schemas/config-schema.json` — For `diffguard.toml` validation
- `schemas/receipt-schema.json` — For `CheckReceipt` validation

Schemas are used by:
- IDE autocompletion (VS Code, IntelliJ)
- CI validation
- API documentation

## Adding New Commands

1. Add a new variant to the command enum in `src/main.rs`
2. Implement the handler function
3. Update the match statement in `main()`
4. Document the command in this README

## Configuration

The `.cargo/config.toml` can define an alias for convenience:

```toml
[alias]
xtask = "run -p xtask --"
```

This enables:
```bash
cargo xtask ci
cargo xtask schema
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
