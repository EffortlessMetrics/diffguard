# xtask

Repository automation binary for the diffguard workspace.

This crate implements the `xtask` pattern (Rust-native project automation
instead of shell scripts/Makefiles).

## Commands

### `ci`

Runs local CI checks:

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. Cockpit conformance in quick mode

```bash
cargo run -p xtask -- ci
```

### `schema`

Regenerates JSON schemas in `schemas/`:

- `diffguard.config.schema.json`
- `diffguard.check.schema.json`
- `sensor.report.v1.schema.json`
- `diffguard.false-positive-baseline.v1.schema.json`
- `diffguard.trend-history.v1.schema.json`

```bash
cargo run -p xtask -- schema
cargo run -p xtask -- schema --out-dir schemas
```

### `conform`

Runs Cockpit conformance tests.

```bash
cargo run -p xtask -- conform
cargo run -p xtask -- conform --quick
```

### `mutants`

Runs `cargo mutants` across workspace crates (or selected packages).

```bash
cargo run -p xtask -- mutants
cargo run -p xtask -- mutants -p diffguard-core -p diffguard-domain
```

## Notes

- `xtask` is workspace tooling (`publish = false`)
- It may invoke external tools (`cargo`, `cargo-mutants`) via subprocess

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
