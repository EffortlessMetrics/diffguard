# CLAUDE.md - diffguard-types

## Crate Purpose

Pure data transfer objects (DTOs) with serialization support. This is the foundation crate that all other diffguard crates depend on.

## Key Constraints

- **Intentionally "dumb"** - This crate contains only data structures with no logic
- **No I/O** - Must not use `std::process`, `std::fs`, or `std::env`
- **Flat structure** - All types live in `lib.rs`, no submodules
- **Stable API** - Types here form the public contract; changes affect all consumers

## Key Types

| Type | Purpose |
|------|---------|
| `Severity` | Enum: Info, Warn, Error |
| `Scope` | Enum: Added, Changed |
| `FailOn` | Enum: Error, Warn, Never |
| `Finding` | Single rule match result |
| `CheckReceipt` | Complete output structure (versioned schema) |
| `ConfigFile` | On-disk TOML configuration format |
| `RuleConfig` | Individual rule definition |
| `Verdict*` | Verdict status and counts |

## Serialization

All types derive:
- `serde::Serialize` / `serde::Deserialize` - JSON/TOML support
- `schemars::JsonSchema` - JSON schema generation

The `CHECK_SCHEMA_V1` constant provides schema versioning for receipts.

## Built-in Rules

Built-in rules are provided via `ConfigFile::built_in()` for the CLI/app pipeline.
CLI presets live in the `diffguard` crate (`diffguard init --preset ...`); there is
no `presets` module in `diffguard-types`.

## Common Tasks

### Adding a new field to RuleConfig

1. Add the field with `#[serde(default)]` if optional
2. Update `diffguard-domain/src/rules.rs` to handle it
3. Update `diffguard-domain/src/evaluate.rs` if it affects evaluation
4. Regenerate schemas: `cargo run -p xtask -- schema`
5. Update `diffguard.toml.example`

### Adding a new enum variant

1. Add variant to the enum
2. Ensure serialization name is lowercase/kebab-case as appropriate
3. Update pattern matching in consuming crates
4. Add tests for the new variant

## Testing

```bash
cargo test -p diffguard-types
```

Tests include:
- Serialization round-trips
- Schema validation
- Property tests via `proptest`
