# diffguard-types

Core types and data structures for the [diffguard](https://crates.io/crates/diffguard) governance linter.

This crate provides serializable DTOs (Data Transfer Objects) used throughout the diffguard ecosystem. It is intentionally "dumb" — pure data structures with no logic, forming the foundation that all other diffguard crates depend on.

## Types

### Configuration

| Type | Purpose |
|------|---------|
| `ConfigFile` | Root configuration structure (maps to `diffguard.toml`) |
| `RuleConfig` | Individual rule definition with patterns, paths, severity |
| `Defaults` | Default settings for base ref, scope, fail policy |

### Output

| Type | Purpose |
|------|---------|
| `CheckReceipt` | Complete check output (versioned schema via `CHECK_SCHEMA_V1`) |
| `Finding` | Single rule match with location, severity, snippet |
| `Verdict` | Pass/warn/fail determination with counts |
| `VerdictStatus` | Enum: Pass, Warn, Fail |
| `VerdictCounts` | Aggregated counts by severity |

### Enums

| Enum | Variants |
|------|----------|
| `Severity` | `Info`, `Warn`, `Error` |
| `Scope` | `Added`, `Changed` |
| `FailOn` | `Error`, `Warn`, `Never` |

## Features

- Full `serde` support for JSON/TOML serialization
- JSON Schema generation via `schemars`
- Built-in rule presets for common languages

## Built-in Presets

```rust
use diffguard_types::presets;

let rust_rules = presets::rust_quality();      // unwrap, expect, todo!, etc.
let python_rules = presets::python_debug();    // print(), breakpoint(), pdb
let js_rules = presets::js_console();          // console.log, debugger
let go_rules = presets::go_quality();          // fmt.Print, panic
```

## Usage

```rust
use diffguard_types::{ConfigFile, Severity, RuleConfig, Scope, FailOn};

// Load built-in rules
let config = ConfigFile::built_in();

// Or define custom rules
let rule = RuleConfig {
    id: "no-todo".to_string(),
    severity: Severity::Warn,
    message: "Remove TODO comments before merging".to_string(),
    patterns: vec![r"\bTODO\b".to_string()],
    paths: vec!["**/*.rs".to_string()],
    exclude_paths: vec!["**/tests/**".to_string()],
    languages: vec![],
    ignore_comments: false,  // We want to find TODOs in comments!
    ignore_strings: true,
    scope: None,  // Inherit from defaults
};

// Serialize to TOML for config file
let toml = toml::to_string_pretty(&config)?;

// Serialize receipt to JSON
let receipt: CheckReceipt = /* ... */;
let json = serde_json::to_string_pretty(&receipt)?;
```

## Schema Versioning

The `CHECK_SCHEMA_V1` constant identifies the receipt schema version, ensuring consumers can detect breaking changes:

```rust
use diffguard_types::CHECK_SCHEMA_V1;

assert_eq!(receipt.schema, CHECK_SCHEMA_V1);
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
