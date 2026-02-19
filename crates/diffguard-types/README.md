# diffguard-types

Serializable DTOs and schema-bound types shared across the diffguard workspace.

This crate intentionally contains data types and constants, not orchestration or
I/O.

## Primary Type Groups

Configuration:

- `ConfigFile`
- `Defaults`
- `RuleConfig`
- `RuleTestCase`
- `DirectoryOverrideConfig`
- `RuleOverride`

Check/receipt model:

- `CheckReceipt`
- `Finding`
- `Verdict`
- `VerdictCounts`
- `VerdictStatus` (`pass`, `warn`, `fail`, `skip`)
- `DiffMeta`, `ToolMeta`, `TimingMetrics`

Sensor model:

- `SensorReport`
- `RunMeta`
- `CapabilityStatus`
- `SensorFinding`
- `SensorLocation`
- `Artifact`

Enums/constants:

- `Severity`, `Scope`, `FailOn`, `MatchMode`
- `CHECK_SCHEMA_V1`
- `SENSOR_REPORT_SCHEMA_V1`
- stable reason/code/capability tokens

## Built-In Rules

`ConfigFile::built_in()` returns the workspace default rule set and default
settings used by the CLI pipeline.

## Usage

```rust
use diffguard_types::{ConfigFile, RuleConfig, Severity};

let built_in = ConfigFile::built_in();

let custom_rule = RuleConfig {
    id: "example.no_todo".to_string(),
    severity: Severity::Warn,
    message: "Resolve TODO comments before merge".to_string(),
    languages: vec!["rust".to_string()],
    patterns: vec![r"\bTODO\b".to_string()],
    paths: vec!["**/*.rs".to_string()],
    exclude_paths: vec!["**/tests/**".to_string()],
    ignore_comments: false,
    ignore_strings: true,
    match_mode: Default::default(),
    multiline: false,
    multiline_window: None,
    context_patterns: vec![],
    context_window: None,
    escalate_patterns: vec![],
    escalate_window: None,
    escalate_to: None,
    depends_on: vec![],
    help: None,
    url: None,
    tags: vec![],
    test_cases: vec![],
};

let _json = serde_json::to_string_pretty(&built_in)?;
let _toml = toml::to_string_pretty(&custom_rule)?;
```

## Determinism Notes

Schema IDs and vocabulary constants are stable integration contracts for
downstream tooling.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
