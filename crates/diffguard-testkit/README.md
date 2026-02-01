# diffguard-testkit

Shared test utilities for the [diffguard](https://crates.io/crates/diffguard) workspace.

This crate provides reusable test infrastructure: proptest strategies, diff builders, fixtures, and schema validators. It is **not published** — used only as a dev-dependency within the workspace.

## Modules

| Module | Purpose |
|--------|---------|
| `arb` | Proptest strategies for generating valid test inputs |
| `diff_builder` | Fluent API for constructing unified diffs |
| `fixtures` | Sample configs and diffs for common test scenarios |
| `schema` | JSON schema validation helpers |

## Proptest Strategies (`arb`)

Generate valid test inputs without filtering:

```rust
use diffguard_testkit::arb::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_rule_evaluation(
        rule in arb_rule_config(),
        severity in arb_severity(),
    ) {
        // Test with generated inputs
    }
}
```

Available strategies:
- `arb_severity()` — `Severity` enum
- `arb_scope()` — `Scope` enum
- `arb_fail_on()` — `FailOn` enum
- `arb_rule_config()` — Complete rule configuration
- `arb_regex_pattern()` — Valid regex patterns
- `arb_glob_pattern()` — Valid glob patterns
- `arb_verdict_status()` — `VerdictStatus` enum

### Bounds

Generation is bounded for fast tests:
- `MAX_FILES = 5`
- `MAX_HUNKS_PER_FILE = 5`
- `MAX_LINES_PER_HUNK = 20`
- `MAX_LINE_LENGTH = 200`
- `MAX_PATTERNS_PER_RULE = 5`

## Diff Builder (`diff_builder`)

Fluent API for constructing test diffs:

```rust
use diffguard_testkit::diff_builder::DiffBuilder;

let diff = DiffBuilder::new()
    .file("src/main.rs")
        .hunk(1, 3, 1, 4)
            .context("fn main() {")
            .add_line("    println!(\"hello\");")
            .context("}")
        .done()
    .done()
    .file("src/lib.rs")
        .hunk(10, 2, 10, 3)
            .remove_line("old code")
            .add_line("new code")
        .done()
    .done()
    .build();

// Produces valid unified diff format
```

## Fixtures (`fixtures`)

Pre-built test data:

```rust
use diffguard_testkit::fixtures::{sample_configs, sample_diffs};

// Configurations
let empty = sample_configs::empty();
let minimal = sample_configs::minimal();
let rust = sample_configs::rust_focused();

// Diffs
let simple = sample_diffs::simple_add();
let rename = sample_diffs::file_rename();
```

## Schema Validation (`schema`)

Validate outputs against JSON schemas:

```rust
use diffguard_testkit::schema::{validate_check_receipt, validate_config_file};

let receipt: CheckReceipt = run_check(plan)?;
validate_check_receipt(&receipt)?;  // Panics if invalid

let config: ConfigFile = load_config()?;
validate_config_file(&config)?;
```

## Usage in Tests

Add as dev-dependency in `Cargo.toml`:

```toml
[dev-dependencies]
diffguard-testkit = { path = "../diffguard-testkit" }
```

Import in test modules:

```rust
#[cfg(test)]
mod tests {
    use diffguard_testkit::{
        arb::*,
        diff_builder::DiffBuilder,
        fixtures::sample_configs,
        schema::validate_check_receipt,
    };

    // ...
}
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
