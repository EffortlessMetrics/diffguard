# diffguard-testkit

Shared test helpers for the diffguard workspace.

`diffguard-testkit` is a dev-only crate (`publish = false`) that centralizes
proptest strategies, diff builders, sample fixtures, and schema validation.

## Modules

- `arb` - proptest generators for DTOs/patterns/options
- `diff_builder` - fluent unified-diff construction helpers
- `fixtures` - sample configs/diffs/receipts
- `schema` - JSON-schema validation helpers

## `arb` Example

```rust
use diffguard_testkit::arb::{arb_rule_config, arb_severity};
use proptest::prelude::*;

proptest! {
    #[test]
    fn generated_rules_have_ids(rule in arb_rule_config(), _severity in arb_severity()) {
        prop_assert!(!rule.id.is_empty());
    }
}
```

Bounded generation keeps tests fast (`MAX_*` constants in `arb.rs`).

## `diff_builder` Example

```rust
use diffguard_testkit::diff_builder::DiffBuilder;

let diff = DiffBuilder::new()
    .file("src/main.rs")
        .hunk(1, 1, 1, 2)
            .context("fn main() {}")
            .add_line("fn helper() {}")
        .done()
    .done()
    .file("src/lib.rs")
        .hunk(10, 1, 10, 1)
            .remove("old code")
            .add_line("new code")
        .done()
    .done()
    .build();

assert!(diff.contains("+new code"));
```

## `fixtures` Example

```rust
use diffguard_testkit::fixtures::{sample_configs, sample_diffs};

let cfg = sample_configs::rust_focused();
let diff = sample_diffs::simple_addition();
let renamed = sample_diffs::renamed_file();
```

## `schema` Example

```rust
use diffguard_testkit::fixtures::{sample_configs, sample_receipts};
use diffguard_testkit::schema::{validate_check_receipt, validate_config_file};

let config = sample_configs::minimal();
validate_config_file(&config)?;

let receipt = sample_receipts::with_warnings();
validate_check_receipt(&receipt)?;
```

## Add to a Crate

```toml
[dev-dependencies]
diffguard-testkit = { path = "../diffguard-testkit" }
```

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE) or [MIT license](../../LICENSE-MIT) at your option.
