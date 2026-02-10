# CLAUDE.md - diffguard-testkit

## Crate Purpose

Shared test utilities library for generating test inputs, building diffs, and validating outputs. Not published - internal testing use only.

## Key Constraint

**Not published** - This crate has `publish = false` in Cargo.toml. It's only used as a dev-dependency by other crates.

## Module Structure

| Module | Purpose |
|--------|---------|
| `arb.rs` | Proptest strategies for generating valid inputs |
| `diff_builder.rs` | Fluent API for constructing unified diffs |
| `fixtures.rs` | Sample test data (configs, diffs) |
| `schema.rs` | JSON schema validation helpers |

## Proptest Strategies (`arb.rs`)

**Bounded generation** to keep tests fast:
- `MAX_FILES = 5`
- `MAX_HUNKS_PER_FILE = 5`
- `MAX_LINES_PER_HUNK = 20`
- `MAX_LINE_LENGTH = 200`
- `MAX_PATTERNS_PER_RULE = 5`

Key strategies:
```rust
pub fn arb_severity() -> impl Strategy<Value = Severity>
pub fn arb_scope() -> impl Strategy<Value = Scope>
pub fn arb_rule_config() -> impl Strategy<Value = RuleConfig>
pub fn arb_regex_pattern() -> impl Strategy<Value = String>
pub fn arb_glob_pattern() -> impl Strategy<Value = String>
```

**Constructive strategies** - Generate valid inputs directly instead of filtering invalid ones.

## Diff Builder (`diff_builder.rs`)

Fluent API for building test diffs:
```rust
DiffBuilder::new()
    .file("src/main.rs")
        .hunk(1, 1, 1, 2)
            .context("fn main() {")
            .add_line("    println!(\"hello\");")
        .done()
    .done()
    .build()
```

## Fixtures (`fixtures.rs`)

Pre-built test data:
- `sample_configs::empty()` - Empty config
- `sample_configs::minimal()` - One simple rule
- `sample_configs::rust_focused()` - Rust best practices
- `sample_diffs::*` - Common diff patterns

## Schema Validation (`schema.rs`)

```rust
pub fn validate_check_receipt(receipt: &CheckReceipt) -> Result<()>
pub fn validate_config_file(config: &ConfigFile) -> Result<()>
```

Uses `jsonschema` crate for validation against generated schemas.

## Common Tasks

### Adding a new proptest strategy

1. Add function in `arb.rs`
2. Use `prop_oneof!`, `prop_compose!`, or combinators
3. Keep it constructive - avoid `prop_filter` when possible
4. Respect bounds for performance

### Adding a new fixture

1. Add to appropriate module in `fixtures.rs`
2. Keep fixtures minimal but representative
3. Document what scenario the fixture covers

### Adding a new diff builder method

1. Add to appropriate builder struct in `diff_builder.rs`
2. Maintain fluent API style
3. Ensure `build()` produces valid unified diff format

## Testing

This crate is tested implicitly through the crates that use it. Direct tests:
```bash
cargo test -p diffguard-testkit
```

## Usage in Other Crates

Add as dev-dependency:
```toml
[dev-dependencies]
diffguard-testkit = { path = "../diffguard-testkit" }
```

Use in tests:
```rust
use diffguard_testkit::{arb::*, diff_builder::DiffBuilder, fixtures::*};
```
