# ADR-0516: Replace Wildcard Imports with Explicit Imports in testkit/fixtures.rs

## Status
**Proposed**

## Context

The file `crates/diffguard-testkit/src/fixtures.rs` contains two wildcard imports (`use super::*;`):

1. **Line 17** — inside `pub mod sample_configs { use super::*; }`
2. **Line 608** — inside `pub mod sample_receipts { use super::*; }`

These submodules are part of the `diffguard-testkit` crate, which provides shared test fixtures for the workspace. The `super` in each case refers to the `fixtures` module itself, which imports types from `diffguard_types` at the top of the file (lines 6–9).

**Why this matters**: `diffguard` is a governance linter that prevents silent import breakage when module APIs change. The wildcard imports in the test fixtures directly contradict this principle — they would silently absorb new exports instead of triggering compilation errors that would force explicit imports. If `diffguard_types` adds new public types in the future, the wildcard imports would silently pull them in, masking the fact that the fixtures modules may not actually handle those new types correctly.

## Decision

Replace the two `use super::*;` wildcard imports with explicit imports listing only the types actually used in each submodule:

**`sample_configs` (line 17):**
```rust
use super::{ConfigFile, Defaults, RuleConfig, Severity, Scope, FailOn};
```

**`sample_receipts` (line 608):**
```rust
use super::{CheckReceipt, CHECK_SCHEMA_V1, ToolMeta, DiffMeta, Finding, Severity, Scope, Verdict, VerdictCounts, VerdictStatus};
```

## Alternatives Considered

### 1. Leave wildcard imports as-is
**Rejected because**: This creates a maintenance hazard. The whole point of `diffguard` is to prevent silent breakage from API changes. Having wildcard imports in the test fixtures contradicts this mission and could mask issues when `diffguard_types` evolves.

### 2. Disable the `wildcard_imports` clippy lint for this file
**Rejected because**: Disabling lints to avoid fixing real issues is a slippery slope. The lint exists precisely to catch cases like this. Fixing the root cause (wildcard imports) is better than silencing the warning.

### 3. Move fixtures to separate files
**Rejected because**: Overly architectural for what is essentially a find-and-replace fix. The fixtures are well-organized into submodules within a single file; splitting them further would add complexity without solving the core issue.

## Consequences

### Benefits
- **Compile-time safety**: If `diffguard_types` adds new exports in the future, the compilation will fail with an "unused import" or "missing import" error rather than silently absorbing them.
- **Self-governance**: The fix aligns the test fixtures with the same discipline that `diffguard` enforces on its users.
- **Explicit intent**: Each submodule clearly declares which types it depends on, improving code readability and maintainability.

### Tradeoffs / Risks
- **Future maintenance**: If a new type is added to `diffguard_types` and is needed by these fixtures, the developer must explicitly add it to the import list. This is intentional — it forces a conscious decision rather than silent absorption.
- **Risk of forgetting a type**: If a developer adds usage of a new type without updating the import list, compilation will fail. This is caught early but requires the fix to be known. Mitigated by clear error messages.
- **Other wildcard imports remain**: Four other wildcard imports exist in `diffguard-testkit` (`arb.rs:480`, `diff_builder.rs:588`, `schema.rs:170`, `fixtures.rs:784` in `#[cfg(test)]`), but these are out of scope for this issue.
