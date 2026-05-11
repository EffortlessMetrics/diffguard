# ADR: Replace wildcard import with explicit named imports in sample_receipts

## Status
**Proposed**

## Context

GitHub issue #424 reports a `clippy::pedantic::wildcard_imports` warning in `crates/diffguard-testkit/src/fixtures.rs:608`. Inside the `pub mod sample_receipts` module, the line `use super::*;` uses a wildcard import that obscures symbol provenance — callers cannot determine which traits/types are re-exported without reading the parent module.

This is the same provenance issue as #335, which flagged similar wildcard imports elsewhere in the crate.

The `wildcard_imports` lint is **pedantic** and is NOT currently enforced by CI (CI uses `-D warnings` which does not include pedantic lints). However, the fix is still correct as a code quality improvement.

## Decision

Replace `use super::*;` at line 608 in the `sample_receipts` module with explicit named imports of the symbols actually used from `super`:

```rust
// Before:
use super::*;

// After:
use super::{
    CHECK_SCHEMA_V1, CheckReceipt, DiffMeta, Finding, Scope, Severity, ToolMeta, Verdict,
    VerdictCounts, VerdictStatus,
};
```

This approach:
- Matches the fix already proven in commit `b53f261` on branch `feat/work-8b588be9/wildcard-imports-fix`
- Enumerates exactly the 10 symbols required by the module
- Makes symbol provenance explicit and refactoring safer

## Consequences

**Benefits:**
- Callers can determine exact symbol provenance without reading parent module
- Tools can build accurate import graphs
- Refactoring is safer (missing symbols produce compile errors, not silent breakage)
- Matches the established pattern from issue #335 resolution

**Tradeoffs:**
- Import lines are more verbose (10 symbols vs 1 glob)
- Risk of missing a symbol if the module evolves without updating imports (mitigated by `cargo check`)
- The identical pattern at line 17 (`sample_configs`) remains unfixed per issue scope

## Alternatives Considered

### 1. Do nothing
**Rejected** — Issue #424 is valid. The wildcard import obscures provenance and the fix is straightforward.

### 2. Add `deny(clippy::wildcard_imports)` to crate root
**Deferred** — Adding a crate-wide deny lint is a separate architectural decision that affects the entire `diffguard-testkit` crate. Per maintainer recommendation, this should be a follow-up issue, not part of this fix. It would also need to address line 17 (`sample_configs`).

### 3. Use a glob re-export in the parent module
**Rejected** — A re-export like `pub use diffguard_types::{...}` in the parent still obscures which symbols the child module actually uses. It also doesn't solve the problem for external callers.

### 4. Restructure to avoid super:: imports entirely
**Rejected** — Moving the symbols to module-root level or passing them as function arguments would be a significant architectural change disproportionate to the issue. The types are defined in `diffguard_types` and imported at the file level; re-exporting through `super` is the idiomatic pattern here.

## Out of Scope (Technical Debt)

- **Line 17 (`sample_configs`)** — Has the identical wildcard import pattern but is not mentioned in issue #424. Should be fixed in a follow-up issue.
- **Crate-wide deny lint** — Deferred to a future ADR.
