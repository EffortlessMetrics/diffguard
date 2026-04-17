# ADR: Add `# Errors` Section to `verify_snake_case_fields`

## Status
Accepted

## Context
The public function `verify_snake_case_fields` in `crates/diffguard-testkit/src/schema.rs` returns `Result<(), Vec<String>>` but its doc comment lacks a `# Errors` section, triggering `clippy::missing_errors_doc`.

This is a pure documentation fix with no API or behavior change.

## Decision
Add a `# Errors` section to the doc comment of `verify_snake_case_fields` following the canonical style used throughout the codebase:
- Blank line after the `# Errors` header
- Prose describing the error variant (`Err(Vec<String>)` containing non-snake_case field names)

Do **not** use `#[allow(clippy::missing_errors_doc)]` suppression — there is no precedent for suppression in this codebase, and it would add technical debt by hiding the documentation gap.

## Canonical Style Reference
The established `# Errors` format (from `crates/diffguard-core/src/check.rs:86-92`):
```rust
/// # Errors
///
/// Returns an error if:
/// - [description of error conditions]
```

## Consequences

### Benefits
- Eliminates `clippy::missing_errors_doc` warning for this function
- Aligns with repo-wide documentation standards
- No logic or API changes — purely additive documentation

### Tradeoffs / Risks
- None — documentation-only change, no behavioral impact
- Internal crate (`publish = false`) — no downstream consumer impact

## Alternatives Considered

### 1. Suppress with `#[allow(clippy::missing_errors_doc)]`
Rejected: No suppression precedent in codebase. Adds technical debt. Does not improve documentation quality.

### 2. Document errors within `# Returns` section
Rejected: `clippy::missing_errors_doc` requires a dedicated `# Errors` section. The existing `# Returns` section only describes the `Ok(())` variant.

## Scope Constraint
This ADR addresses only `verify_snake_case_fields` (line 153 of `schema.rs`) per the issue title. Other functions in `schema.rs` (lines 50, 63, 71, 77) have the same gap but are out of scope for this change.
