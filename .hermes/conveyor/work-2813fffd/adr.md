# ADR-381: Use named variable placeholder `{err}` in server.rs format string

## Status
Accepted

## Context
GitHub issue #381 requests changing the format! macro at `server.rs` from using a positional placeholder (`{}`) to a named variable placeholder (`{err}`) for the `invalid didOpen params` error message.

The current code at line 552:
```rust
&format!("invalid didOpen params: {}", err),
```

Should become:
```rust
&format!("invalid didOpen params: {err}"),
```

This is part of a codebase hygiene initiative where named format arguments (`{var}`) are preferred over anonymous positional placeholders (`{}`) for clarity and consistency.

## Decision
We will change the format! macro at line 552 to use the named variable placeholder `{err}` instead of the positional placeholder `{}`.

The named placeholder:
- Is self-documenting (explicitly shows which variable is being formatted)
- Is consistent with other named format patterns in the codebase (`{match_mode}`, `{w}`, `{status}`, `{single}`, etc.)
- Produces identical runtime output (no behavioral change)
- Follows Rust best practices for format strings

## Consequences

### Benefits
- Improved code readability and self-documentation
- Consistency with codebase style guidelines
- Alignment with Rust best practices for format! macro usage

### Tradeoffs
- None — both forms produce identical runtime output

### Risks
- None — trivial format string change with no behavioral impact

## Alternatives Considered

### 1. Keep positional placeholder `{}`
Rejected because:
- Inconsistent with the codebase's named placeholder direction
- Less self-documenting when variable name is not obvious from context

### 2. Batch with other similar issues (9 other lines)
Rejected because:
- Issue #381 explicitly scopes this to a single line
- Other lines have separate issues filed (per the issue body)
- Keeping scope minimal reduces risk and accelerates single-issue resolution
