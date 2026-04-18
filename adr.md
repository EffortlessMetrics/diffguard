# ADR — Add #[must_use] to split_lines() in diffguard-lsp

## Status
**Proposed**

## Context

The `split_lines()` function in `crates/diffguard-lsp/src/text.rs` (line 6) is a public utility function that returns `Vec<&str>`. If callers accidentally ignore the return value — writing `split_lines(text);` as a statement instead of `let lines = split_lines(text);` — the code silently does nothing. No compiler warning is emitted because the function lacks the `#[must_use]` attribute.

This is a correctness hazard because `split_lines` performs non-trivial work (splitting text into lines) and callers who forget to capture the result will have logic bugs that are hard to detect.

The same file already uses `#[must_use]` on two other public functions returning non-()`:` `build_synthetic_diff` (line 31) and `utf16_length` (line 121), establishing a deliberate pattern in this module. The broader workspace also uses `#[must_use]` consistently across `diffguard-types` (4 instances) and `diffguard-diff` (2 instances, documented in CHANGELOG for `#329`).

## Decision

Add the `#[must_use]` attribute to `pub fn split_lines(text: &str) -> Vec<&str>` at line 6 of `crates/diffguard-lsp/src/text.rs`.

This is a purely additive compile-time change with zero runtime impact.

## Consequences

### Benefits
- Compile-time enforcement prevents silent discarding of `split_lines` return values
- Aligns `split_lines` with the existing `#[must_use]` pattern already used in the same file (lines 31, 121)
- Extends the established workspace convention for `#[must_use]` on value-returning utility functions
- Zero runtime cost, zero API change, zero behavioral change

### Tradeoffs / Risks
- **External callers that discard the return value** will now receive compiler warnings. This is the **intended** behavior — the warning correctly flags a bug in the calling code.
- No internal callers in the crate itself discard the return value (verified: lines 15, 16, 37 all use direct assignment), so no warnings are introduced within the crate.

## Alternatives Considered

### 1. Do Nothing
**Rejected.** The bug is real — a function that silently no-ops when called as a statement is a correctness hazard. The absence of a warning is misleading.

### 2. Rename the Function
**Rejected.** A name like `split_lines_into()` or `get_lines()` would hint at the return-value requirement but does not actually enforce it. It also breaks the public API and any external callers.

### 3. Add Documentation Only
**Rejected.** Documentation can be missed. Compiler enforcement via `#[must_use]` is more robust and aligns with the existing deliberate pattern in this codebase.

### 4. Suppress the Warning with `let _ =`
**Rejected.** This is the workaround callers can use if they intentionally discard the value — but the attribute should be present to catch accidental discards. The attribute itself does not prevent `let _ = split_lines(...)` from working.
