# ADR-2024-XXXX: RustQuality Preset Documentation String Namespacing

## Status
Proposed

## Context

The `RustQuality` preset in `crates/diffguard/src/presets.rs` has two documentation strings that use shorthand rule names which do not match the actual rule IDs generated in the TOML output:

1. **Line 13** (enum variant doc comment): `/// Rust best practices (no_unwrap, no_dbg, no_todo, no_print)`
2. **Line 40** (description() method): `"Rust best practices (no unwrap, no dbg, no todo, no print)"`

However, `generate_rust_quality()` (lines 103-168) produces these rule IDs:
- `rust.no_unwrap` (line 104)
- `rust.no_expect` (line 115)
- `rust.no_dbg` (line 126)
- `rust.no_println` (line 137)
- `rust.no_todo` (line 148)
- `rust.no_unimplemented` (line 159)

The shorthand names (`no_todo`, `no_print`) do not match any actual rule ID. This creates a mismatch between documentation and generated output, eroding user trust in the preset documentation at a key user entry point (`diffguard init --preset rust-quality`).

## Decision

We will update the two documentation strings in `presets.rs` to use full namespaced rule IDs that match the generated TOML:

| Location | Current | New |
|----------|---------|-----|
| Line 13 (doc comment) | `(no_unwrap, no_dbg, no_todo, no_print)` | `(rust.no_unwrap, rust.no_dbg, rust.no_todo, rust.no_println)` |
| Line 40 (description) | `(no unwrap, no dbg, no todo, no print)` | `(rust.no_unwrap, rust.no_dbg, rust.no_todo, rust.no_println)` |

This aligns documentation with the actual generated rule IDs while maintaining brevity by omitting `rust.no_expect` and `rust.no_unimplemented` (which are intentionally excluded to keep the description concise).

## Consequences

### Benefits
- Documentation accurately reflects the actual generated rule IDs
- Users see consistent `rust.*` namespace names across documentation and TOML output
- Aligns with codebase convention of using `rust.*` namespace for all Rust-related rules
- Restores user trust in preset documentation accuracy

### Tradeoffs
- None. This is a pure documentation fix with no behavioral change.

### Risks
- None identified. The fix is surgical, self-contained, and touches only string literals.

## Alternatives Considered

### 1. Leave shorthand names (Rejected)
Keep the shorthand names (`no_todo`, `no_print`) in documentation. Rejected because users who see `no_todo` in the doc comment will not find a matching rule when they look at their generated TOML showing `rust.no_todo`. This creates unnecessary confusion at a key user entry point.

### 2. Expand to all 6 generated rules (Rejected as out of scope)
Update the doc comment and description to list all 6 generated rules (`rust.no_unwrap`, `rust.no_expect`, `rust.no_dbg`, `rust.no_println`, `rust.no_todo`, `rust.no_unimplemented`). Rejected because:
- The issue title specifically calls out "mismatches built-in rule names (no_todo vs rust.no_todo)" — the naming fix
- The 6-vs-4 documentation gap is a separate concern to be addressed in a follow-up issue
- Scope creep on a governed change conveyor wastes pipeline resources