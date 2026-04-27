# ADR-456: Descriptor-Based Refactor of `run_conformance()`

## Status
Proposed

## Context

The `run_conformance()` function in `xtask/src/conform_real.rs` (lines 14–221, 172 non-blank/non-comment lines) violates `clippy::too_many_lines` (limit: 100). The function orchestrates 15 conformance tests sequentially, with each invocation following an identical pattern:

```rust
print!("  [N/15] Test name... ");
match test_xxx() {
    Ok(()) => { println!("PASS"); passed += 1; }
    Err(e) => { println!("FAIL: {e}"); failed += 1; }
}
```

This creates ~207 lines of repetitive match-arm boilerplate. The 15 test functions themselves are proper abstractions — the problem is exclusively the orchestration layer.

The issue is a code quality/maintainability problem. The function is CI-only (`xtask` binary) and does not ship in the production crate.

## Decision

We will refactor `run_conformance()` using a **descriptor-based iteration pattern**:

1. **Define a `ConformanceTest` struct** with explicit fields:
   - `position: u8` — the test number (1–15), explicit not derived from array index
   - `name: &'static str` — human-readable display name
   - `run: fn() -> Result<()>` — function pointer to the test
   - `skip_in_quick: bool` — whether to skip in `quick` mode

2. **Create a `run_test()` helper function** that centralizes:
   - Printing the `[N/15] name... ` header
   - Calling the test function
   - Printing PASS or FAIL
   - Returning `true`/`false`

3. **Define a static `CONFORMANCE_TESTS` array** listing all 15 tests in execution order with their metadata.

4. **Rewrite `run_conformance()`** to iterate over the static list, replacing ~207 lines of repetitive match arms with a ~15-line loop.

5. **Handle `test_vocabulary_constants`** (which returns `()` not `Result<()>`) via a named module-level wrapper function `fn run_vocabulary_constants_test() -> Result<()>` that calls the test and returns `Ok(())`.

### Key Design Decisions

- **Explicit `position: u8`** rather than deriving from array index via `enumerate()`. This makes position self-documenting and prevents silent misnumbering if tests are reordered in the array.
- **`fn() -> Result<()>` field type** for uniformity. All 14 `Result<()>` tests use direct function pointers. The one `()`-returning test uses a named wrapper.
- **`[N/15]` labels preserved as-is** even in quick mode (matching current behavior — the denominator is always 15, not the actual test count).
- **`#[cfg(test)]` module untouched** at lines 1435–1486.

## Consequences

### Benefits
- **Scannable test registry**: One data structure lists all conformance tests. A developer can answer "what tests exist?" by reading one array, not grepping across 200 lines.
- **Centralized output format**: Future changes to PASS/FAIL output (timestamps, colors, structured logging) require editing one function.
- **Extensible**: New fields on `ConformanceTest` (e.g., `timeout`, `requires_network`, `ci_only`) require editing the descriptor list and helper — not the orchestrator loop.
- **Trivially introspectable**: The list can be printed by a `--list` flag, counted, filtered.
- **Clippy-compliant**: The refactored `run_conformance()` will be ~15 lines, well under the 100-line limit.

### Tradeoffs / Risks
- **Silent omission risk**: If someone adds a test function but forgets to add it to `CONFORMANCE_TESTS`, it silently never runs. Mitigation: the current code has the same symmetric risk (forgotten call in the 15-match-arm block). A future smoke test can close this gap.
- **One more abstraction**: The descriptor struct and helper function add indirection. However, they are simple, idiomatic Rust with no magic — understandable in minutes.
- **`test_vocabulary_constants` wrapper**: A named wrapper function (`run_vocabulary_constants_test`) is required because closures cannot be stored in `fn()` fields. This adds one module-level function but keeps the descriptor list uniformly typed.

### What This Does NOT Change
- The 15 test functions themselves are unchanged.
- Output format (PASS/FAIL/SKIP messages) is preserved.
- Test ordering is preserved.
- `#[cfg(test)]` module at end of file is untouched.
- Production crate code is unaffected.

## Alternatives Considered

### 1. `#[allow(clippy::too_many_lines)]`
Do nothing; suppress the lint with an attribute on `run_conformance()`.

**Rejected because**: This is suppression, not refactoring. It papers over the symptom without addressing the disease. It sets a precedent that "long sequential functions are OK." The repetitive match arms remain, creating maintenance burden and a precedent that erodes codebase quality over time.

### 2. `macro_rules!` descriptor macro
Define a `conformance_test!($idx, $name, $func)` macro that generates the match-arm boilerplate.

**Rejected because**: The macro approach doesn't actually reduce clippy's line count — clippy counts source lines, not macro-expansion lines. The 15 macro calls in the function body would still violate the lint. It also introduces `macro_rules!` syntax that may be unfamiliar to contributors and sets a precedent for macro-heavy xtask code.

### 3. Do nothing
Leave `run_conformance()` as-is.

**Rejected because**: The function violates a clippy lint (when enabled with `-W`), the issue was filed, and the repetitive pattern creates ongoing maintenance burden. The codebase values clean architecture — orchestration should be declarative and scannable, not copy-paste sequential blocks.

### 4. Closure wrapper in descriptor list (initial plan)
Store `move || { test_vocabulary_constants(); Ok(()) }` inline in the descriptor list.

**Rejected because**: Closures cannot be stored in `fn()` fields. This would produce a compiler error. The fix is to use a named module-level wrapper function instead.

## References

- GitHub Issue: [#456](https://github.com/EffortlessMetrics/diffguard/issues/456)
- Primary file: `xtask/src/conform_real.rs`
- Issue title claims "1511 lines" — actual function is 208 lines, entire file is 1486 lines. Issue is valid in substance.
