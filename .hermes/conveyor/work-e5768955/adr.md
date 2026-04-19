# ADR: Change `exit_code` from `i32` to `u8` Throughout the Call Chain

## Status
Proposed

## Context

The `CheckRun.exit_code` field in `diffguard-core/src/check.rs:52` is typed as `i32`, but exit codes are semantically in the range 0..=255 (per POSIX). The value flows through `compute_exit_code()` (which returns only 0, 2, or 3) and `compute_baseline_exit_code()` up to `run_with_args()` in `crates/diffguard/src/main.rs`, finally reaching `main()` at line 646 where it is cast to `u8` via a `clamp + as u8` pattern:

```rust
std::process::ExitCode::from(code.clamp(i32::from(u8::MIN), i32::from(u8::MAX)) as u8)
```

This is a **type safety issue**, not a runtime bug for current values (0, 2, 3 pass through unchanged). However, using `i32` allows future code to produce values outside 0..=255 that would be silently truncated to 255 by the `clamp` before casting — a class of bug that should be impossible at compile time.

The codebase has an established precedent: commit `e38e907` fixed similar lossy `usize→u32` casts with `TryFrom`, showing the project corrects type-level semantic mismatches.

## Decision

Change `exit_code` from `i32` to `u8` throughout the exit-code return chain, making invalid values (outside 0..=255) a compile-time error rather than a runtime truncation:

1. **`diffguard-core/src/check.rs`**:
   - `CheckRun.exit_code: i32` → `u8`
   - `fn compute_exit_code(...) -> i32` → `-> u8`

2. **`crates/diffguard/src/main.rs`**:
   - `fn compute_baseline_exit_code(...) -> i32` → `-> u8`
   - `fn cmd_check(...) -> Result<i32>` → `Result<u8>`
   - `fn cmd_check_inner(...) -> Result<i32>` → `Result<u8>`
   - `fn cmd_validate(...) -> Result<i32>` → `Result<u8>`
   - `fn cmd_doctor(...) -> Result<i32>` → `Result<u8>`
   - `fn cmd_test(...) -> Result<i32>` → `Result<u8>`
   - `fn run_with_args(...) -> Result<i32>` → `Result<u8>`
   - Simplify `main()`: remove the `clamp + as u8` pattern, use `ExitCode::from(code)` directly

3. **Literal type annotations**: Add explicit `u8` suffix (`Ok(0u8)`, `Ok(1u8)`) to all `Ok(...)` literals in the affected functions to avoid type inference ambiguity.

4. **Unaffected functions**: `cmd_rules`, `cmd_explain`, `cmd_sarif`, `cmd_junit`, `cmd_csv`, `cmd_init`, `cmd_trend` all return `Result<()>`. They are called with `?` and wrapped as `Ok(0u8)` in `run_with_args()` — no changes to their signatures needed.

## Consequences

### Benefits
- **Compile-time enforcement of exit code range**: Invalid exit code values (outside 0..=255) become compile errors, not silent truncations
- **Semantic correctness**: `u8` is the correct type for exit codes (0..=255 per POSIX)
- **Removes runtime overhead**: The `clamp` call is eliminated from the hot path
- **Self-documenting code**: The `u8` type communicates the valid range to future developers
- **Precedent established**: Similar to commit `e38e907` which fixed lossy `usize→u32` casts

### Tradeoffs / Risks
- **Breaking API change**: `CheckRun.exit_code` is a public field. Any external consumer of `diffguard-core` reading `run.exit_code` as `i32` would break. However, this is a correcting change — the type was always semantically wrong.
- **Width of change**: The type change propagates through 8 functions across 2 crates. This is mechanical but requires careful enumeration.
- **Literal type annotations required**: Without explicit `Ok(0u8)` / `Ok(1u8)` suffixes, Rust infers `Ok(0)` as `Result<i32, _>`. All 10+ literal sites must be updated.
- **Integration test `DiffguardResult.exit_code` is unaffected**: This is the OS-level exit code from `Command::output()?.status.code()`, not `CheckRun.exit_code`. No integration test changes needed.

## Alternatives Considered

### 1. Keep `i32`, Fix Only the `clamp` Pattern
Keep `CheckRun.exit_code` as `i32`, but change `main()` to use `TryFrom` or a checked cast instead of `clamp + as u8`.

**Rejected because**: This doesn't address the root cause — `exit_code` being `i32` allows out-of-range values to be stored in `CheckRun`. A future code change to `compute_exit_code` could silently produce invalid exit codes. The type should make invalid states unrepresentable.

### 2. Add a Newtype `ExitCode` Enum
Define an `enum ExitCode { Pass, PolicyFail, WarnFail }` or a newtype wrapper.

**Rejected because**: Overkill for a type-level correction. The documented stable API exit codes (0, 1, 2, 3) are plain integers and changing to an enum would be a larger API redesign. The `u8` primitive is sufficient and aligns with POSIX conventions.

### 3. Do Nothing
Leave `exit_code` as `i32` with the `clamp + as u8` pattern.

**Rejected because**: This allows silent truncation bugs if `compute_exit_code` ever returns a value outside 0..=255. The codebase has an explicit emphasis on type-level correctness; doing nothing leaves a known safety issue unfixed.
