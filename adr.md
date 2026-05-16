# ADR-034: Inline Format Arguments in diffguard CLI

## Status
Proposed

## Context

GitHub issue #416 reports ~20 instances of `clippy::uninlined_format_args` warnings in `crates/diffguard/src/main.rs`. These occur when a variable is passed as a standalone `{}` format argument (e.g., `format!("{}", e)`) instead of being inlined into the format string (e.g., `format!("{e}")`).

The `diffguard` project enforces `cargo clippy --workspace --all-targets -- -D warnings` in CI, and a prior precedent (commit `d192d33`, issue #505) established inlining format arguments as the project standard when fixing `xtask`.

The fix is purely syntactic — no logic changes, no behavioral changes — but the issue scope is limited to `crates/diffguard/src/main.rs` only (20 locations), while the same lint produces ~94 additional warnings across other crates.

## Decision

Fix all 20 `clippy::uninlined_format_args` warnings in `crates/diffguard/src/main.rs` by inlining format arguments using `cargo clippy --fix`, supplemented by manual fixes for any cases clippy cannot auto-fix.

**Implementation approach:**
1. Run `cargo clippy -p diffguard --fix --lib -- -W clippy::uninlined_format_args` for library target
2. Run `cargo clippy -p diffguard --fix --tests -- -W clippy::uninlined_format_args` for test target  
3. Manual patch for any remaining unfixable locations
4. Verify with `cargo clippy -p diffguard --all-targets -- -W clippy::uninlined_format_args`

**Scope boundaries:**
- **In-scope**: 20 locations in `crates/diffguard/src/main.rs` (lib and test code within that file)
- **Out-of-scope**: Warnings in `diffguard-core`, `diffguard-types`, `presets.rs`, and other files — these are separate work items

**Semantic fix note**: Line 2880 (`bail!("No rules match filter '{}'", filter)`) has a latent bug — `'{}'` is a literal, so the `filter` variable was silently ignored. The fix will correct this to actually display the filter value in error messages.

## Consequences

### Benefits
- **Readability**: `{e}` is more scannable than `format!("{}", e)` in CLI output code
- **Consistency**: Aligns with the project's established precedent (commit `d192d33`)
- **CI compliance**: Removes warnings that would break the lint gate if enforced later
- **Correctness**: Fixes the latent semantic bug at line 2880 where `filter` was ignored

### Tradeoffs
- **Narrow scope**: The ~94 warnings in other crates remain unfixed, creating短期内 inconsistency
- **Pre-existing test error**: `green_tests_work_d4a75f70.rs:119` has a compile error that blocks test target fixes — must be addressed separately
- **Risk of scope creep**: Running `--fix --tests` also fixes `presets.rs` (7 warnings) — discipline required to stay within scope

### Risks
- Very low: The change is mechanical, clippy verifies correctness, and no logic changes occur

## Alternatives Considered

### 1. Manual-only fix
Reject `cargo clippy --fix` and manually edit all 20 locations.
- **Rejected because**: Too time-consuming for identical-pattern fixes; clippy auto-fix is well-tested and deterministic.

### 2. Suppress lint with `#[allow()]`
Add `#[allow(clippy::uninlined_format_args)]` to suppress warnings rather than fix them.
- **Rejected because**: Goes against the issue intent (#416 specifically asks to fix them), leaves codebase inconsistent with established project standard.

### 3. Fix entire workspace at once
Extend scope to fix all ~114 warnings across all crates simultaneously.
- **Rejected because**: Issue #416 is scoped specifically to main.rs; broader scope risks diffusion of responsibility and makes review harder.

## References
- GitHub Issue: #416
- Prior precedent: commit `d192d33` (issue #505, xtask uninlined format args)
- Lint: `clippy::uninlined_format_args`
- File: `crates/diffguard/src/main.rs`
