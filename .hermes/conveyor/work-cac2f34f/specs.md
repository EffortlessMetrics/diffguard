# Specs: Fix CLI Error Output to Use Display Format

**Work Item:** work-cac2f34f

**Repo:** diffguard

---

## Feature Description

Change the CLI error handler in `crates/diffguard/src/main.rs` to use Display format (`{err}`) instead of debug format (`{err:?}`) when printing top-level errors to stderr. This produces user-facing error messages rather than verbose implementation-focused output.

---

## Acceptance Criteria

### AC-1: Code Change
- [ ] Line 642 in `crates/diffguard/src/main.rs` changed from `eprintln!("{err:?}");` to `eprintln!("{err}");`

### AC-2: Compilation
- [ ] `cargo check -p diffguard` completes successfully with no errors

### AC-3: Tests Pass
- [ ] `cargo test -p diffguard` passes all existing tests (56 tests)

### AC-4: Exit Code Preserved
- [ ] Exit code remains `1` on error (Stable API contract unchanged)

### AC-5: No Other Files Modified
- [ ] Change is isolated to `crates/diffguard/src/main.rs:642`

---

## Non-Goals

1. **No error handling logic changes** — only output format changes
2. **No new tests added** — the `#[cfg(not(test))]` code path is not covered by unit tests; this is a pre-existing structural gap not addressed by this change
3. **No prefix addition** — the plan review recommended considering `diffguard: error: {err}` but this is optional polish, not required

---

## Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| `anyhow::Error` Display impl | Guaranteed | `anyhow::Error` always implements Display by design contract |
| `run_with_args()` return type | Confirmed | Returns `Result<i32>` using `anyhow::Result` (line 648-653) |
| Branch existence | Required | `feat/work-cac2f34f/diffguard` must exist before commit |

---

## Verification Plan

1. **Pre-patch baseline** (optional): Run `cargo check -p diffguard` and `cargo test -p diffguard` to confirm clean state
2. **Apply patch**: Change `{err:?}` → `{err}` at line 642
3. **Post-patch verification**: Run `cargo check -p diffguard` and `cargo test -p diffguard`
4. **Commit**: Stage and commit with message following conventions

---

## File Locations

| File | Path |
|------|------|
| ADR | `/home/hermes/.hermes/state/conveyor/work-cac2f34f/adr-001-cli-error-display-format.md` |
| Specs | `/home/hermes/.hermes/state/conveyor/work-cac2f34f/specs.md` |
| Implementation | `crates/diffguard/src/main.rs:642` |
