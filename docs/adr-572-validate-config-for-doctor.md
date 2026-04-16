# ADR: Use Idiomatic `Option<&PathBuf>` for `validate_config_for_doctor`

## Status
Accepted

## Context

The function `validate_config_for_doctor` in `crates/diffguard/src/main.rs:1008` has the signature:

```rust
fn validate_config_for_doctor(config_path: &Option<PathBuf>, explicit_config: bool) -> bool
```

This `&Option<PathBuf>` pattern forces callers to double-reference when passing an `Option<PathBuf>` value. For example, when `config_path: Option<PathBuf>`, the caller must write `&config_path`, creating an awkward `&Option<PathBuf>`. This is less idiomatic than passing `Option<&PathBuf>` directly.

While the issue title claims `clippy::ptr_arg` lint flags this pattern, verification confirmed that `clippy::ptr_arg` does **not** fire on `&Option<PathBuf>` in Rust 1.92 / Clippy 1.92 (the lint covers `&Vec<T>`, `&String`, `&HashMap<K,V>`, `&HashSet<T>`, and `&OsString` — not `&Option<T>`). However, the API idiom improvement is still valid and worthwhile.

## Decision

Change the function signature to use `Option<&PathBuf>` instead of `&Option<PathBuf>`:

**Before:**
```rust
fn validate_config_for_doctor(config_path: &Option<PathBuf>, explicit_config: bool) -> bool
```

**After:**
```rust
fn validate_config_for_doctor(config_path: Option<&PathBuf>, explicit_config: bool) -> bool
```

Update the single call site from `&config_path` to `config_path.as_ref()`:

**Before:**
```rust
all_pass &= validate_config_for_doctor(&config_path, args.config.is_some());
```

**After:**
```rust
all_pass &= validate_config_for_doctor(config_path.as_ref(), args.config.is_some());
```

The `as_ref()` call converts `Option<PathBuf>` to `Option<&PathBuf>` without cloning — it is zero-cost at runtime.

## Consequences

### Benefits
- **Cleaner API**: Callers can pass `Some(&path)` directly, which is more intuitive
- **Idiomatic Rust**: Follows the convention of `Option<T>` being on the outside, not wrapping a reference
- **No behavior change**: Pure type-level refactor
- **Zero runtime cost**: `as_ref()` on `Option<T>` is optimized away by the compiler
- **Isolated scope**: Only one function and one call site affected; no other `&Option<T>` patterns exist in the codebase

### Tradeoffs/Downsides
- **Issue motivation discrepancy**: The issue title incorrectly attributes this to `clippy::ptr_arg`. The fix should be described as an API idiom improvement, not a lint fix.
- **Minimal change scope**: Two lines in one file — negligible risk

## Alternatives Considered

### 1. Keep `&Option<PathBuf>`
**Decision: Rejected**

While functionally equivalent, `&Option<PathBuf>` is an awkward pattern that forces callers into double-referencing. The API is genuinely improved by using `Option<&PathBuf>`.

### 2. Change to `Option<PathBuf>` (consume the option)
**Decision: Rejected**

The caller needs to retain `config_path` after this call for other uses. Consuming the `Option<PathBuf>` would require cloning, which is unnecessary overhead.

### 3. Keep as-is (no change)
**Decision: Rejected**

The current API is less idiomatic. Even without a lint warning, improving API quality is worthwhile.

## Scope

**Covers:**
- `crates/diffguard/src/main.rs` line 1008: function signature change
- `crates/diffguard/src/main.rs` line 1001: call site update

**Does not cover:**
- Any other functions or files
- Any behavior changes
- Any other `&Option<T>` patterns (none exist in codebase)