# SPECS-2026-0411-001: Remove `CompiledRule` from Public API Export

**Work ID:** work-d1531005  
**Gate:** DESIGNED  
**Date:** 2026-04-11  

---

## Summary

Remove `CompiledRule` from the public re-export in `diffguard_domain::lib.rs`. Update 2 internal consumer files to import `CompiledRule` via the internal path `diffguard_domain::rules::CompiledRule`. Update documentation to clarify `CompiledRule` is an internal type.

---

## Changes

### 1. Remove `CompiledRule` from Public Re-export

**File:** `crates/diffguard-domain/src/lib.rs`  
**Line:** 19

**Before:**
```rust
pub use rules::{CompiledRule, RuleCompileError, compile_rules, detect_language};
```

**After:**
```rust
pub use rules::{RuleCompileError, compile_rules, detect_language};
```

**Rationale:** `CompiledRule` should not be part of the public API. It is an internal implementation detail.

---

### 2. Update `main.rs` Import

**File:** `crates/diffguard/src/main.rs`  
**Line:** ~756

**Before:**
```rust
) -> Result<Vec<diffguard_domain::CompiledRule>, diffguard_domain::RuleCompileError> {
```

**After:**
```rust
) -> Result<Vec<diffguard_domain::rules::CompiledRule>, diffguard_domain::RuleCompileError> {
```

---

### 3. Update `properties.rs` Test Import

**File:** `crates/diffguard-domain/tests/properties.rs`  
**Line:** ~1973

**Before:**
```rust
let rules: Vec<diffguard_domain::CompiledRule> = vec![];
```

**After:**
```rust
let rules: Vec<diffguard_domain::rules::CompiledRule> = vec![];
```

---

### 4. Update Architecture Documentation

**File:** `docs/architecture.md`  
**Line:** ~109

**Before:**
```
1. **rules.rs** - Rule compilation
   - `compile_rules(configs) -> Vec<CompiledRule>`
```

**After:**
```
1. **rules.rs** - Rule compilation
   - `compile_rules(configs) -> Vec<CompiledRule>` (internal)
```

**Rationale:** Clarify that `CompiledRule` is an internal type returned by `compile_rules`.

---

## Acceptance Criteria

- `cargo check -p diffguard-domain` succeeds
- `cargo check -p diffguard` succeeds
- `cargo check -p bench` succeeds
- `cargo test -p diffguard-domain` succeeds
- No remaining references to `diffguard_domain::CompiledRule` (only `diffguard_domain::rules::CompiledRule`)
- Architecture docs updated to clarify internal status

---

## Files Summary

| Action | File |
|--------|------|
| MODIFY | `crates/diffguard-domain/src/lib.rs` |
| MODIFY | `crates/diffguard/src/main.rs` |
| MODIFY | `crates/diffguard-domain/tests/properties.rs` |
| MODIFY | `docs/architecture.md` |

---

## Rollback Plan

Revert the changes to lib.rs by adding `CompiledRule` back to the `pub use` statement, and revert consumer imports.

---

## Dependencies

None — this is a refactoring change with no semantic modifications.
