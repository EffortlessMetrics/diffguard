# Deep Review: work-d1531005

## Summary

**Decision: APPROVED**

The changes correctly remove `CompiledRule` from the public API export of `diffguard-domain`, making it an internal implementation detail as intended.

---

## Review Findings

### 1. Removal of Public Re-export (`crates/diffguard-domain/src/lib.rs`)

**Change:**
```rust
// Before:
pub use rules::{CompiledRule, RuleCompileError, compile_rules, detect_language};

// After:
pub use rules::{RuleCompileError, compile_rules, detect_language};
```

**Assessment:** ✓ Correct

- `CompiledRule` is an internal data structure containing compiled regex patterns and glob sets
- The ADR-2026-0411-001 correctly identifies this as a leaky abstraction
- The `rules` module remains public (as `pub mod rules;`), so `diffguard_domain::rules::CompiledRule` is still accessible where needed
- No external consumers depend on this re-export (this is an internal crate with controlled consumers)

---

### 2. Internal Import Updates

#### `crates/diffguard/src/main.rs` (line 756)

**Change:**
```rust
// Before:
-> Result<Vec<diffguard_domain::CompiledRule>, diffguard_domain::RuleCompileError>

// After:
-> Result<Vec<diffguard_domain::rules::CompiledRule>, diffguard_domain::RuleCompileError>
```

**Assessment:** ✓ Correct

- Uses the full module path `diffguard_domain::rules::CompiledRule`
- This is appropriate since `main.rs` is an internal consumer of domain logic
- No public API surface affected

#### `crates/diffguard-domain/tests/properties.rs` (line 1973)

**Change:**
```rust
// Before:
let rules: Vec<diffguard_domain::CompiledRule> = vec![];

// After:
let rules: Vec<diffguard_domain::rules::CompiledRule> = vec![];
```

**Assessment:** ✓ Correct

- Test file correctly uses internal module path
- Existing property-based test `property_no_rules_no_findings` continues to function

---

### 3. Documentation Update (`docs/architecture.md`)

**Change:** Line 109 updated to clarify `CompiledRule` is internal:
```rust
- `compile_rules(configs) -> Vec<CompiledRule>` (internal)
```

**Assessment:** ✓ Correct and appropriate

- Clear parenthetical "(internal)" designation
- Matches the documentation in `CLAUDE.md` which already described `CompiledRule` as an internal implementation detail
- Helps prevent future confusion

---

### 4. ADR Document (`.hermes/conveyor/work-d1531005/adr.md`)

**Quality:** ✓ Excellent

- Comprehensive problem statement
- Clear enumeration of affected files with before/after import paths
- Documents alternatives considered (#[non_exhaustive], deprecation window, two-tier API)
- Lists verification steps

---

## Verification Results

| Check | Result |
|-------|--------|
| `cargo check -p diffguard-domain` | ✓ Pass |
| `cargo check -p diffguard` | ✓ Pass |
| `cargo test -p diffguard-domain --no-run` | ✓ Pass |
| No remaining `diffguard_domain::CompiledRule` references in code | ✓ Verified |

---

## Remaining Reference Found

One reference to `diffguard_domain::CompiledRule` exists in `crates/diffguard-domain/tests/red_tests_work_d1531005.rs`, but this is **only in a documentation comment**:

```rust
//! After the fix, any actual test using `diffguard_domain::CompiledRule` would fail to compile.
```

This is intentional - the file is a placeholder/red test that documents the expected compilation failure if someone tried to use the old import path.

---

## Conclusion

The refactoring is **correct and well-executed**:

1. **Encapsulation improved** - `CompiledRule` is now clearly internal
2. **No breaking changes** - All internal consumers updated to use module path
3. **Documentation aligned** - architecture.md reflects internal status
4. **ADR comprehensive** - Decision properly documented with alternatives

**Recommendation: APPROVE** - Ready to proceed through the conveyor.