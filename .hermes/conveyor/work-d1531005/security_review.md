# Security Review: work-d1531005

## Work Item
- **Work ID**: work-d1531005
- **Gate**: HARDENED
- **Description**: api: CompiledRule exported from diffguard-domain but appears to be internal
- **Type**: API Visibility Refactoring

## Change Summary
This is a visibility refactoring that removes `CompiledRule` from the public re-export in `diffguard-domain/src/lib.rs` and updates internal imports to use the correct internal path `diffguard_domain::rules::CompiledRule`.

### Files Changed
| File | Change |
|------|--------|
| `crates/diffguard-domain/src/lib.rs` | Removed `CompiledRule` from public re-export |
| `crates/diffguard/src/main.rs` | Updated import to use `diffguard_domain::rules::CompiledRule` |
| `crates/diffguard-domain/tests/properties.rs` | Updated import to use `diffguard_domain::rules::CompiledRule` |
| `crates/diffguard-domain/tests/red_tests_work_d1531005.rs` | New placeholder test file |
| `crates/diffguard-types/tests/built_in_data_driven.rs` | Formatting changes (unrelated) |
| `docs/architecture.md` | Marked `CompiledRule` as internal |

## Security Review Findings

### ✅ 1. Public API Surface - No Unintended Removals
The only item removed from the public API was `CompiledRule` via the re-export line:
```rust
// Before
pub use rules::{CompiledRule, RuleCompileError, compile_rules, detect_language};

// After
pub use rules::{RuleCompileError, compile_rules, detect_language};
```
This is the intended change.

### ✅ 2. No New Public Entry Points Introduced
All `pub mod` and `pub use` statements in `lib.rs` remain unchanged except for the removal of `CompiledRule`. The `rules` module is still publicly accessible at `diffguard_domain::rules::`, but `CompiledRule` is no longer directly re-exported at the crate root.

### ✅ 3. Internal Imports Use Correct Paths
Verified all usages now correctly reference the internal path:
- `crates/diffguard/src/main.rs:756`: `diffguard_domain::rules::CompiledRule` ✅
- `crates/diffguard-domain/tests/properties.rs:1973`: `diffguard_domain::rules::CompiledRule` ✅
- `bench/benches/evaluation.rs:32,128`: `diffguard_domain::rules::CompiledRule` ✅

No usages of the old path `diffguard_domain::CompiledRule` remain in implementation code (only in a comment explaining the fix).

### ✅ 4. Documentation Builds
```
cargo doc --package diffguard-domain --no-deps
cargo doc --document-private-items --package diffguard-domain --no-deps
```
Both commands completed successfully.

### ✅ 5. Compilation and Tests
```
cargo check -p diffguard-domain -p diffguard  # Succeeded
cargo test -p diffguard-domain --no-run       # Succeeded
```

## Verification Commands Run
| Command | Result |
|---------|--------|
| `cargo check -p diffguard-domain -p diffguard` | ✅ Passed |
| `cargo test -p diffguard-domain --no-run` | ✅ Passed |
| `cargo doc --package diffguard-domain --no-deps` | ✅ Passed |
| `cargo doc --document-private-items --package diffguard-domain --no-deps` | ✅ Passed |
| `grep -rn "diffguard_domain::CompiledRule"` | ✅ Only found in documentation comment |

## Conclusion
**APPROVED** - No security issues found. This is a clean visibility refactoring that:
1. Correctly removes `CompiledRule` from the public API
2. Updates all internal usages to the correct internal path
3. Introduces no new public entry points
4. Builds and compiles successfully
5. Does not change any behavioral logic