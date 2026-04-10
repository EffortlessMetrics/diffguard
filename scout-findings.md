## Issue 1: Duplicate `RuleHitStat` structs with incompatible fields — API inconsistency across crates

**Crate:** `diffguard-domain` vs `diffguard-core`

**Severity:** Medium

**Description:**

`diffguard-domain` and `diffguard-core` each define their own `RuleHitStat` struct:

- `diffguard-domain/src/evaluate.rs` line 29:
  ```rust
  pub struct RuleHitStat {
      pub rule_id: String,
      pub total: u32,
      pub emitted: u32,
      pub suppressed: u32,
      pub info: u32,
      pub warn: u32,
      pub error: u32,
  }
  ```

- `diffguard-core/src/check.rs` line 64:
  ```rust
  pub struct RuleHitStat {
      pub rule_id: String,
      pub total: u32,
      pub emitted: u32,
      pub suppressed: u32,
      pub info: u32,
      pub warn: u32,
      pub error: u32,
      pub false_positive: u32,  // ← extra field not in domain type
  }
  ```

**Problem:**

1. `diffguard-domain` owns the domain logic but `diffguard-core` defines an extended version with an extra field (`false_positive`). This creates an awkward translation layer where `check.rs` maps from domain's `RuleHitStat` to its own (lines 210–213).

2. `diffguard-domain` is meant to be the foundational domain crate (I/O-free, pure logic). Having the core type defined there without `false_positive` is correct conceptually, but the duplication is confusing and error-prone.

3. The `false_positive` field is only tracked in `diffguard-core/check.rs` — consumers of `diffguard-domain`'s `Evaluation` struct cannot access per-rule false-positive counts even though they flow through the system.

**Recommendation:**

Move `RuleHitStat` to `diffguard-types` (which already holds all shared DTOs) as a single canonical type including `false_positive`. Update both `diffguard-domain` and `diffguard-core` to re-export from there. This would also make the type available to `diffguard-testkit` for property-based testing.

---

## Issue 2: `diffguard-testkit` missing `diffguard-diff` as a dependency — blocks comprehensive diff-based testing

**Crate:** `diffguard-testkit`

**Severity:** Low (dev-only, but still an API gap)

**Description:**

`diffguard-testkit` provides `DiffBuilder` for constructing unified diffs, but does not depend on `diffguard-diff`. The module comment in `diff_builder.rs` says it builds "valid unified diff strings," yet testing that the built diff is actually parseable requires `parse_unified_diff` from `diffguard-diff`.

Currently, only `fixtures.rs` (a test module) uses `diffguard_diff::parse_unified_diff` at line 828 — but this is in a `#[cfg(test)]` block. There is no way to use `diffguard_diff` types (like `DiffLine`) directly in testkit for building richer test helpers.

**Problem:**

The `DiffBuilder` API returns a raw `String`. Consumers who want to validate or inspect the parsed structure of a generated diff cannot do so using types from `diffguard-testkit` alone — they must bring in `diffguard-diff` directly.

**Recommendation:**

Add `diffguard-diff` as a regular (non-dev) dependency of `diffguard-testkit` so the crate can re-export `DiffLine` and `DiffStats` types for use in tests. Alternatively, document the expectation that consumers combine `diffguard-testkit` + `diffguard-diff` for full diff validation.

---

## Issue 3: `RuleOverrideMatcher` and `DirectoryRuleOverride` not publicly exported from `diffguard-domain`

**Crate:** `diffguard-domain`

**Severity:** Low

**Description:**

`diffguard-domain` has an `overrides.rs` module with:
- `DirectoryRuleOverride` — the raw input struct for per-directory overrides
- `RuleOverrideMatcher` — the compiled matcher used during evaluation
- `OverrideCompileError` — error type

The module is declared `pub mod overrides;` in `lib.rs`, but the key types are NOT re-exported at the crate root. Code consuming `diffguard-domain` must reach in via `diffguard_domain::overrides::RuleOverrideMatcher`.

The CLAUDE.md for `diffguard-domain` documents these as part of the public API ("Key APIs" section shows `RuleOverrideMatcher`), yet they are not on the same level as other exports like `compile_rules`, `evaluate_lines`, `SuppressionTracker`, etc.

**Recommendation:**

Add to `diffguard-domain/src/lib.rs` re-exports:
```rust
pub use overrides::{
    DirectoryRuleOverride, OverrideCompileError, ResolvedRuleOverride, RuleOverrideMatcher,
};
```

This matches the existing pattern (line 15–17 already does this but uses the full path). Currently this appears to already be done (line 15–17 shows these are exported), so this may already be resolved. Confirm and close if already present.

---

## Issue 4: `diffguard-testkit` test-only use of `diffguard_diff` in `fixtures.rs` — ad-hoc parsing not covered by testkit's schema validation

**Crate:** `diffguard-testkit`

**Severity:** Low

**Description:**

`fixtures.rs` at line 828 uses `diffguard_diff::parse_unified_diff` directly inside a `#[test]` function to verify that sample diffs parse correctly. This is good testing practice, but it reveals a gap:

- `schema.rs` validates `CheckReceipt` and `ConfigFile` against JSON schemas
- `DiffBuilder` produces diff strings
- There is no `DiffFile` / `DiffLine` / `DiffStats` type exposed from `diffguard-testkit`
- The connection between built diffs → parsed lines → validated receipts is not covered by the testkit's own public API

**Recommendation:**

This is related to Issue 2. If `diffguard-diff` is added as a dependency, consider adding a `validate_built_diff(diff: &str) -> Result<(Vec<DiffLine>, DiffStats), ...>` helper in `diff_builder.rs` or a new `diff_validator.rs` module.

---

## Issue 5: `Severity`, `Scope`, `FailOn`, `MatchMode` not fully re-exported from `diffguard-testkit` — inconsistent with stated API surface

**Crate:** `diffguard-testkit`

**Severity:** Low

**Description:**

Looking at `diffguard-testkit/src/lib.rs` lines 29–31, the crate re-exports:
```rust
pub use arb::{
    arb_fail_on, arb_glob_pattern, arb_regex_pattern, arb_rule_config, arb_scope, arb_severity,
};
```

It does NOT re-export the underlying types (`Severity`, `Scope`, `FailOn`, `MatchMode`). While these types live in `diffguard-types` and are accessible via `diffguard_testkit::arb::arb_severity()` returning `impl Strategy<Value = Severity>`, a consumer who wants to use `Severity` directly must:

```rust
use diffguard_types::Severity;  // Full path required
```

vs the expected:
```rust
use diffguard_testkit::Severity;  // Not available
```

**Recommendation:**

Add re-exports to `diffguard-testkit/src/lib.rs`:
```rust
pub use diffguard_types::{FailOn, MatchMode, Scope, Severity};
```

This follows the same pattern as `diffguard_types` being in `[dependencies]`, not just `[dev-dependencies]`, allowing it to be used as a broader test utilities crate.

---

*Scout agent findings for diffguard public API surface — April 2026*