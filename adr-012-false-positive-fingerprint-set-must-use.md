# ADR-012: Add `#[must_use]` to `false_positive_fingerprint_set()`

**Status:** Proposed

**Date:** 2026-04-18

**Work Item:** work-ea81e659

---

## Context

The function `false_positive_fingerprint_set()` in `crates/diffguard-analytics/src/lib.rs` returns an owned `BTreeSet<String>` but lacks the `#[must_use]` attribute. If a caller discards the result (e.g., writes `false_positive_fingerprint_set(&baseline);` without assigning or using the return value), the entire set of fingerprints is silently dropped by the Rust compiler. This could cause the caller to incorrectly believe the baseline fingerprints were loaded/processed when they were not.

This issue was introduced when commit `1329225` (fix #522) added `#[must_use]` to three sister functions (`normalize_false_positive_baseline`, `fingerprint_for_finding`, `baseline_from_receipt`) but inadvertently missed `false_positive_fingerprint_set`.

---

## Decision

Add `#[must_use]` attribute to `false_positive_fingerprint_set()` in `crates/diffguard-analytics/src/lib.rs`, placing it between the doc comment (line 138) and the function declaration (line 139), matching the established pattern of its sister functions.

---

## Consequences

### Benefits
- **Prevents silent data loss**: Callers that discard the return value will now receive a compiler warning, preventing false positives from being incorrectly processed
- **Consistency**: Aligns `false_positive_fingerprint_set()` with the three other similar functions that already have `#[must_use]`
- **No breaking changes**: Existing code that correctly uses the return value continues to work unchanged
- **Pure addition**: The attribute is a compile-time lint; no runtime overhead

### Risks
- **None identified**: This is a purely additive lint attribute that produces warnings rather than errors

---

## Alternatives Considered

### 1. Leave as-is (reject)
Accepting the current state means accepting that future callers could silently lose data. This contradicts the codebase's explicit `#[must_use]` campaign evident in commits `1329225`, `e0c2094`, and `3e1d9e1`. Not acceptable.

### 2. Add `#[must_use]` + documentation (deferred)
Some teams prefer updating doc comments when adding `#[must_use]`. However, the existing doc comment ("Returns the baseline as a fingerprint set for fast lookup") already makes the return value's importance clear. No doc change is necessary for this trivial fix.

### 3. Expand scope to other functions (rejected)
Other functions in `diffguard-analytics` (`merge_false_positive_baselines`, `normalize_trend_history`, `append_trend_run`, etc.) also lack `#[must_use]`. However, issue #540 specifically targets only `false_positive_fingerprint_set`. Expanding scope would delay resolution and increase risk. These can be addressed in follow-up issues.

---

## Related Decisions
- ADR-011 (various): Original `#[must_use]` additions for `normalize_false_positive_baseline`, `fingerprint_for_finding`, `baseline_from_receipt` (commit `1329225`)