# ADR-012: Remove Redundant `Language::Json` Match Arm in `string_syntax()` (Issue #452)

**Status:** Proposed

**Date:** 2026-04-27

**Work Item:** work-1f927a4d

**Supersedes:** ADR-011 (work-5d83e2c9, issue #136) — same decision applied to issue #452

---

## Context

GitHub issue #452 reports a redundant match arm in `preprocess.rs` where `Language::Yaml | Language::Toml | Language::Json` is explicitly matched in the `string_syntax()` function alongside a wildcard (`_`) pattern that produces the same result (`StringSyntax::CStyle`).

**However**, the issue's core premise is factually incorrect. The issue claims that "the wildcard `_` already covers Yaml, Toml, and Json." This is wrong — in Rust, the wildcard only catches variants NOT explicitly matched. Currently:

- Line 107 explicitly handles `Yaml | Toml | Json`
- Line 109 wildcard catches `C, Cpp, CSharp, Java, Kotlin, Unknown` — NOT Yaml/Toml/Json

The arm is **redundant** (removable without behavior change), not **unreachable** (already caught by wildcard).

This work item (issue #452) requests the same fix as ADR-011 (issue #136): remove only `Json` from the arm, keeping `Yaml | Language::Toml` explicit.

---

## Decision

Follow ADR-011's decision: **remove only `Language::Json`** from the match arm, keeping `Yaml | Language::Toml` explicit.

**Changes to `string_syntax()` (lines 106-109):**

Before:
```rust
// YAML/TOML/JSON strings are C-style-like in this best-effort model
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
// All other languages (C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

After:
```rust
// YAML/TOML strings are C-style-like in this best-effort model
// (JSON is handled by the wildcard below since JSON uses C-style strings)
Language::Yaml | Language::Toml => StringSyntax::CStyle,
// All other languages (including JSON, C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

---

## Alternatives Considered

### Option A: Remove entire arm (Yaml | Toml | Json) — as literal issue #452 request
- ❌ Issue's premise is factually incorrect (wildcard doesn't cover explicitly-matched arms)
- ❌ Conflicts with ADR-011 decision
- ❌ Would break existing tests (`yaml_and_toml_have_explicit_arms_not_wildcard`)
- ❌ Removes valuable type-level documentation that YAML/TOML are intentional special cases
- ❌ Less clear about YAML/TOML configuration-language special case

### Option B: Remove only Json, keep Yaml | Toml explicit (ADR-011 approach) ✅
- ✅ Aligns with existing ADR-011
- ✅ Matches pattern in `comment_syntax()` which explicitly handles YAML/TOML
- ✅ Preserves explicit handling for configuration languages (YAML/TOML may need distinct handling in future)
- ✅ Existing tests pass without modification
- ✅ Maintains code-as-documentation

**Selected:** Option B

---

## Consequences

**Positive:**
- Eliminates redundant match arm warning from clippy (if any)
- Improves code clarity by documenting JSON is handled by wildcard
- Consistency with `comment_syntax()` function pattern
- No functional change — behavior is identical
- YAML/TOML remain explicit for future maintainability

**Negative:**
- Does not fully "resolve" issue #452's literal request (which was based on incorrect premise)

**Neutral:**
- The change is purely cosmetic — no runtime behavior changes
- This ADR is essentially a re-affirmation of ADR-011 for issue #452

---

## Risk Assessment

- **Severity:** Very Low (cosmetic/code cleanup)
- **Functional change:** None — both paths produce `StringSyntax::CStyle`
- **Regression risk:** Negligible
- **Test impact:** Existing tests in `red_tests_work_5d83e2c9.rs` remain valid

---

## Files Affected

- `crates/diffguard-domain/src/preprocess.rs` — modify `string_syntax()` match arm (lines 106-109)

---

## References

- [ADR-011: Remove Redundant `Language::Json` Match Arm](adr-011-redundant-match-arm.md) — prior decision for issue #136
- [Issue #452](https://github.com/EffortlessMetrics/diffguard/issues/452) — this work item's source issue
- [Issue #136](https://github.com/EffortlessMetrics/diffguard/issues/136) — similar issue addressed by ADR-011