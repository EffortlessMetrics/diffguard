# ADR-011: Remove Redundant `Language::Json` Match Arm in `string_syntax()`

**Status:** Accepted

**Date:** 2026-04-11

**Work Item:** work-5d83e2c9

---

## Context

GitHub issue #136 reports a redundant match arm in `preprocess.rs` where `Language::Json` is explicitly matched in the `string_syntax()` function but is then shadowed by a wildcard (`_`) pattern that produces the same result (`StringSyntax::CStyle`).

The problematic code at lines 107-109:
```rust
// YAML/TOML/JSON strings are C-style-like in this best-effort model
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
_ => StringSyntax::CStyle,
```

The wildcard `_` catches all `Language` variants not explicitly matched, including `Language::Json`. Since both paths produce `StringSyntax::CStyle`, the explicit `Language::Json` arm is redundant.

---

## Decision

Remove `Language::Json` from the match arm and update comments to clarify that JSON is handled by the wildcard.

**Changes:**

1. **Line 107-108:** Change `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,` to `Language::Yaml | Language::Toml => StringSyntax::CStyle,`

2. **Comment on line 107:** Update to: `// YAML/TOML strings are C-style-like in this best-effort model (JSON is handled by the wildcard below since JSON uses C-style strings)`

3. **Add comment to wildcard arm:** Add explanatory comment before `_ => StringSyntax::CStyle,` clarifying that all other languages (including JSON, C, C++, Java, etc.) use C-style strings.

This mirrors the pattern already used in `comment_syntax()` (lines 81-84) which has an identical comment structure acknowledging that JSON is handled by the wildcard.

---

## Alternatives Considered

### Option A: Remove only `Language::Json` from the arm (keep `Yaml | Toml`)
- ✅ Cleaner, minimal change
- ✅ Matches pattern in `comment_syntax()`
- ✅ Comment explains JSON is handled by wildcard

### Option B: Remove entire arm, let wildcard handle all
- ❌ Less clear about YAML/TOML special case
- ❌ Comment explains YAML/TOML/JSON together

### Option C: Leave as-is (no change)
- ❌ Compiler warning for redundant pattern
- ❌ Confusing for future maintainers

**Selected:** Option A

---

## Consequences

**Positive:**
- Eliminates compiler warning about redundant match arm
- Improves code clarity by documenting wildcard behavior
- Consistency with `comment_syntax()` function pattern
- No functional change — behavior is identical

**Negative:**
- None

**Neutral:**
- The change is purely cosmetic — no runtime behavior changes

---

## Risk Assessment

- **Severity:** Very Low (cosmetic/code cleanup)
- **Compiler warning removal:** Yes
- **Functional change:** None — both paths produce `StringSyntax::CStyle`
- **Regression risk:** Negligible — change does not alter matching logic

---

## Files Affected

- `crates/diffguard-domain/src/preprocess.rs` — modify `string_syntax()` match arm (lines 107-109)