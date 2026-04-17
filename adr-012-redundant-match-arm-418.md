# ADR-012: Remove Redundant `Language::Json` Match Arm in `string_syntax()` (Issue #418)

**Status:** Proposed

**Date:** 2026-04-17

**Work Item:** work-05d48a76

**Supersedes:** ADR-011 (work-5d83e2c9, issue #136 — same fix, different issue instance)

---

## Context

GitHub issue #418 reports a redundant match arm in `preprocess.rs` where `Language::Json` is explicitly matched in the `string_syntax()` function but is then shadowed by a wildcard (`_`) pattern that produces the same result (`StringSyntax::CStyle`).

The problematic code at lines 107-109:
```rust
// YAML/TOML/JSON strings are C-style-like in this best-effort model
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
// All other languages (C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

The wildcard `_` catches all `Language` variants not explicitly matched, including `Language::Json`. Since both paths produce `StringSyntax::CStyle`, the explicit `Language::Json` arm is redundant dead code.

---

## Decision

Remove `Language::Json` from the match arm and update comments to clarify that JSON is handled by the wildcard.

**Changes:**

1. **Line 107:** Change `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,` to `Language::Yaml | Language::Toml => StringSyntax::CStyle,`

2. **Comment on line 106:** Update to: `// YAML/TOML strings are C-style-like in this best-effort model`

3. **Add clarifying comment:** Add note that JSON is handled by the wildcard below (mirroring `comment_syntax()` pattern)

4. **Update wildcard comment:** Add that JSON is caught by the wildcard

This mirrors the pattern already used in `comment_syntax()` (lines 80-84) which has an identical comment structure acknowledging that JSON is handled by the wildcard.

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
- ❌ Redundant arm confuses future maintainers
- ❌ Inconsistent with `comment_syntax()` pattern

**Selected:** Option A

---

## Consequences

**Positive:**
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
- **Functional change:** None — both paths produce `StringSyntax::CStyle`
- **Regression risk:** Negligible — change does not alter matching logic

---

## Note on Clippy Warning

Unlike ADR-011 which claimed this fix "eliminates a clippy warning," verification confirms `cargo clippy -p diffguard-domain` produces **zero warnings**. The Rust compiler/lint does not warn about this specific pattern. The motivation for this fix is purely **code clarity and consistency** — not warning elimination.

---

## Files Affected

- `crates/diffguard-domain/src/preprocess.rs` — modify `string_syntax()` match arm (lines 106-109)