# Specification: Remove Redundant Match Arm in `string_syntax()` (Issue #452)

## Issue

GitHub issue #452 reports a redundant match arm in `preprocess.rs` where `Language::Yaml | Language::Toml | Language::Json` is explicitly matched but claims the wildcard `_` "already covers" all three.

**Correction:** The issue's premise is factually incorrect. In Rust, the wildcard only catches variants NOT explicitly matched. The arm is redundant (removable without behavior change), not unreachable (already caught by wildcard).

This specification follows ADR-012, which adopts ADR-011's approach: remove only `Json` from the arm, keeping `Yaml | Language::Toml` explicit.

---

## Current Code (lines 106-109)

```rust
// YAML/TOML/JSON strings are C-style-like in this best-effort model
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
// All other languages (C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

---

## Fixed Code

```rust
// YAML/TOML strings are C-style-like in this best-effort model
// (JSON is handled by the wildcard below since JSON uses C-style strings)
Language::Yaml | Language::Toml => StringSyntax::CStyle,
// All other languages (including JSON, C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

---

## Acceptance Criteria

1. `Language::Json` is removed from the explicit match arm (arm becomes `Language::Yaml | Language::Toml`)
2. Comment on the YAML/TOML arm explains JSON is handled by the wildcard
3. Wildcard arm has a comment explaining it catches JSON and other languages
4. Both YAML and TOML remain explicitly handled (not redundant)
5. `cargo build -p diffguard-domain` succeeds
6. `cargo clippy -p diffguard-domain` shows no warnings
7. `cargo test -p diffguard-domain` passes with no changes to test behavior
8. Existing test `yaml_and_toml_have_explicit_arms_not_wildcard` passes

---

## Non-Goals

- No functional change — `Language::Json` still produces `StringSyntax::CStyle` via wildcard
- YAML and TOML remain explicit (not removed)
- No changes to `comment_syntax()` function (already correct)
- No new tests required — existing tests in `red_tests_work_5d83e2c9.rs` are sufficient

---

## Dependencies

- None — this is a pure code cleanup with no new dependencies

---

## Test Plan

1. **Compile check:** `cargo build -p diffguard-domain` succeeds
2. **Clippy check:** `cargo clippy -p diffguard-domain` shows no redundant match arm warnings
3. **Test suite:** `cargo test -p diffguard-domain` passes
4. **Visual verification:** Inspect `string_syntax()` function to confirm comment clarity matches `comment_syntax()` pattern

---

## Files Modified

- `crates/diffguard-domain/src/preprocess.rs` — `string_syntax()` method, lines 106-109

---

## References

- [ADR-012: Remove Redundant `Language::Json` Match Arm (Issue #452)](adr-012-redundant-match-arm-452.md)
- [ADR-011: Remove Redundant `Language::Json` Match Arm (Issue #136)](adr-011-redundant-match-arm.md)
- [Issue #452](https://github.com/EffortlessMetrics/diffguard/issues/452)