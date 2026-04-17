# Specification — work-fd603479

## Feature/Behavior Description

This work item addresses GitHub issue #470: `clippy::identical_match_arms` warning at `preprocess.rs:107` claiming `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle` was redundant.

**Actual State (as of this writing):**
- `Language::Json` is handled by the wildcard `_ => StringSyntax::CStyle` (already removed from explicit arm)
- `Language::Yaml | Language::Toml` remain as an explicit match arm (line 108)

## Acceptance Criteria

1. **AC1**: `Language::Json.string_syntax()` returns `StringSyntax::CStyle` via the wildcard arm (not via explicit arm)
   - Verified by: `language_json_returns_cstyle()` and `language_json_and_unknown_behave_identically_in_string_syntax()` tests

2. **AC2**: `Language::Yaml.string_syntax()` and `Language::Toml.string_syntax()` return `StringSyntax::CStyle` via the **explicit** match arm `Language::Yaml | Language::Toml => StringSyntax::CStyle`
   - Verified by: `yaml_and_toml_have_explicit_arms_not_wildcard()` test

3. **AC3**: All tests in `red_tests_work_5d83e2c9.rs` pass without modification

4. **AC4**: No code changes are required — the issue is already resolved by prior commit

## Non-Goals

- This specification does NOT require removing YAML/TOML from the explicit arm
- This specification does NOT modify `comment_syntax()` or other functions
- This specification does NOT address the lint firing in strict mode (`-- -W clippy::restriction`)

## Dependencies

- Regression test file: `crates/diffguard-domain/tests/red_tests_work_5d83e2c9.rs`
- Source file: `crates/diffguard-domain/src/preprocess.rs`

## Implementation Notes

The explicit arm `Language::Yaml | Language::Toml => StringSyntax::CStyle` is:
- Functionally redundant from the compiler's perspective (wildcard returns same value)
- Semantically meaningful for code documentation and maintainability
- Required to remain explicit per regression test `yaml_and_toml_have_explicit_arms_not_wildcard()`
