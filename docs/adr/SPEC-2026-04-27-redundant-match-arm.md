# Spec: Remove Redundant Match Arm — work-9811a5e3

## Feature/Behavior Description

Remove the unreachable `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle` match arm from `string_syntax()` in `crates/diffguard-domain/src/preprocess.rs`. This arm is dead code because the wildcard `_ => StringSyntax::CStyle` already handles these three language variants. Both branches produce identical behavior.

Additionally, update the misleading comment above the wildcard to accurately describe its coverage.

## Acceptance Criteria

1. **Dead code removed**: The explicit arm `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle` and its associated comment are removed from `string_syntax()`.

2. **Comment updated**: The comment above the wildcard `_ => StringSyntax::CStyle` is updated from "All other languages (C, C++, Java, etc.)" to accurately reflect that the wildcard handles all remaining languages including YAML, TOML, and JSON.

3. **Exhaustive match preserved**: The match expression remains exhaustive — all `Language` variants are handled either by explicit arms or the wildcard.

4. **No behavioral change**: `Language::Yaml.string_syntax()`, `Language::Toml.string_syntax()`, and `Language::Json.string_syntax()` continue to return `StringSyntax::CStyle` (via the wildcard).

5. **No changes to `comment_syntax()`**: The YAML/TOML explicit arm in `comment_syntax()` is unaffected and remains necessary because it returns `CommentSyntax::Hash` (not caught by the wildcard's `CommentSyntax::CStyle`).

## Non-Goals

- No changes to any test files
- No new `#[allow(dead_code)]` attributes needed
- No changes to `comment_syntax()` method
- No changes to `Language::from_str()` parsing
- No I/O or API changes

## Dependencies

- `cargo build -p diffguard-domain` — must compile without warnings
- `cargo test -p diffguard-domain` — all existing tests must pass
- `cargo clippy -p diffguard-domain --lib` — no new clippy warnings

## Technical Notes

The redundancy exists because:
- The match handles 9 explicit groups (Rust, Python, JavaScript/TypeScript/Ruby, Go, Shell, Swift/Scala, Sql, Xml, Php)
- The wildcard `_` covers all remaining variants: C, Cpp, CSharp, Java, Kotlin, Yaml, Toml, Json, Unknown
- Since `Yaml`, `Toml`, `Json` are in no other arm, they fall through to the wildcard
- Both the explicit arm and the wildcard return `StringSyntax::CStyle` — behavior is identical

The `comment_syntax()` method is NOT affected because:
- YAML/TOML return `CommentSyntax::Hash`
- The wildcard returns `CommentSyntax::CStyle`
- These are different values, so the explicit arm is genuinely needed