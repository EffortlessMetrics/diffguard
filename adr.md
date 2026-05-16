# ADR-012: Remove Redundant Language::Json Match Arm in string_syntax()

## Status
Proposed

## Context

In `crates/diffguard-domain/src/preprocess.rs`, the `string_syntax()` method (lines 106-109) has a redundant match arm:

```rust
// YAML/TOML/JSON strings are C-style-like in this best-effort model
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
// All other languages (C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

The `Language::Json` variant is explicitly matched on line 107, but the wildcard `_ => StringSyntax::CStyle` on line 109 already catches all languages not yet matched, including `Language::Json`. Since both arms produce identical output (`StringSyntax::CStyle`), the explicit `Language::Json` arm is dead code.

This issue was reported in GitHub issue #287 and has occurred multiple times before (#142, #256, #375), suggesting the need for a clear pattern to prevent recurrence.

## Decision

Remove the redundant `Language::Json` match arm from `string_syntax()` and update comments to clarify that JSON is handled by the wildcard catch-all. This aligns with the established pattern in `comment_syntax()` (lines 84-86):

```rust
// YAML/TOML use # comments
Language::Yaml | Language::Toml => CommentSyntax::Hash,
// JSON supports comments in jsonc/json5 dialects (handled by wildcard)
_ => CommentSyntax::CStyle,
```

The fix changes `string_syntax()` to:

```rust
// YAML/TOML strings are C-style-like in this best-effort model
Language::Yaml | Language::Toml => StringSyntax::CStyle,
// JSON uses C-style strings (handled by wildcard, as are C, C++, Java, etc.)
_ => StringSyntax::CStyle,
```

## Consequences

### Benefits
1. **Removes dead code**: The `Language::Json` arm is unreachable since the wildcard already catches it
2. **Aligns with established pattern**: `string_syntax()` now follows the same comment structure as `comment_syntax()`
3. **Prevents future confusion**: Explicit comments clarify that JSON is intentionally handled by the wildcard
4. **Reduces recurrence risk**: Clear documentation of why JSON isn't explicitly listed helps prevent re-introduction

### Tradeoffs
1. **No functional change**: `Language::Json` still returns `StringSyntax::CStyle` (via wildcard)
2. **Minimal risk**: This is purely cosmetic; no behavior changes
3. **Comment accuracy**: The comment must be kept accurate to prevent future developers from re-adding the redundant arm

## Alternatives Considered

### Alternative 1: Keep explicit `Language::Json` arm with no comment
- **Rejected because**: The redundancy is not documented, leading to future confusion and potential re-filing of the same issue

### Alternative 2: Remove wildcard and explicitly list all C-style languages
- **Rejected because**: Defeats the purpose of the wildcard catch-all; would require updating the match every time a new language is added

### Alternative 3: No change
- **Rejected because**: The issue was reported and the redundant arm should be removed; it generates a compiler warning in some configurations and is technically dead code

## References

- GitHub Issue: #287
- Prior fixes: #142, #256, #375 (all for the same redundant pattern)
- Established pattern: `comment_syntax()` function (lines 84-86)