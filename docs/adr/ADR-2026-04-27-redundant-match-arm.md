# ADR-2026-04-27: Remove Redundant Yaml/Toml/Json Match Arm in string_syntax()

## Status
Proposed

## Context

In `crates/diffguard-domain/src/preprocess.rs`, the `string_syntax()` method on `Language` (lines 88-111) contains a redundant match arm at lines 106-107:

```rust
// YAML/TOML/JSON strings are C-style-like in this best-effort model
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,
// All other languages (C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

The wildcard `_ => StringSyntax::CStyle` (line 109) matches **all** `Language` variants not explicitly handled by prior arms (lines 90-105). Since `Yaml`, `Toml`, and `Json` appear in no other arm, they fall through to the wildcard. The explicit arm at line 107 is unreachable dead code.

This redundancy was likely introduced during #515 cleanup when the wildcard was retained alongside an explicit arm for these three languages.

The preprocessing model is documented as using "C-like syntax heuristics; not a full parser for any language" (CLAUDE.md). The redundant arm misrepresents the design by implying YAML/TOML/JSON are specially handled in string syntax when they are not — they are simply another group falling through to the C-style wildcard.

## Decision

Remove the redundant match arm `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle` (lines 106-107) from `string_syntax()`.

Update the comment on line 108 from:
```rust
// All other languages (C, C++, Java, etc.) use C-style strings
```
To accurately reflect that the wildcard handles all remaining languages:
```rust
// All other languages use C-style strings
```

## Consequences

### Positive
- Removes dead code that obscured the preprocessing model's best-effort design
- Aligns implementation with documented `CLAUDE.md` behavior ("C-like syntax heuristics")
- Prevents future maintainer confusion about whether YAML/TOML/JSON require special string-syntax handling
- Eliminates a potential location for `#[allow(dead_code)]` on the `Language::Json` variant

### Negative
- None — pure dead-code elimination with identical runtime behavior

### Neutral
- The `comment_syntax()` method at line 81 still has `Language::Yaml | Language::Toml => CommentSyntax::Hash` — this is **not** redundant because the wildcard `_ => CommentSyntax::CStyle` does NOT cover YAML/TOML (which require hash comments). That arm remains necessary and is out of scope.

## Alternatives Considered

### Keep the arm with corrected comment
Reject: The arm is still unreachable. The comment fix alone doesn't resolve the misleading code structure or prevent future confusion about exhaustiveness.

### Remove only Json (keep Yaml/Toml explicit)
Reject: Prior issues (#229, #256) addressed JSON separately, but the wildcard catches all three equally. Partial removal would be inconsistent and leave misleading code for the remaining variants.

### No change
Reject: Dead code creates maintenance burden and misrepresents the preprocessing design in code structure.

## Dependencies

- No new dependencies introduced
- No I/O changes (domain crate remains I/O-free per invariant)
- No API or behavior change
- All existing tests pass with identical results