# ADR-334a49bf: Resolve match_same_arms Warnings in preprocess.rs

## Status
Proposed

## Context

Clippy's `match_same_arms` lint flags two genuine redundancies in `Language::comment_syntax()` and `Language::string_syntax()` in `preprocess.rs`:

1. **`comment_syntax()` lines 71 and 81**: Both return `CommentSyntax::Hash` — two separate match arms with identical bodies that should be merged:
   ```rust
   Language::Python | Language::Ruby | Language::Shell => CommentSyntax::Hash,  // line 71
   Language::Yaml | Language::Toml => CommentSyntax::Hash,                     // line 81
   ```

2. **`string_syntax()` line 107**: `Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle` is literally identical to the wildcard `_ => StringSyntax::CStyle` on line 109 — the explicit arm should be removed.

**What is NOT redundant** (must be preserved):
- `Language::Xml => CommentSyntax::Xml` — triggers XML `<!-- -->` block comment handling (distinct from CStyle)
- `Language::Php => CommentSyntax::Php` — triggers PHP-specific `#` comment handling (CStyle doesn't handle `#`)
- `Language::Php => StringSyntax::Php` — produces `Mode::NormalString` for single-quoted strings; CStyle produces `Mode::Char` for single quotes — these are NOT identical
- `Language::Xml => StringSyntax::Xml` — handled distinctly downstream

The prior research misidentified singleton arms (`Language::Xml`, `Language::Php`) as "redundant." They are not redundant — they produce distinct enum values with genuinely different downstream processing.

## Decision

1. **Merge the two `CommentSyntax::Hash` arms** in `comment_syntax()` into a single arm:
   ```rust
   // Python, Ruby, Shell, YAML, and TOML all use # comments
   Language::Python | Language::Ruby | Language::Shell | Language::Yaml | Language::Toml => CommentSyntax::Hash,
   ```

2. **Remove the redundant `Yaml|Toml|Json` arm** from `string_syntax()` (line 107) entirely. These languages fall through to the wildcard `CStyle` already.

3. **Preserve all singleton arms** (`Language::Xml`, `Language::Php`) — they are not flagged by clippy because their bodies are genuinely distinct from the wildcard.

## Consequences

**Benefits:**
- Resolves 2 genuine clippy `match_same_arms` warnings
- Reduces code duplication in a well-traveled code path
- Clarifies the distinction between "truly redundant" (identical bodies) and "singleton but necessary" (different bodies with different behavior)

**Tradeoffs:**
- None — the fix is purely cosmetic, no behavioral change

**Risks:**
- None identified — existing tests verify all language preprocessing behavior

## Alternatives Considered

### Alternative 1: Remove singleton arms entirely
Remove `Language::Php => StringSyntax::Php` and let PHP fall to CStyle wildcard.

**Rejected because:**
- `StringSyntax::Php` produces `Mode::NormalString` for single-quoted strings
- `StringSyntax::CStyle` produces `Mode::Char` for single-quoted strings
- PHP single-quoted strings would be incorrectly processed as char literals
- This would introduce a regression in PHP string preprocessing

### Alternative 2: Suppress clippy lint with `#[allow(clippy::match_same_arms)]`
Keep the duplicate arms and suppress the warning.

**Rejected because:**
- The warnings represent genuine code duplication
- Suppressing warnings creates technical debt and warning fatigue
- The fix is trivial and risk-free
