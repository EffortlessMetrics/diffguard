# Spec: work-334a49bf — Resolve match_same_arms Warnings in preprocess.rs

## Feature/Behavior Description

Resolve clippy's `match_same_arms` lint warnings in `Language::comment_syntax()` and `Language::string_syntax()` methods in `preprocess.rs` by merging genuinely redundant match arms while preserving all singleton arms that produce distinct downstream behavior.

## Changes

### 1. `comment_syntax()` — Merge duplicate `CommentSyntax::Hash` arms

**Current (lines 71, 81):**
```rust
Language::Python | Language::Ruby | Language::Shell => CommentSyntax::Hash,  // line 71
// ... other arms ...
Language::Yaml | Language::Toml => CommentSyntax::Hash,                       // line 81
```

**Fixed:**
```rust
// Python, Ruby, Shell, YAML, and TOML all use # comments
Language::Python | Language::Ruby | Language::Shell | Language::Yaml | Language::Toml => CommentSyntax::Hash,
```

### 2. `string_syntax()` — Remove redundant `Yaml|Toml|Json` arm

**Current (lines 107, 109):**
```rust
// YAML/TOML/JSON strings are C-style-like in this best-effort model
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,  // line 107
// All other languages (C, C++, Java, etc.) use C-style strings
_ => StringSyntax::CStyle,                                                 // line 109
```

**Fixed:**
```rust
// All other languages (C, C++, Java, YAML, TOML, JSON, etc.) use C-style strings
_ => StringSyntax::CStyle,
```

### 3. Preserve singleton arms (NOT redundant)

The following arms are NOT modified — they are not flagged by clippy because their bodies are genuinely distinct from the wildcard:

- `Language::Xml => CommentSyntax::Xml` — triggers XML `<!-- -->` comment handling
- `Language::Php => CommentSyntax::Php` — triggers PHP `#` comment handling
- `Language::Xml => StringSyntax::Xml` — distinct downstream handling
- `Language::Php => StringSyntax::Php` — produces `Mode::NormalString` (not `Mode::Char` like CStyle)

## Acceptance Criteria

1. **`cargo clippy -p diffguard-domain -- -W clippy::match_same_arms`** produces 0 warnings for `preprocess.rs`

2. **`cargo test -p diffguard-domain`** passes all tests, including:
   - `xml_comment_syntax` — verifies `Language::Xml` produces `CommentSyntax::Xml`
   - `php_comment_syntax` — verifies `Language::Php` produces `CommentSyntax::Php`
   - `xml_string_syntax` — verifies `Language::Xml` produces `StringSyntax::Xml`
   - `php_string_syntax` — verifies `Language::Php` produces `StringSyntax::Php`

3. **No behavioral regression** — preprocessing output is unchanged for all languages (existing tests verify this)

## Non-Goals

- This fix does NOT remove singleton arms for `Language::Xml` or `Language::Php`
- This fix does NOT add or remove any `CommentSyntax` or `StringSyntax` enum variants
- This fix does NOT change any downstream processing logic

## Dependencies

- None — only affects `comment_syntax()` and `string_syntax()` match expressions
