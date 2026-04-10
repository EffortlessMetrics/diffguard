## Problem

The `Preprocessor` in `diffguard-domain/src/preprocess.rs` supports 20+ languages, but property tests in `crates/diffguard-domain/tests/properties.rs` only cover a subset (Python, Ruby, JavaScript, TypeScript, Go, and C-style). Several languages are entirely missing property-based coverage: **SQL, XML, PHP, Swift, Scala**.

## Scope

**In scope:**
- `crates/diffguard-domain/src/preprocess.rs` — Preprocessor, Language, CommentSyntax, StringSyntax
- `crates/diffguard-domain/tests/properties.rs` — property tests

**Out of scope:**
- No changes to production code — purely a test coverage gap

## Background

The Preprocessor implements language-aware masking of comments and strings per `PreprocessOptions` (mask_comments, mask_strings). Each language maps to:
- A `CommentSyntax` variant (CStyle, CStyleNested, Hash, Sql, Xml, Php, etc.)
- A `StringSyntax` variant (Rust, Python, Go, CStyle, Shell, SwiftScala, Sql, Xml, Php, etc.)

The property tests in `properties.rs` extensively test Python (hash comments), Ruby (hash comments), JavaScript/TypeScript/Go (C-style line comments), and C-style block comments. But there are **zero property tests** for:

| Language | CommentSyntax | StringSyntax | Status |
|----------|--------------|--------------|--------|
| Swift | CStyleNested | SwiftScala | No property tests |
| Scala | CStyleNested | SwiftScala | No property tests |
| Sql | Sql | Sql | No property tests |
| Xml | Xml | Xml | No property tests |
| Php | Php | Php | No property tests |

Additionally, some edge cases for tested languages are missing:
- **Rust triple-quoted raw strings** (`r#"..."#`) — only covered in fuzz target, not in property tests
- **Swift/Scala triple-quoted strings** (`"""..."""`) — same gap

## What Property Tests Should Cover

### Swift / Scala (CStyleNested + SwiftScala)

```rust
// Swift: CStyleNested comments support nesting /* /* nested */ */ 
// Scala: same, plus """ multi-line strings
```

**Tests:**
- `property_swift_comment_masking`: nested block comments fully masked
- `property_scala_triple_quote_string_masking`: `"""..."""` strings masked
- `property_swift_raw_string_masking`: `r#"..."#` raw strings masked

### SQL (Sql comment syntax, Sql string syntax)

**Tests:**
- `property_sql_comment_masking`: `--` line comments masked
- `property_sql_string_literal_masking`: single-quoted strings masked
- Edge: `--` appears inside a string should NOT be treated as comment

### XML (Xml comment syntax, Xml string syntax)

**Tests:**
- `property_xml_comment_masking`: `<!-- ... -->` block comments masked
- Edge: nested `--` inside XML comment (invalid XML but should not crash)
- `property_xml_attribute_masking`: attribute values masked

### PHP (Php comment syntax, Php string syntax)

**Tests:**
- `property_php_comment_masking`: `#` hash comments and `//` C-style both masked
- `property_php_heredoc_masking`: `<<<END...END;` heredoc strings masked

## Acceptance Criteria

- [ ] Property test for Swift comment (nested block comments)
- [ ] Property test for Scala triple-quoted strings
- [ ] Property test for SQL `--` comment masking
- [ ] Property test for XML `<!-- -->` comment masking
- [ ] Property test for PHP `#` comment masking
- [ ] Property test for PHP heredoc string masking
- [ ] All tests verify: output length == input length
- [ ] All tests verify: comment/string content replaced with spaces, delimiters preserved
- [ ] Tests use `proptest!` with 100+ cases

## Affected Crate
- diffguard-domain