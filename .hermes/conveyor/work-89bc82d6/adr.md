# ADR-012: Consolidate duplicate `CommentSyntax::Hash` match arms in `Language::comment_syntax()`

## Status
Proposed

## Context
In `Language::comment_syntax()` (`crates/diffguard-domain/src/preprocess.rs`), two separate match arms both return `CommentSyntax::Hash`:
- Line 71: `Language::Python | Language::Ruby | Language::Shell => CommentSyntax::Hash`
- Line 81: `Language::Yaml | Language::Toml => CommentSyntax::Hash`

This duplication was reported in GitHub issue #286. The Rust compiler enforces exhaustiveness, so this is safe to refactor, but the duplication is inconsistent with the codebase's own precedent (ADR-011) for cleaning up redundant match arms in `preprocess.rs`.

## Decision
Combine the two duplicate `CommentSyntax::Hash` match arms into a single arm:

```rust
Language::Python | Language::Ruby | Language::Shell | Language::Yaml | Language::Toml => CommentSyntax::Hash,
```

Update the associated comment from "// YAML/TOML use # comments" to accurately describe all five languages: "// Python, Ruby, Shell, YAML, and TOML all use # comments".

## Consequences

### Benefits
- **Eliminates code duplication** — two identical arms become one
- **Improves maintainability** — future language additions using `#` comments need only one arm
- **Consistent with existing ADR-011 precedent** — the codebase already made a similar cleanup
- **Sets a good precedent** — non-functional refactorings should be treated as legitimate changes
- **Zero functional risk** — Rust compiler enforces exhaustiveness; no behavior change

### Tradeoffs / Risks
- **Merged arm comment must be accurate** — the combined comment must list all five languages
- **Line number references stale** — any external docs referencing lines 71 or 81 become outdated
- **Stale JSON comment at line 82** — a separate misleading comment ("JSON supports comments in jsonc/json5 dialects") exists; filed as out-of-scope debt for a separate issue

## Alternatives Considered

### 1. Leave as-is (reject)
The duplication is unambiguous and the fix is trivial. Leaving it in place sets a poor precedent for code hygiene and makes future maintenance harder. Not acceptable.

### 2. Separate into helper function (reject)
Extracting to a helper function would add indirection with no benefit — the match arms are already perfectly clear. Also overkill for a simple deduplication.

### 3. Add a new `CommentSyntax` variant per language grouping (reject)
This would be a significant architectural change (more `CommentSyntax` variants) with zero benefit. The existing categorization is sound.

## Alternatives Summary
| Alternative | Why Rejected |
|-------------|--------------|
| Leave as-is | Code hygiene, maintenance burden |
| Extract to helper | Over-engineering; adds indirection for no benefit |
| New `CommentSyntax` variant per language | Architectural overreach; zero functional need |
