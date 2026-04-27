# ADR/Spec Findings — work-89bc82d6

## What This ADR Decides
Combine two duplicate `CommentSyntax::Hash` match arms in `Language::comment_syntax()` (lines 71 and 81 of `preprocess.rs`) into a single arm covering Python, Ruby, Shell, Yaml, and TOML. This eliminates code duplication and aligns with ADR-011 precedent.

## Key Decision
Merge the two identical `CommentSyntax::Hash` arms into one: `Language::Python | Language::Ruby | Language::Shell | Language::Yaml | Language::Toml => CommentSyntax::Hash`, and update the comment from "// YAML/TOML use # comments" to accurately cover all five languages.

## Alternatives Considered
1. **Leave as-is** — rejected for code hygiene reasons
2. **Extract to helper function** — rejected as over-engineering
3. **New CommentSyntax variant per language** — rejected as architectural overreach

## Consequences
- **Benefits:** Eliminates duplication, improves maintainability, consistent with ADR-011 precedent, zero functional risk
- **Risks:** Stale line number references, merged comment must stay accurate

## Acceptance Criteria
1. All 5 languages return `CommentSyntax::Hash` via a single match arm
2. Comment accurately describes Python, Ruby, Shell, YAML, and TOML
3. `cargo test -p diffguard-domain` passes
4. `cargo clippy -p diffguard-domain` clean
5. No functional change for any Language variant
