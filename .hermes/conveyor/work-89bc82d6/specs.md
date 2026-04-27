# Specs — work-89bc82d6

## Feature / Behavior Description

Refactor the `Language::comment_syntax()` method in `crates/diffguard-domain/src/preprocess.rs` by combining two duplicate match arms that both return `CommentSyntax::Hash` into a single arm covering all five languages: Python, Ruby, Shell, Yaml, and TOML.

## Acceptance Criteria

1. **Correctness** — After the change, `Language::Python`, `Language::Ruby`, `Language::Shell`, `Language::Yaml`, and `Language::Toml` all return `CommentSyntax::Hash` via a single match arm.

2. **Comment accuracy** — The merged arm's comment accurately describes all five languages (Python, Ruby, Shell, YAML, TOML) using `#` comments. The old comment "// YAML/TOML use # comments" is updated accordingly.

3. **Tests pass** — `cargo test -p diffguard-domain` passes with no regressions.

4. **Clippy clean** — `cargo clippy -p diffguard-domain` produces no warnings related to the change.

5. **No functional change** — The behavior of `comment_syntax()` is identical before and after for all 21 `Language` variants.

## Non-Goals

- Fixing the stale JSON comment at line 82 ("// JSON supports comments in jsonc/json5 dialects (handled by wildcard)") — this is a separate issue, out of scope for #286
- Updating `CommentSyntax::Hash` documentation at line 122 (pre-existing debt)
- Any other refactoring or functional changes

## Dependencies

- Rust toolchain (standard `cargo test` and `cargo clippy`)
- No external dependencies affected — pure refactoring within `diffguard-domain`
