# Specification: Remove Redundant Language::Json Match Arm in string_syntax()

## Feature/Behavior Description

Remove the redundant `Language::Json` match arm from the `string_syntax()` method in `preprocess.rs`. The `Language::Json` variant is currently explicitly matched alongside `Language::Yaml` and `Language::Toml`, but it is also caught by the wildcard `_ => StringSyntax::CStyle` catch-all. Since both produce identical output, the explicit `Language::Json` arm is dead code.

After the fix, `Language::Json` will continue to return `StringSyntax::CStyle` (via the wildcard), but will no longer be listed explicitly.

## Acceptance Criteria

1. **Code Change**: In `crates/diffguard-domain/src/preprocess.rs`, line 107, remove `| Language::Json` from the match arm so it reads:
   ```rust
   Language::Yaml | Language::Toml => StringSyntax::CStyle,
   ```

2. **Comment Updates**:
   - Update line 106 comment to remove "JSON" since it is no longer explicitly matched
   - Add clarification comment to the wildcard arm (line 109) explaining JSON is handled by the wildcard

3. **Behavior Preservation**: `Language::Json.string_syntax()` must still return `StringSyntax::CStyle` after the fix (via the wildcard)

4. **Code Quality**: After the fix, `cargo clippy -p diffguard-domain` should show no redundant match arm warnings

5. **Tests Pass**: `cargo test -p diffguard-domain` should pass without errors

## Non-Goals

- No changes to `comment_syntax()` function (already correct)
- No changes to other `Language` variants
- No functional changes to string syntax handling
- No new tests required (existing tests cover the behavior)

## Dependencies

- None — pure code cleanup with no new dependencies

## Verification

1. Run `cargo clippy -p diffguard-domain 2>&1 | grep -i "redundant"` — should return no results
2. Run `cargo test -p diffguard-domain` — all tests should pass
3. Visual inspection of `string_syntax()` should show:
   - `Language::Yaml | Language::Toml` explicit arm
   - Wildcard `_` arm with comment clarifying JSON is handled by wildcard