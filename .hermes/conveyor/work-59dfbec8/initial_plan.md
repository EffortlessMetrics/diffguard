# Initial Plan: Remove redundant `Language::Json` match arms in preprocess.rs

## Approach
Remove the redundant `Language::Json` match arms in `comment_syntax()` and `string_syntax()` methods in `crates/diffguard-domain/src/preprocess.rs`.

The fix consolidates language coverage by letting the catch-all `_ =>` handle what was being redundantly matched explicitly.

### Step 1: Fix `comment_syntax()` (line 83)
Remove the redundant arm:
```rust
// REMOVE this line:
Language::Json => CommentSyntax::CStyle,
```
The catch-all `_ => CommentSyntax::CStyle` already covers `Json`.

### Step 2: Fix `string_syntax()` (line 108)
Change the grouped arm to exclude `Json`:
```rust
// BEFORE:
Language::Yaml | Language::Toml | Language::Json => StringSyntax::CStyle,

// AFTER:
Language::Yaml | Language::Toml => StringSyntax::CStyle,
```
`Yaml` and `Toml` must remain explicit because they are NOT covered by the catch-all `_ => StringSyntax::CStyle` (which only covers the remaining languages: C, Cpp, CSharp, Java, Kotlin, JavaScript, TypeScript, Go, Ruby, Unknown).

## Risks

1. **Rustc warning vs error**: Removing the arm may change a warning into an error in strict builds or with `#[deny(dead_code))]` or `#[deny(unreachable_patterns)]` — verify the crate compiles cleanly after changes.

2. **Mutation tests**: The `mutants.out.old` files suggest mutation testing was run. Removing dead code patterns may trigger different mutation coverage or new warnings from rustc.

3. **Behavioral documentation**: The explicit `Language::Json` arm served as documentation that JSON intentionally uses C-style syntax even though JSON technically has no comments in its base spec. The comment `// JSON supports comments in jsonc/json5 dialects` on line 82 explains the intent. Removing the arm loses this documentation signal within the match.

## Task Breakdown

1. **Edit `comment_syntax()`**: Remove `Language::Json => CommentSyntax::CStyle,` at line 83
2. **Edit `string_syntax()`**: Change `Language::Yaml | Language::Toml | Language::Json` to `Language::Yaml | Language::Toml` at line 108
3. **Verify compilation**: `cargo build -p diffguard-domain` to ensure no new errors/warnings
4. **Run tests**: `cargo test -p diffguard-domain` to confirm existing tests still pass
5. **Optional**: Add a `#[allow(dead_code)]` or clarify the comment if the explicit `Json` arm was intentionally documented behavior

## Verification Checklist
- [ ] `cargo build -p diffguard-domain` succeeds with no new warnings
- [ ] `cargo test -p diffguard-domain` passes
- [ ] `cargo clippy -p diffguard-domain` passes (if applicable)
- [ ] Mutation tests unchanged (existing test coverage for `Language::Json` remains)
