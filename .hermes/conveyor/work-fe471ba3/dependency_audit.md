# Dependency Audit — work-fe471ba3
## Add doctor subcommand to check environment prerequisites
### Branch: feat/vscode-lsp-client-rewrite | Gate: HARDENED

---

## 1. Dependencies Added or Changed

### Rust (Cargo.toml / Cargo.lock)
**No Cargo.toml or Cargo.lock changes** were detected in this branch vs `main`.  
The `git diff main -- '*.toml' Cargo.lock` produced no modifications. All dependency changes belong to prior PRs in the VS Code LSP client rewrite branch stack.

### JavaScript (VS Code Extension)
The following npm dependencies were added to `editors/vscode-diffguard/package.json`:

| Dependency | Version | Type |
|---|---|---|
| `vscode-languageclient` | ^9.0.1 | runtime |
| `@vscode/vsce` | ^3.0.0 | dev (packaging) |

Additionally, `editors/vscode-diffguard/package-lock.json` was created (4039 lines). It is recommended to verify the lockfile was generated with `npm install` or `npm ci` and has not been manually edited.

---

## 2. License Compatibility Check

### Rust Dependencies (260 packages in lockfile)
All Rust transitive dependency licenses found:

| License | Compatibility with MIT OR Apache-2.0 |
|---|---|
| Apache-2.0 | Compatible |
| MIT | Compatible |
| MIT OR Apache-2.0 | Compatible |
| MIT/Apache-2.0 | Compatible |
| Apache-2.0 OR MIT | Compatible |
| Apache-2.0 OR BSL-1.0 | Compatible |
| Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | Compatible |
| Unlicense OR MIT | Compatible |
| BSL-1.0 | Compatible (Boost Software License is permissive) |
| Unicode-3.0 | Compatible (Unicode license is permissive) |

**Result: All 260 Rust dependency licenses are compatible.**

### JavaScript Dependencies
| Package | License | Compatible |
|---|---|---|
| `vscode-languageclient` (^9.0.1) | MIT | Yes |
| `@vscode/vsce` (^3.0.0) | MIT | Yes |

**Result: All JS dependency licenses are compatible.**

### Warning: License Inconsistency
The VS Code extension `editors/vscode-diffguard/package.json` declares its license as `"MIT"` only. The workspace Rust project uses `"MIT OR Apache-2.0"`. This is not a license risk (MIT is a subset), but it creates an inconsistency. Consider aligning to `"MIT OR Apache-2.0"` for uniformity across the repo.

---

## 3. Semver-Major Bumps

### Rust
No semver-major bumps detected in this PR — **no Rust dependency version changes exist in this diff.** All dependency versions remain as-pinned from prior commits.

### JavaScript (VS Code Extension)
- `vscode-languageclient` is pinned at `^9.0.1` — this uses caret ranges which allow minor/patch updates within the 9.x line. No semver-major risk.
- `@vscode/vsce` is pinned at `^3.0.0` — dev dependency; safe.

---

## 4. Lockfile Status

### Rust (Cargo.lock)
- **Cargo.lock is unmodified** in this PR. No drift from `main`.
- Note: `cargo tree -d` reports one duplicate (non-breaking):  
  `winnow` v0.7.15 and v1.0.1 are both present as transitive deps of the `toml` crate ecosystem. This is a known artifact of `toml 0.9.12` depending on both `winnow 0.7.x` directly and `winnow 1.0.x` via `toml_parser`. Not a concern.
- **Pre-existing issue**: `cargo check --workspace` fails to compile due to missing `description` field in `RuleConfig` initializers in `crates/diffguard-testkit/src/fixtures.rs` (12 errors). This is a code-level issue, not a dependency issue.

### JavaScript (package-lock.json)
- `package-lock.json` is newly created (4039 lines). It was not present on `main` for the `editors/vscode-diffguard/` directory.
- Lockfile present and deterministic — good practice.

---

## 5. Duplicate Dependency Versions

### Rust
| Crate | Versions | Source |
|---|---|---|
| `winnow` | 0.7.15, 1.0.1 | Transitive via `toml 0.9.12` / `toml_parser 1.1.2` |

This is a known, non-actionable duplication within the `toml` ecosystem. No action required.

No other duplicate versions detected.

---

## 6. Deprecated / Unmaintained Dependencies

- No deprecated Rust crates detected in the dependency tree.
- All primary dependencies (anyhow, clap, serde, regex, toml, thiserror, etc.) are actively maintained on crates.io.
- `chrono 0.4.44` — active and maintained.
- `lsp-server 0.7.9`, `lsp-types 0.97.0` — active LSP ecosystem crates.

---

## Recommendation: pass-with-warnings

### Summary
- **Rust dependencies**: No changes in this PR; lockfile stable; all licenses compatible.
- **JavaScript dependencies**: 2 new deps added for the VS Code LSP client; both permissively licensed.
- **Lockfile**: Cargo.lock unchanged; new `package-lock.json` created (good).

### Warnings
1. **License inconsistency**: `editors/vscode-diffguard/package.json` declares `"MIT"` only, while the workspace uses `"MIT OR Apache-2.0"`. Recommend alignment for consistency.
2. **Pre-existing build failure**: `cargo check --workspace` fails in `diffguard-testkit` due to missing `description` field on `RuleConfig`. This predates this audit scope but should be resolved before merge.
3. **Duplicate `winnow`**: Minor transitive duplication (0.7.x and 1.0.x) within the `toml` ecosystem. Non-blocking.

### No blocking dependency risks identified.
