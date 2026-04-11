# Plan: Centralize workspace crate versions

## Goal
Fix workspace dependency issues where intra-workspace crate references use bare version specifiers instead of `version.workspace = true`, and external crate versions are not centralized in `workspace.dependencies`.

## Current Context
- `cargo clippy --all-targets --all-features` is **clean** (0 warnings)
- `cargo test --workspace` **passes** (59 tests across all crates)
- PR #5 (v0.2 enhancements — LSP, multi-base, analytics) is **MERGED**
- Current branch `feat/work-d1531005/api--compiledrule-exported-from-diffguar` has 12 commits ahead of main
- 4 open issues directly related to workspace/Cargo.toml hygiene

## Open Issues (workspace hygiene cluster)
| # | Title | Priority |
|---|-------|----------|
| 155 | Hardcoded version instead of `version.workspace = true` in `bench/Cargo.toml` | High |
| 152 | Intra-workspace crate dependencies use bare version specifiers instead of `version.workspace = true` | High |
| 153 | External crate versions not centralized in `workspace.dependencies` | Medium |
| 154 | `diffguard-testkit`: Unused dependency on `diffguard-domain` | Low |

## Proposed Approach

### Step 1: Inspect Cargo workspace layout
```bash
cd ~/repos/diffguard
grep -r "version\s*=" Cargo.toml | grep -v workspace
```
Identify all bare version references in intra-workspace deps.

### Step 2: Fix `bench/Cargo.toml`
Add `version.workspace = true` to `bench/Cargo.toml`.

### Step 3: Replace bare version specifiers in intra-workspace deps
In all workspace member `Cargo.toml` files, replace:
```
diffguard-types = "0.2.0"
```
with:
```
diffguard-types = { version = "0.2.0", workspace = true }
```

### Step 4: Centralize external crate versions
Add `workspace.dependencies` section to root `Cargo.toml`, then update all members to use `version.workspace = true` for external crates (serde, tokio, etc.).

### Step 5: Verify
```bash
cargo build --workspace
cargo test --workspace
cargo clippy --all-targets --all-features
```

## Files Likely to Change
- `Cargo.toml` (root — add `workspace.dependencies`)
- `bench/Cargo.toml`
- `crates/*/Cargo.toml` (intra-workspace bare version references)

## Risks
- None significant — purely declarative Cargo.toml changes
- Must ensure all version references stay synchronized

## Verification
1. `cargo build --workspace` succeeds
2. `cargo test --workspace` succeeds
3. `cargo clippy --all-targets --all-features` is clean
4. `git diff` shows only `Cargo.toml` changes
