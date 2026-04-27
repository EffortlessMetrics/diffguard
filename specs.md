# Specification: Align diffguard-types regex dev-dependency with workspace pin

## Feature/Behavior Description

Update `crates/diffguard-types/Cargo.toml` to use `regex.workspace = true` for its dev-dependency instead of hardcoding `regex = "1"`. This aligns the crate with the workspace dependency management convention used by all other members of the diffguard workspace.

## Acceptance Criteria

1. **Dependency Declaration**: `crates/diffguard-types/Cargo.toml` line 24 must use `regex.workspace = true` instead of `regex = "1"`

2. **Workspace Consistency**: The change must be consistent with the pattern used by all other workspace crates:
   - `crates/diffguard/Cargo.toml` uses `regex.workspace = true` (lines 24 and 41)
   - `crates/diffguard-domain/Cargo.toml` uses `regex.workspace = true` (line 18)
   - `crates/diffguard-testkit/Cargo.toml` uses `regex.workspace = true` (line 20)
   - `crates/diffguard-lsp/Cargo.toml` uses `regex.workspace = true` (line 28)
   - `xtask/Cargo.toml` uses `regex.workspace = true` (line 19)

3. **Build Verification**: `cargo check -p diffguard-types` must succeed after the change, confirming the workspace resolver correctly picks up `regex = "1.12.3"`

4. **Test Verification**: `cargo test -p diffguard-types` must pass after the change, confirming regex functionality is preserved

## Non-Goals

- No changes to other crates or the root `Cargo.toml`
- No changes to the `regex` version pin (remains `1.12.3` in workspace)
- No functional code changes — only Cargo.toml dependency declaration

## Dependencies

- Workspace resolver v2 (already configured in root `Cargo.toml` line 2)
- `regex = "1.12.3"` in `[workspace.dependencies]` (root `Cargo.toml` line 38)
