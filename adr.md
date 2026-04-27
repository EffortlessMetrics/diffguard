# ADR-0017: Use Workspace Dependency for regex in diffguard-types

## Status
Proposed

## Context

The `crates/diffguard-types/Cargo.toml` specifies `regex = "1"` as a dev-dependency, which is misaligned with the workspace pin of `regex = "1.12.3"` defined in the root `Cargo.toml` at line 38. This is the only crate in the workspace that does not use `regex.workspace = true` for the regex dependency.

Workspace members that correctly use `regex.workspace = true`:
- `crates/diffguard/Cargo.toml` (lines 24 and 41)
- `crates/diffguard-domain/Cargo.toml` (line 18)
- `crates/diffguard-testkit/Cargo.toml` (line 20)
- `crates/diffguard-lsp/Cargo.toml` (line 28)
- `xtask/Cargo.toml` (line 19)

The workspace uses `resolver = "2"` which enables workspace dependency inheritance for all dependency types including dev-dependencies.

## Decision

Change line 24 in `crates/diffguard-types/Cargo.toml` from:
```toml
regex = "1"
```
to:
```toml
regex.workspace = true
```

This uses the workspace-level pinned version `regex = "1.12.3"` instead of allowing any `1.x.x` version.

## Consequences

### Benefits
- Aligns `diffguard-types` with the workspace dependency management strategy used by all 5 other crates
- Ensures the pinned version `1.12.3` is used consistently in all test/dev contexts
- Prevents future version drift if the workspace pin is updated
- Single source of truth for the regex version

### Tradeoffs
- Dev-dependency only change — no runtime behavior change since `regex = "1"` already includes `1.12.3` SemVer-compatibly
- Minimal risk: regex 1.x API has been stable

## Alternatives Considered

### 1. Keep `regex = "1"` as-is
- **Rejected because**: Bypasses workspace dependency management, creates inconsistency with all other workspace crates, and risks version drift

### 2. Hardcode `regex = "1.12.3"` in diffguard-types
- **Rejected because**: Duplicates the workspace pin, requires manual updates if root version changes, defeats the purpose of workspace dependency abstraction

### 3. Remove regex dev-dependency entirely
- **Rejected because**: The crate uses `regex` in its test code (e.g., `proptest` strategies for string generation), so the dependency is required
