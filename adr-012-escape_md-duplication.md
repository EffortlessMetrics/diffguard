# ADR-012: Hoist `escape_md` to `diffguard-types`

**Status:** Proposed

**Date:** 2026-04-20

**Work Item:** work-a59eb6b6

**Supersedes:** ADR-057 (unmerged, same decision)

---

## Context

GitHub issue #472 reports that `escape_md` (which escapes special Markdown characters for safe table cell inclusion) is duplicated with identical implementations in two crates:
- `crates/diffguard-core/src/render.rs` (private, line 126)
- `crates/diffguard/src/main.rs` (private, line 1702)

The function escapes 10 characters (`|`, `` ` ``, `#`, `*`, `_`, `[`, `]`, `>`, `\r`, `\n`) and is used by markdown rendering functions in both crates.

## Decision

Hoist `escape_md` to `crates/diffguard-types/src/lib.rs` as a public utility function, and update both `diffguard-core` and `diffguard` to import from there.

**Changes:**

1. **Add `escape_md` to `diffguard-types/src/lib.rs`** — Add the function near the existing private helpers (`is_zero`, `is_false`, `is_match_mode_any`) with a doc comment explaining its purpose and that it exists to avoid duplication across rendering crates.

2. **Update `diffguard-core/src/render.rs`** — Replace the local `escape_md` with `use diffguard_types::escape_md;` and update the call site.

3. **Update `diffguard/src/main.rs`** — Replace the local `escape_md` with `use diffguard_types::escape_md;` and remove the duplicate definition.

4. **Verify snapshots unchanged** — Run `cargo test -p diffguard-core` and `cargo test -p diffguard` to confirm markdown rendering is identical.

## Alternatives Considered

### Option A: Export from `diffguard-core` (rejected)
Making `diffguard` re-export `diffguard-core`'s `escape_md()` was rejected because it would create an unintended dependency direction. `diffguard` must not depend on `diffguard-core` internals — that would violate the architectural layer boundary where `diffguard` is the I/O boundary and `diffguard-core` is the orchestration engine.

### Option B: Create a new shared utility crate (rejected)
Creating a new crate adds unnecessary complexity to the dependency graph. Since `diffguard-types` is a shared dependency of both crates and already contains utility functions, it is the natural home for this utility.

### Option C: Leave as-is (rejected)
The duplication creates maintenance burden. Any future change to markdown escaping logic would need to be applied in two places, risking divergence.

## Consequences

**Benefits:**
- Single source of truth for markdown escaping logic
- Both crates already depend on `diffguard-types`, so no new dependency graph changes
- Architectural layer boundaries preserved (`diffguard` does not depend on `diffguard-core` internals)

**Tradeoffs:**
- `diffguard-types` now contains a utility function alongside pure DTOs — slightly blurs its "intentionally dumb" contract, but the function is purely transformative with no I/O, so it does not violate the crate's core invariant

**Risks:**
- Low: Implementations are identical, change is purely organizational
- Snapshot tests must pass to confirm no functional change

---

## References

- Issue: #472
- Prior unmerged attempt: commit `33a76e34` (branch `feat/work-33cc5aa2/...`)
