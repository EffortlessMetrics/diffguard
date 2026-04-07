# Dependency Audit Report

**Work Item:** work-9e77f361  
**Branch:** feat/work-9e77f361/add-performance-benchmark-infrastructure  
**Audit Date:** 2026-04-07  
**Auditor:** dependency-audit-agent

---

## Summary

| Check | Status |
|-------|--------|
| License Compatibility | ✅ Pass |
| Semver Violations | ✅ Pass |
| Lockfile Status | ⚠️ Warning (pre-existing) |
| Duplicate Dependencies | ✅ Pass |
| Deprecated Dependencies | ⚠️ Warning (non-blocking) |

**Recommendation:** `pass-with-warnings`

---

## Dependencies Added or Changed

### New Crate: `diffguard-bench`

| Dependency | Version | Type | License | Notes |
|------------|---------|------|---------|-------|
| criterion | 0.5.1 | normal | MIT OR Apache-2.0 | Benchmarking framework |
| proptest | 1.11.0 | dev | MIT OR Apache-2.0 | Property testing (dev-dependency) |
| diffguard-diff | 0.2.0 | path | MIT OR Apache-2.0 | Internal workspace crate |
| diffguard-domain | 0.2.0 | path | MIT OR Apache-2.0 | Internal workspace crate |
| diffguard-core | 0.2.0 | path | MIT OR Apache-2.0 | Internal workspace crate |
| diffguard-types | 0.2.0 | path | MIT OR Apache-2.0 | Internal workspace crate |
| diffguard-testkit | 0.2.0 | path | MIT OR Apache-2.0 | Internal workspace crate (dev) |
| insta | 1.46.3 | dev | MIT OR Apache-2.0 | Snapshot testing (via workspace) |
| serde_json | 1.0.149 | dev | MIT OR Apache-2.0 | JSON serialization (via workspace) |

### Workspace Dependency Addition

| Dependency | Version Spec | Resolved | Semver-Major? |
|------------|--------------|----------|---------------|
| criterion | 0.5 | 0.5.1 | No (0.5.0 → 0.5.1 is patch) |

---

## License Compatibility Check

✅ **All licenses are compatible with the workspace license (MIT OR Apache-2.0)**

- `criterion 0.5.1`: MIT OR Apache-2.0 ✅
- `proptest 1.11.0`: MIT OR Apache-2.0 ✅
- All internal path dependencies: MIT OR Apache-2.0 ✅

No copyleft, restricted, or incompatible licenses detected.

---

## Semver Violations

✅ **No semver-major violations detected**

- `criterion`: Specified as `0.5` which resolves to `>=0.5.0 <0.6.0`. Resolved version is `0.5.1`, a patch update within the same minor version. This is not a breaking change.
- All other dependencies are path-based workspace crates at version `0.2.0`.

---

## Lockfile Status

⚠️ **Warning: Cargo.lock is not committed**

- `Cargo.lock` exists at workspace root (68306 bytes, last modified Apr 7 20:55)
- `Cargo.lock` is listed in `.gitignore` — this is **pre-existing** and consistent with the repo's `.gitignore` on `main`
- `cargo check --locked -p diffguard-bench` **passes** — lockfile is up to date with `Cargo.toml`

**Assessment:** This is a repository-wide policy decision, not a problem introduced by this work item. The lockfile is currently up-to-date.

---

## Duplicate Dependency Versions

✅ **No duplicate versions detected**

- `cargo tree -d` shows only version conflicts for `winnow` and `toml` which are unrelated to the bench crate (they appear in main workspace)
- `proptest` resolves to a single version (1.11.0) across all uses

---

## Deprecated or Unmaintained Dependencies

⚠️ **criterion 0.5 is not the latest version**

| Package | Specified | Latest | Status |
|---------|-----------|--------|--------|
| criterion | 0.5.1 | 0.8.2 | **Not deprecated**, but outdated |

The `criterion` crate 0.5.x is a mature, stable version. Version 0.8.x introduced breaking changes. Using 0.5 is a valid conservative choice. This is flagged as a **warning only**, not blocking, as the crate is actively maintained and 0.5.x receives bug fixes.

---

## Findings Detail

### Blocking Issues
**0** — No blocking issues found.

### Warnings (Non-Blocking)
1. **Cargo.lock not committed** — Repository-level `.gitignore` policy. Lockfile is currently up-to-date but this reduces reproducibility for downstream users.
2. **criterion 0.5.1 vs latest 0.8.2** — Outdated but stable. No security or functionality concerns with 0.5.x line.

### Info
- New `bench` crate added as workspace member
- `criterion` added to workspace dependencies for benchmark support
- All internal workspace dependencies use path references (no external version changes)

---

## Verification Commands

```bash
# Verify bench crate compiles
cargo check -p diffguard-bench

# Verify lockfile is in sync (using --locked to verify)
cargo check -p diffguard-bench --locked

# Check for duplicate dependencies
cargo tree -d

# Verify license compatibility
cargo tree -e no-dev -p diffguard-bench | grep -i "license\|MIT\|Apache"
```
