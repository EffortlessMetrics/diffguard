# Dependency Audit Report

**Work ID:** work-48dac268  
**Branch:** feat/work-48dac268/enable-xtask-ci  
**Audit Date:** 2026-04-08  
**Auditor:** dependency-audit-agent

## Summary

| Category | Status |
|----------|--------|
| Dependencies Added/Changed | None |
| License Compatibility | Pass |
| Semver Violations | None |
| Lockfile Status | Not committed (by design) |
| Duplicate Dependencies | Info only (not blocking) |
| Deprecation Issues | None |

---

## 1. Dependencies Added or Changed

**No dependencies were added or modified in this branch.**

The changes in this branch are limited to:
- `.github/workflows/ci.yml` - Enabling xtask CI job (removed `if: false`, changed test command)
- `action.yml` - Hardening improvements (permissions, curl flags, tar extraction, SARIF upload)
- `CHANGELOG.md` - Documentation updates

No Cargo.toml files were modified in this branch.

---

## 2. License Compatibility Check

**Result: PASS**

The workspace license is declared as:
```
license = "MIT OR Apache-2.0"
```

All direct workspace dependencies inherit compatible licenses:
- Core dependencies (anyhow, chrono, clap, serde, etc.) are MIT or Apache-2.0
- All transitive dependencies checked are compatible with MIT OR Apache-2.0

No copyleft or incompatible licenses detected.

---

## 3. Semver Violations Check

**Result: PASS - No semver-major bumps**

No dependencies were modified in this branch, so no semver analysis is applicable.

---

## 4. Lockfile Status

**Result: INFO (Not blocking)**

The `Cargo.lock` file is intentionally not committed to version control (listed in `.gitignore`). This is a deliberate project choice as shown by the workspace configuration.

```gitignore
Cargo.lock
!/fuzz/Cargo.toml
```

Verification:
- `cargo check --workspace` completes successfully
- `cargo fetch` confirms lockfile is in sync with manifests
- No dependency resolution errors

**Note:** If the project policy requires committing Cargo.lock, this would be a deviation, but since this is the established project pattern and no new dependencies were added, this is not blocking.

---

## 5. Duplicate Dependency Versions

**Result: INFO - Non-blocking duplicates detected**

The dependency tree contains some duplicate version pairs:

| Package | Versions Found | Note |
|---------|----------------|------|
| winnow | 0.7.15, 1.0.1 | Required by different toml versions |
| bit-set | 0.5.3, 0.8.0 | Transitive via different deps |
| bit-vec | 0.6.3, 0.8.0 | Transitive via different deps |
| bitflags | 1.3.2, 2.11.0 | Transitive via different deps |

These duplicates are caused by transitive dependencies pinning different versions. They do not cause build failures or conflicts. This is common in Rust projects and is not a blocking issue.

---

## 6. Deprecated or Unmaintained Dependencies

**Result: PASS - No deprecated dependencies detected**

All dependencies are actively maintained. No deprecation warnings from cargo.

---

## Findings by Severity

| Severity | Count | Description |
|----------|-------|-------------|
| Blocking | 0 | None |
| Warning | 0 | None |
| Info | 4 | Non-blocking duplicate versions |

---

## Recommendation

**PASS**

This branch introduces no dependency changes. The audit confirms:
1. No new or modified dependencies
2. All licenses are compatible with project policy
3. No semver-breaking changes
4. Lockfile is in sync (even though not committed)
5. Duplicate dependencies are informational only
6. No deprecated packages

The changes are CI and documentation focused with no dependency risk.
