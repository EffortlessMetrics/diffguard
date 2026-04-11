# Dependency Audit Report: work-d1531005

## Work Item
- **Work ID:** work-d1531005
- **Gate:** HARDENED
- **Branch:** feat/work-d1531005/api--compiledrule-exported-from-diffguar
- **Description:** api: CompiledRule exported from diffguard-domain but appears to be internal

## Audit Results

### 1. Security Vulnerability Scan
- **Tool:** `cargo audit`
- **Result:** ✅ PASSED
- **Details:** No security vulnerabilities found in 286 crate dependencies
- **Advisory database:** 1042 security advisories loaded

### 2. New Dependencies Added
- **Status:** ⚠️ YES - New dependency detected
- **Package:** `regex` version `"1"` 
- **Location:** `crates/diffguard-types/Cargo.toml`
- **Note:** The task description stated "NO new dependencies added" but this was incorrect. The regex dependency was added in this change.

### 3. Dependency Tree Status
- **Cargo.lock:** Up to date (286 dependencies)
- **Workspace dependencies:** Unchanged (no workspace-level Cargo.toml modifications)

## Files Changed Related to Dependencies
```diff
diff --git a/crates/diffguard-types/Cargo.toml b/crates/diffguard-types/Cargo.toml
--- a/crates/diffguard-types/Cargo.toml
+++ b/crates/diffguard-types/Cargo.toml
@@ -21,3 +21,4 @@ schemars.workspace = true
 proptest.workspace = true
 jsonschema = "0.18"
 toml.workspace = true
+regex = "1"
```

## Summary
| Check | Status |
|-------|--------|
| Security vulnerabilities | ✅ None found |
| New dependencies added | ⚠️ YES (`regex = "1"`) |
| Dependency tree clean | ✅ Yes (286 deps scanned) |

## Recommendation
The new `regex = "1"` dependency should be reviewed. If this dependency was unintentionally added, it should be removed. If it's a legitimate requirement for the change (likely used for pattern matching in the rule system), it should be documented in the change rationale.

**Audit completed successfully - no vulnerable dependencies found.**
