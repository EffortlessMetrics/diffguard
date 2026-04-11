# ADR-011: Remove Unnecessary Result Wrapper from parse_blame_porcelain

**Status:** Accepted

**Date:** 2026-04-11

**Work Item:** work-430b0729

---

## Context

Issue #141 reports that `parse_blame_porcelain` in `crates/diffguard/src/main.rs` (line 1768) is typed to return `Result<BTreeMap<u32, BlameLineMeta>>` but never actually returns `Err`. This is dead code — the function silently skips invalid entries via `continue` rather than propagating errors, and always reaches `Ok(out)` at line 1818.

Clippy detects this pattern with the `unnecessary_result_bool` lint (or equivalent): *"this function's return value is unnecessarily wrapped by `Result`"*.

---

## Decision

Change `parse_blame_porcelain` to return `BTreeMap<u32, BlameLineMeta>` directly, removing the `Result` wrapper.

### Changes Required

1. **Function signature (line 1768):**
   ```rust
   // Before
   fn parse_blame_porcelain(blame_text: &str) -> Result<BTreeMap<u32, BlameLineMeta>>
   
   // After
   fn parse_blame_porcelain(blame_text: &str) -> BTreeMap<u32, BlameLineMeta>
   ```

2. **Return expression (line 1818):**
   ```rust
   // Before
   Ok(out)
   
   // After
   out
   ```

3. **Caller in `collect_blame_allowed_lines` (lines 1861-1862):**
   ```rust
   // Before
   let blame_map = parse_blame_porcelain(&blame_text)
       .with_context(|| format!("parse git blame for {}", path))?;
   
   // After
   let blame_map = parse_blame_porcelain(&blame_text);
   ```

4. **Test at line 4068:**
   ```rust
   // Before
   let map = parse_blame_porcelain(porcelain).expect("parse");
   
   // After
   let map = parse_blame_porcelain(porcelain);
   ```

### Rationale for Silent-Skip Behavior

The parsing logic skips malformed entries rather than failing because:
- Git blame output for files with unusual content (binary, untrusted encoding) may contain partial/invalid entries
- The function is used to extract allowed-line metadata for diff checking — incomplete data is tolerable, hard failure is not
- This behavior is established and users depend on it

---

## Alternatives Considered

### 1. Keep Result and document the never-err case
Adding a comment like `// SAFETY: this function never returns Err` would suppress the lint but leave unnecessary complexity for callers.

### 2. Return Option instead of bare BTreeMap
`Option<BTreeMap<u32, BlameLineMeta>>` would allow `None` for parse failures, but no call site checks for `Err` so `None` would be equally unused. The bare type is cleaner.

### 3. Make the function return Result and propagate real errors
Adding proper error propagation would be a breaking change to the call sites' logic and is out of scope for this fix.

---

## Consequences

**Positive:**
- Removes dead error-handling code from callers
- Eliminates Clippy lint
- Improves code clarity — readers know the function cannot fail
- Removes `.expect()` from test, making test failure messages cleaner

**Negative:**
- None — this is purely a refactor with no behavioral change

**Neutral:**
- The `anyhow::Result` type alias used throughout the crate remains; this only affects one function's return type

---

## Files Affected

- `crates/diffguard/src/main.rs` — function definition (line 1768), return (line 1818), caller (lines 1861-1862), test (line 4068)

---

## Verification

After applying changes:
1. Run `cargo clippy -p diffguard` — confirm no lint warnings related to `parse_blame_porcelain`
2. Run `cargo test -p diffguard` — confirm all tests pass, especially `parse_blame_porcelain_extracts_line_metadata`