# diffguard Rule IDs and Finding Codes

This document lists all built-in rules and their finding codes.

## Rule ID Format

Rule IDs follow the pattern: `<language>.<rule_name>`

- Language prefix groups related rules
- Rule name describes what is being checked
- Custom rules SHOULD follow this convention

## Severity Levels

| Severity | Exit Code | Description |
|----------|-----------|-------------|
| `info` | 0 | Informational only, never causes failure |
| `warn` | 3 | Warning, causes failure with `--fail-on warn` |
| `error` | 2 | Error, always causes failure (unless `--fail-on never`) |

## Built-in Rules

### Rust Rules

#### `rust.no_unwrap`

**Severity:** `error`

**Message:** Avoid unwrap/expect in production code.

**Patterns:**
- `\.unwrap\(`
- `\.expect\(`

**Applies to:** `**/*.rs`

**Excludes:** `**/tests/**`, `**/benches/**`, `**/examples/**`

**Preprocessing:** Ignores comments and strings

**Rationale:** `unwrap()` and `expect()` can cause panics in production code.
Use proper error handling with `?`, `match`, or `if let` instead.

**Example finding:**
```rust
let value = result.unwrap();  // ERROR: rust.no_unwrap
```

**Suggested fix:**
```rust
let value = result?;
// or
let value = result.unwrap_or_default();
// or
let value = match result {
    Ok(v) => v,
    Err(e) => return Err(e.into()),
};
```

---

#### `rust.no_dbg`

**Severity:** `warn`

**Message:** Remove dbg!/println!/eprintln! before merging.

**Patterns:**
- `\bdbg!\(`
- `\bprintln!\(`
- `\beprintln!\(`

**Applies to:** `**/*.rs`

**Excludes:** `**/tests/**`, `**/benches/**`, `**/examples/**`

**Preprocessing:** Ignores comments and strings

**Rationale:** Debug print statements should not be committed to production code.
Use proper logging with `log` or `tracing` crates instead.

**Example finding:**
```rust
dbg!(config);  // WARN: rust.no_dbg
println!("Debug: {}", value);  // WARN: rust.no_dbg
```

**Suggested fix:**
```rust
tracing::debug!(?config);
log::debug!("Debug: {}", value);
```

---

### Python Rules

#### `python.no_print`

**Severity:** `warn`

**Message:** Remove print() before merging.

**Patterns:**
- `\bprint\s*\(`

**Applies to:** `**/*.py`

**Excludes:** `**/tests/**`, `**/test_*.py`

**Preprocessing:** Ignores comments and strings

**Rationale:** Debug print statements should not be committed to production code.
Use proper logging instead.

**Example finding:**
```python
print("Debug info")  # WARN: python.no_print
```

**Suggested fix:**
```python
import logging
logger = logging.getLogger(__name__)
logger.debug("Debug info")
```

---

#### `python.no_pdb`

**Severity:** `error`

**Message:** Remove debugger statements before merging.

**Patterns:**
- `\bimport\s+pdb\b`
- `\bpdb\.set_trace\s*\(`

**Applies to:** `**/*.py`

**Excludes:** None

**Preprocessing:** Ignores comments and strings

**Rationale:** Debugger breakpoints will hang the application in production.

**Example finding:**
```python
import pdb  # ERROR: python.no_pdb
pdb.set_trace()  # ERROR: python.no_pdb
```

**Suggested fix:**
Remove the debugger statements entirely.

---

### JavaScript/TypeScript Rules

#### `js.no_console`

**Severity:** `warn`

**Message:** Remove console.log before merging.

**Patterns:**
- `\bconsole\.(log|debug|info)\s*\(`

**Applies to:** `**/*.js`, `**/*.ts`, `**/*.jsx`, `**/*.tsx`

**Excludes:** `**/tests/**`, `**/*.test.*`, `**/*.spec.*`

**Preprocessing:** Ignores comments and strings

**Rationale:** Console statements pollute browser/node console output
and may leak sensitive information.

**Example finding:**
```javascript
console.log("Debug:", data);  // WARN: js.no_console
console.debug(state);  // WARN: js.no_console
```

**Suggested fix:**
```javascript
// Use a proper logging library
import logger from './logger';
logger.debug("Debug:", data);
```

---

#### `js.no_debugger`

**Severity:** `error`

**Message:** Remove debugger statements before merging.

**Patterns:**
- `\bdebugger\b`

**Applies to:** `**/*.js`, `**/*.ts`, `**/*.jsx`, `**/*.tsx`

**Excludes:** None

**Preprocessing:** Ignores comments and strings

**Rationale:** The `debugger` statement will pause execution when
DevTools are open, breaking production user experience.

**Example finding:**
```javascript
function process(data) {
  debugger;  // ERROR: js.no_debugger
  return transform(data);
}
```

**Suggested fix:**
Remove the `debugger` statement entirely.

---

### Go Rules

#### `go.no_fmt_print`

**Severity:** `warn`

**Message:** Remove fmt.Print* before merging.

**Patterns:**
- `\bfmt\.(Print|Println|Printf)\s*\(`

**Applies to:** `**/*.go`

**Excludes:** `**/*_test.go`

**Preprocessing:** Ignores comments and strings

**Rationale:** Debug print statements should not be committed to production code.
Use structured logging instead.

**Example finding:**
```go
fmt.Println("Debug:", value)  // WARN: go.no_fmt_print
fmt.Printf("State: %+v\n", state)  // WARN: go.no_fmt_print
```

**Suggested fix:**
```go
import "log/slog"
slog.Debug("Debug", "value", value)
```

---

## Custom Rules

Add custom rules to your `diffguard.toml`:

```toml
[[rule]]
id = "custom.no_todo"
severity = "warn"
message = "TODO comments should be tracked in issues."
patterns = ["\\bTODO\\b", "\\bFIXME\\b"]
paths = ["**/*.rs", "**/*.py", "**/*.js"]
exclude_paths = []
ignore_comments = false  # We want to match in comments!
ignore_strings = true
```

### Custom Rule Best Practices

1. **Use descriptive IDs** - `team.category.rule_name`
2. **Write clear messages** - Explain what to do, not just what's wrong
3. **Be specific with paths** - Avoid false positives with precise globs
4. **Consider preprocessing** - Set `ignore_comments`/`ignore_strings` appropriately
5. **Start with `warn`** - Upgrade to `error` once stable
6. **Exclude test files** - Unless the rule applies there too

## Language Applicability

| Rule | Rust | Python | JS | TS | Go | Ruby | C/C++ | C# | Java | Kotlin |
|------|------|--------|----|----|----|----- |-------|----|----- |--------|
| rust.no_unwrap | Yes | | | | | | | | | |
| rust.no_dbg | Yes | | | | | | | | | |
| python.no_print | | Yes | | | | | | | | |
| python.no_pdb | | Yes | | | | | | | | |
| js.no_console | | | Yes | Yes | | | | | | |
| js.no_debugger | | | Yes | Yes | | | | | | |
| go.no_fmt_print | | | | | Yes | | | | | |

## Exit Code Reference

| Scenario | Exit Code |
|----------|-----------|
| No findings | 0 |
| Only info-level findings | 0 |
| Only warn-level findings, `--fail-on error` | 0 |
| Only warn-level findings, `--fail-on warn` | 3 |
| Any error-level findings | 2 |
| Tool error (invalid config, etc.) | 1 |
| Any findings, `--fail-on never` | 0 |
