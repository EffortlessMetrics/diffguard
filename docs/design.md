# diffguard Design

This document describes the technical design and internal workings of diffguard.

## High-Level Pipeline

```
     [Git Repository]
            |
            | git diff base...head
            v
    +---------------+
    | Unified Diff  |  (text input)
    +---------------+
            |
            v
    +---------------+
    | Diff Parser   |  diffguard-diff
    +---------------+
            |
            | Vec<DiffLine>
            v
    +---------------+
    | Preprocessor  |  diffguard-domain (mask comments/strings)
    +---------------+
            |
            v
    +---------------+
    | Rule Matcher  |  diffguard-domain (regex evaluation)
    +---------------+
            |
            | Vec<Finding>
            v
    +---------------+
    | Verdict       |  diffguard-core (aggregate, compute exit code)
    +---------------+
            |
            v
    +------+------+------+
    |      |      |      |
  JSON  Markdown  Annotations
```

## Dataflow Details

### 1. Diff Acquisition

The CLI supports three diff sources:

- `git diff --unified=N base...head` (default)
- `git diff --cached --unified=N` (`--staged`)
- Unified diff text from file/stdin (`--diff-file <path|->`)

For multi-base comparisons (`--base` repeated), diffguard computes each base-to-head
diff and evaluates the union of changed lines (deduplicated by path/line/content).

Key parameters:
- `base`: Git ref (branch, tag, or SHA) representing the target branch
- `head`: Git ref representing the source branch (often `HEAD`)
- `--unified=N`: Context lines (default 0 for minimal diff)

### 2. Diff Parsing (`diffguard-diff`)

The parser processes the unified diff format line-by-line:

```
diff --git a/path b/path    -> New file section, extract path
--- a/path                  -> Old file path
+++ b/path                  -> New file path (preferred)
@@ -old,count +new,count @@ -> Hunk header, extract new line number
 context line               -> Increment line counter
+added line                 -> Emit DiffLine, increment counter
-removed line               -> Track for "changed" scope
```

**Scope semantics:**
- `Scope::Added`: All lines starting with `+`
- `Scope::Changed`: Only `+` lines immediately following `-` lines (modifications)

**Special case handling:**
- Binary files: Detected by `Binary files ... differ`, skipped entirely
- Submodules: Detected by `Subproject commit ...`, skipped
- Renames: Use destination path from `rename to ...`
- Deleted files: Skip (no added lines to evaluate)
- Mode changes: Skip (no content changes)

### 3. Preprocessing (`diffguard-domain/preprocess.rs`)

Before regex matching, lines are optionally preprocessed to mask:
- **Comments**: Replaced with spaces to preserve column positions
- **Strings**: Replaced with spaces to avoid false positives

The preprocessor is **language-aware** and handles:

| Language | Comment Syntax | String Syntax |
|----------|---------------|---------------|
| Rust | `//`, `/* */` (nested) | `"..."`, `r#"..."#`, `b"..."` |
| Python | `#` | `"..."`, `'...'`, `"""..."""` |
| JavaScript | `//`, `/* */` | `"..."`, `'...'`, `` `...` `` |
| Go | `//`, `/* */` | `"..."`, `` `...` `` (raw) |
| Ruby | `#` | `"..."`, `'...'` |
| C/C++ | `//`, `/* */` | `"..."`, `'c'` |
| SQL | `--`, `/* */` | `'...'` |
| XML/HTML | `<!-- -->` | `"..."`, `'...'` |
| PHP | `//`, `#`, `/* */` | `"..."`, `'...'` |
| YAML/TOML | `#` | C-style best-effort |
| JSON/JSONC | `//`, `/* */` | C-style best-effort |

**Stateful processing:**
The preprocessor maintains state across lines to handle multi-line comments
and strings. State is reset when switching between files.

**Limitations (by design):**
- Uses heuristics, not full language parsers
- May not handle all edge cases (nested string interpolation, etc.)
- Best-effort: false negatives preferred over false positives

### 4. Rule Matching (`diffguard-domain/rules.rs`, `evaluate.rs`)

Rules are compiled once at startup:
1. Validate all patterns as valid regex
2. Compile path globs into `GlobSet` for efficient matching
3. Normalize language identifiers to lowercase

For each diff line, the evaluator:
1. Checks if the rule applies (path globs + language filter)
2. Selects the appropriate preprocessed line variant
3. Runs regex patterns in order (first match wins)
4. Records finding with location and matched text

**Applicability checks:**
```
applies = path_in_include_globs(path)
       && !path_in_exclude_globs(path)
       && (rule.languages.is_empty() || language in rule.languages)
```

### 5. Verdict Computation (`diffguard-core/check.rs`)

The verdict aggregates findings into counts and determines the final status:

```
if counts.error > 0:
    status = Fail
elif counts.warn > 0:
    status = Warn
else:
    status = Pass
```

Exit code computation respects the `fail_on` policy:

```
if fail_on == Never:
    exit 0
if counts.error > 0:
    exit 2
if fail_on == Warn && counts.warn > 0:
    exit 3
exit 0
```

## Suppression Model

Suppressions allow developers to acknowledge findings without fixing them.
Suppressed findings are tracked in `VerdictCounts.suppressed` but do not affect
the exit code or verdict status.

```rust
let x = risky_call().unwrap(); // diffguard: ignore rust.no_unwrap
```

Suppression patterns:
- `diffguard: ignore <rule_id>` - Suppress specific rule on this line
- `diffguard: ignore-next-line <rule_id>` - Suppress on the following line
- `diffguard: ignore *` / `diffguard: ignore-all` - Suppress all rules (wildcard)
- Multiple rules can be comma-separated: `diffguard: ignore rule1, rule2`
- Suppressions MUST appear in the diff to take effect (no legacy suppressions)

## Configuration System

### Environment Variable Expansion

Config file content is expanded before TOML parsing. Two forms are supported:

- `${VAR}` - Replaced with the value of `VAR`; errors if unset
- `${VAR:-default}` - Replaced with the value of `VAR`, or `"default"` if unset/empty

```toml
[[rule]]
id = "custom.check"
paths = ["${PROJECT_ROOT}/src/**/*.rs"]
message = "Custom check for ${PROJECT_NAME:-myproject}"
```

### Config Includes

Config files can include other config files via the `includes` directive:

```toml
includes = ["base-rules.toml", "team-overrides.toml"]

[[rule]]
id = "project.specific"
# ...
```

Include resolution:
- Paths are relative to the including file's directory
- Rules are merged by ID (later definitions override earlier ones)
- Circular includes are detected and rejected
- Maximum nesting depth: 10 levels

### Rule Tagging

Rules can be tagged for selective filtering:

```toml
[[rule]]
id = "rust.no_unwrap"
tags = ["safety", "production"]
```

CLI filtering:
- `--only-tags safety` - Only run rules tagged `safety`
- `--enable-tags debug` / `--disable-tags style` - Toggle rules by tag

## Language Detection

Language is detected from file extensions:

| Extension(s) | Language |
|--------------|----------|
| `.rs` | rust |
| `.py`, `.pyw` | python |
| `.js`, `.mjs`, `.cjs`, `.jsx` | javascript |
| `.ts`, `.mts`, `.cts`, `.tsx` | typescript |
| `.go` | go |
| `.rb`, `.rake` | ruby |
| `.c`, `.h` | c |
| `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`, `.hh` | cpp |
| `.cs` | csharp |
| `.java` | java |
| `.kt`, `.kts` | kotlin |
| `.sql` | sql |
| `.xml`, `.html`, `.xsl`, ... | xml |
| `.php`, `.phtml`, ... | php |
| `.yaml`, `.yml` | yaml |
| `.toml` | toml |
| `.json`, `.jsonc`, `.json5` | json |

Unknown extensions return `None`, which:
- Matches rules with empty `languages` filter
- Uses C-style comment/string syntax for preprocessing

## Receipt Schema

```json
{
  "schema": "diffguard.check.v1",
  "tool": {
    "name": "diffguard",
    "version": "0.1.0"
  },
  "diff": {
    "base": "origin/main",
    "head": "HEAD",
    "context_lines": 0,
    "scope": "added",
    "files_scanned": 5,
    "lines_scanned": 120
  },
  "findings": [
    {
      "rule_id": "rust.no_unwrap",
      "severity": "error",
      "message": "Avoid unwrap/expect in production code.",
      "path": "src/lib.rs",
      "line": 42,
      "column": 15,
      "match_text": ".unwrap(",
      "snippet": "let value = result.unwrap();"
    }
  ],
  "verdict": {
    "status": "fail",
    "counts": { "info": 0, "warn": 0, "error": 1, "suppressed": 0 },
    "reasons": ["1 error(s)"]
  },
  "timing": {
    "total_ms": 12,
    "diff_parse_ms": 2,
    "rule_compile_ms": 3,
    "evaluation_ms": 7
  }
}
```

## Rendering

### Markdown

The markdown renderer produces a summary table for PR comments:

```markdown
## diffguard - FAIL

Scanned **5** file(s), **120** line(s) (scope: `added`, base: `origin/main`, head: `HEAD`)

**Verdict reasons:**
- 1 error(s)

| Severity | Rule | Location | Message | Snippet |
|---|---|---|---|---|
| error | `rust.no_unwrap` | `src/lib.rs:42` | Avoid unwrap/expect... | `result.unwrap()` |
```

### GitHub Annotations

Annotations use the workflow command format recognized by GitHub Actions:

```
::error file=src/lib.rs,line=42::rust.no_unwrap Avoid unwrap/expect in production code.
::warning file=src/main.rs,line=10::rust.no_dbg Remove dbg!/println! before merging.
```

## Sensor Report

The sensor report (`sensor.report.v1`) is the R2 Library Contract output envelope
for integrated Cockpit/BusyBox usage. It wraps the check receipt with additional
metadata:

```json
{
  "schema": "sensor.report.v1",
  "tool": { "name": "diffguard", "version": "0.2.0" },
  "run": {
    "check_id": "diffguard.pattern",
    "status": "fail",
    "started_at": "2026-02-06T10:00:00Z",
    "ended_at": "2026-02-06T10:00:01Z",
    "duration_ms": 1200
  },
  "capabilities": {
    "git": { "status": "available" }
  },
  "findings": [ ... ],
  "artifacts": [ ... ]
}
```

The `run_sensor()` entry point in `sensor_api.rs` accepts a `Settings` struct
and optional `Substrate` trait object, returning a `SensorReport`.

## Finding Fingerprints

Each finding receives a stable SHA-256 fingerprint computed from
`rule_id:path:line:match_text`. This 64-character hex string enables:

- Deduplication across runs
- Tracking finding lifecycle (new, existing, resolved)
- Correlation between sensor reports

The fingerprint is intentionally independent of severity, message, and snippet
so that cosmetic changes to rule metadata do not alter identity.

## Budgets and Noise Control

### Max Findings

The `--max-findings` option (default 200) limits the number of findings in output.
Beyond this limit:
- Findings are still counted in verdict totals
- Truncated count is reported in reasons
- Prevents overwhelming output in badly failing PRs

### Severity Filtering

Rules can be assigned different severities:
- `info`: Informational, never causes failure
- `warn`: Warning, causes exit 3 when `--fail-on warn`
- `error`: Error, always causes exit 2

### Path Filtering

Multiple layers of path filtering:
1. CLI `--paths`: Only scan files matching these globs
2. Rule `paths`: Only apply this rule to matching files
3. Rule `exclude_paths`: Skip this rule for matching files

Filters are evaluated in order: CLI filter first, then per-rule filters.
