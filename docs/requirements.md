# diffguard Requirements

This document captures the functional and non-functional requirements for diffguard.

## Mission Statement

diffguard is a **diff-scoped governance linter** for PR automation. It applies configurable rules
only to added or changed lines in Git diffs, enabling teams to enforce coding standards on new
code without creating noise from legacy issues.

## Truth Layer

The source of truth for diffguard is always the **unified diff** between two Git refs.
This means:

1. Only lines that appear as additions (`+`) in the diff are candidates for rule evaluation
2. Context lines and removed lines are not evaluated
3. The tool never reads source files directly; all content comes from the diff

This design ensures:
- Deterministic behavior: same inputs (diff text + rules) always produce the same outputs
- No false positives from unchanged code
- Fast execution regardless of repository size

## Users and Use-Cases

### Primary Users

1. **Platform/DevOps Engineers** - Configure diffguard in CI pipelines to enforce coding standards
2. **Tech Leads** - Define rules to catch common issues before code review
3. **Individual Developers** - Run locally to check changes before pushing

### Core Use-Cases

| Use-Case | Description |
|----------|-------------|
| Block debug statements | Prevent `console.log`, `dbg!`, `print()` from reaching main |
| Enforce error handling | Flag `.unwrap()`, `.expect()` in production Rust code |
| Custom pattern matching | Match arbitrary regex patterns in specific file types |
| CI gate | Fail PRs that violate rules with error severity |
| Incremental adoption | Apply rules only to new code, avoiding legacy noise |

## Non-Goals

The following are explicitly **not** in scope for diffguard:

1. **Full AST analysis** - diffguard uses regex patterns, not language parsers
2. **Auto-fixing** - diffguard reports findings but does not modify code
3. **Blame/authorship tracking** - diffguard does not attribute findings to specific authors
4. **Diff generation** - diffguard consumes diffs; use `git diff` to generate them
5. **Replacement for linters** - diffguard complements language-specific linters (rustfmt, eslint, etc.)

## Functional Requirements

### 1. CLI Interface

| ID | Requirement |
|----|-------------|
| 1.1 | The `check` subcommand MUST accept `--base` and `--head` refs |
| 1.2 | The `check` subcommand MUST accept `--config` path or default to `./diffguard.toml` |
| 1.3 | The `check` subcommand MUST support `--scope` with values `added` or `changed` |
| 1.4 | The `check` subcommand MUST support `--fail-on` with values `error`, `warn`, or `never` |
| 1.5 | The `check` subcommand MUST support `--max-findings` to cap output |
| 1.6 | The `check` subcommand MUST support `--paths` for glob-based path filtering |
| 1.7 | The `check` subcommand MUST support `--out` for JSON receipt path |
| 1.8 | The `check` subcommand MUST support `--md` for Markdown summary path |
| 1.9 | The `check` subcommand MUST support `--github-annotations` for CI integration |
| 1.10 | The `rules` subcommand MUST print effective rules in TOML or JSON format |
| 1.11 | The CLI MUST support `--no-default-rules` to disable built-in rules |

### 2. Configuration

| ID | Requirement |
|----|-------------|
| 2.1 | Configuration MUST be in TOML format |
| 2.2 | Each rule MUST have an `id`, `severity`, `message`, and `patterns` |
| 2.3 | Rules MAY specify `languages` to filter by file type |
| 2.4 | Rules MAY specify `paths` (include globs) and `exclude_paths` (exclude globs) |
| 2.5 | Rules MAY specify `ignore_comments` and `ignore_strings` for preprocessing |
| 2.6 | The `defaults` section SHOULD specify `base`, `head`, `scope`, `fail_on`, `max_findings` |
| 2.7 | User rules MUST be merged with built-in rules; user rules with the same ID override built-ins |

### 3. Rule Model

| ID | Requirement |
|----|-------------|
| 3.1 | Patterns MUST be valid Rust regex syntax |
| 3.2 | Severity MUST be one of: `info`, `warn`, `error` |
| 3.3 | Path globs MUST follow globset syntax (supports `**`) |
| 3.4 | Language detection MUST be based on file extension |
| 3.5 | When `ignore_comments` is true, comment content MUST be masked before matching |
| 3.6 | When `ignore_strings` is true, string content MUST be masked before matching |

### 4. Diff Handling

| ID | Requirement |
|----|-------------|
| 4.1 | Binary files MUST be skipped (no content extraction) |
| 4.2 | Submodule changes MUST be skipped |
| 4.3 | Renamed files MUST use the new (destination) path |
| 4.4 | Mode-only changes (chmod) MUST be skipped |
| 4.5 | Deleted files MUST be skipped (no negative line numbers) |
| 4.6 | Malformed hunk headers MUST NOT crash parsing; subsequent files MUST still be processed |

### 5. Escape Hatches

| ID | Requirement |
|----|-------------|
| 5.1 | The `--fail-on never` option MUST exit 0 regardless of findings |
| 5.2 | Path filters (`--paths`) MUST restrict which files are scanned |
| 5.3 | Exclude paths in rules MUST prevent matching in specified directories |
| 5.4 | `--no-default-rules` MUST disable all built-in rules |

### 6. Outputs

| ID | Requirement |
|----|-------------|
| 6.1 | JSON receipt MUST include: schema version, tool metadata, diff metadata, findings, verdict |
| 6.2 | Each finding MUST include: rule_id, severity, message, path, line, match_text, snippet |
| 6.3 | Verdict MUST include: status (pass/warn/fail), counts, reasons |
| 6.4 | Markdown summary MUST include: header with status, scan stats, findings table |
| 6.5 | GitHub annotations MUST use the workflow command format: `::level file=...,line=...::[message]` |

## Stability Policy

### Exit Codes (Stable API)

| Code | Meaning |
|------|---------|
| 0 | Pass - no policy violations |
| 1 | Tool error - internal failure, invalid config, etc. |
| 2 | Policy fail - at least one error-severity finding |
| 3 | Warn-fail - at least one warning when `--fail-on warn` |

### JSON Schema Versioning

- Receipt schema is versioned (currently `diffguard.check.v1`)
- Breaking changes to schema MUST increment the version
- Schema changes SHOULD be backward-compatible when possible

### Configuration Compatibility

- New config fields SHOULD have sensible defaults
- Removing config fields is a breaking change
- Built-in rule IDs are part of the public API
