# diffguard

A diff-scoped governance linter that applies rules only to added/changed lines in a Git diff.

## Purpose

Designed for PR automation workflows to catch policy violations in new code without repo-wide grep noise.

## Key Features

- **Diff-aware**: Only scans added or changed lines, not the entire codebase
- **JSON receipts**: Stable output format for bots and automation
- **Markdown summaries**: Compact reports for PR comments
- **GitHub Actions annotations**: Native `::error`/`::warning` output
- **Configurable rules**: Regex patterns with glob path matching, language filtering, and comment/string ignoring

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Pass (or only warnings when `fail_on = "error"`) |
| 1 | Tool error (I/O, parse, git failure, invalid config) |
| 2 | Policy failure (error-level findings) |
| 3 | Warn-level failure (only when `fail_on = "warn"`) |

## Configuration

Rules are defined in `diffguard.toml` with support for:
- Severity levels: `info`, `warn`, `error`
- Scope: `added` or `changed` lines
- Path include/exclude globs
- Language filtering
- Comment and string literal ignoring
