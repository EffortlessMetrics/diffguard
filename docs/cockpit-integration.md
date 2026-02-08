# Cockpit Integration Guide

How diffguard integrates with the Cockpit ecosystem as a Tier-1 sensor.

## Artifact Layout

When running in cockpit mode (`--mode cockpit --sensor`), diffguard produces:

```
artifacts/diffguard/
  report.json           # sensor.report.v1 envelope (Tier A)
  comment.md            # Human-readable PR summary (Tier C)
  extras/
    check.json          # diffguard.check.v1 receipt (Tier C)
    report.sarif.json   # SARIF 2.1.0 (Tier C)
    report.xml          # JUnit XML (Tier C)
    report.csv          # CSV (Tier C)
    report.tsv          # TSV (Tier C)
```

## Tier A — Cockpit ABI (never break)

These contracts are stable. Breaking them requires a schema version bump.

### Sensor Envelope

`artifacts/diffguard/report.json` always conforms to `sensor.report.v1`.

Schema file: `contracts/schemas/sensor.report.v1.schema.json`

### Frozen Vocabulary

| Category | Values |
|----------|--------|
| `verdict.status` | `pass`, `warn`, `fail`, `skip` |
| `severity` | `info`, `warn`, `error` |
| `check_id` | `diffguard.pattern`, `diffguard.internal` |
| `capabilities` keys | `git` |
| `capabilities[].status` | `available`, `unavailable`, `skipped` |
| Reason tokens | `no_diff_input`, `missing_base`, `git_unavailable`, `tool_error`, `truncated` |
| Error codes | `tool.runtime_error` |

All tokens match `^[a-z][a-z0-9_.]*$`.

### Identity Tuple

Each finding is uniquely identified by: `(tool, check_id, code, fingerprint)`.

- `fingerprint` is a full SHA-256 (64 lowercase hex chars)
- Fingerprints are deterministic: same input always produces the same hash

### Determinism

Given identical inputs, diffguard produces byte-identical output (excluding timing fields: `started_at`, `ended_at`, `duration_ms`).

- Findings are sorted by `(path, line, rule_id)` for stable ordering
- Truncation is deterministic (first N findings kept)

### Exit Codes (cockpit mode)

| Code | Meaning |
|------|---------|
| `0` | Receipt written successfully (regardless of verdict) |
| `1` | Catastrophic failure (no receipt could be written) |

### Path Conventions

- `location.path` values use forward slashes, are repo-relative, contain no `..` traversals
- `artifacts[].path` values use forward slashes

## Tier B — Cockpit-readable optional data (break only with coordination)

These keys live in the `data` field of the sensor report. If cockpit starts reading
a key, it effectively becomes API and requires coordination to change.

### `data.diffguard` summary

```json
{
  "data": {
    "diff": { ... },
    "diffguard": {
      "suppressed_count": 0,
      "truncated_count": 0,
      "rules_matched": 3,
      "rules_total": 12
    }
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `suppressed_count` | `u32` | Findings suppressed via inline directives |
| `truncated_count` | `u32` | Findings dropped due to `max_findings` limit |
| `rules_matched` | `usize` | Distinct rules that produced at least one finding |
| `rules_total` | `usize` | Total rules evaluated (after tag filtering) |

### `data.diff` metadata

```json
{
  "data": {
    "diff": {
      "base": "origin/main",
      "head": "HEAD",
      "context_lines": 0,
      "scope": "added",
      "files_scanned": 42,
      "lines_scanned": 1200
    }
  }
}
```

## Tier C — Extras (free to evolve, link only)

These artifacts are referenced in `artifacts[]` but their internal structure
can evolve freely. Cockpit links to them but does not parse them.

| Artifact | Schema | Description |
|----------|--------|-------------|
| `extras/check.json` | `diffguard.check.v1` | Tool-native receipt with full findings |
| `extras/report.sarif.json` | SARIF 2.1.0 | For GitHub Code Scanning / IDE import |
| `extras/report.xml` | JUnit XML | For CI/CD test result integration |
| `extras/report.csv` | CSV | Tabular export |
| `extras/report.tsv` | TSV | Tabular export |
| `comment.md` | Markdown | Human-readable PR comment snippet |

## Promotion Checklist

Before proposing a new key or artifact for cockpit consumption:

1. **Stability** — The value has been emitted for at least 2 releases without schema changes
2. **Determinism** — The value is deterministic (same inputs produce same output)
3. **Naming** — Key names follow the token format `^[a-z][a-z0-9_.]*$`
4. **Documentation** — The key is documented in this file with type and description
5. **Conformance** — A conformance test in `xtask/src/conform.rs` validates the key
6. **Schema** — The vendored contract schema includes the new field (if structurally constrained)
7. **Coordination** — A PR or issue is opened against the cockpit integration spec
