# diffguard Design Philosophy

## What diffguard is

diffguard is a **governance primitive layer** for software change.

It provides the building blocks for teams to compose their own governance model:

- **Rules** — check whatever you want (code patterns, artifact existence, PR metadata)
- **Findings** — specific violations with locations and messages
- **Receipts** — structured evidence of what was checked and what was found
- **Verdicts** — pass/fail/error with stable semantics and exit codes

diffguard does not enforce a specific governance model. It provides primitives. Teams compose their own governance from those primitives.

## The architecture

```
Primitives (what diffguard provides)
  → Rules, findings, receipts, verdicts

Governance model (what the team composes)
  → Gate definitions, gate requirements, gate evidence

Work process (what the team does)
  → Their own workflow, CI, review process
```

Each layer is independent:

- Use the primitives without any governance model (just lint code)
- Compose any governance model from the primitives (conveyor, trunk-based, regulatory, custom)
- Change the governance model without changing the primitives

## The rule model

Rules are the core primitive. A rule checks something and produces findings.

Current rule types:
- **Pattern rules** — regex matching on diff lines (what diffguard does today)

Planned rule types:
- **Artifact existence** — check that a file exists with optional content regex
- **PR metadata** — check PR has linked issue, CI passed, labels applied
- **Composite** — AND/OR of other rules for gate logic

These rule types are primitives, not conveyor features. A regulated team might use `artifact_exists` for compliance attestations. A solo developer might not use them at all. The rule types are flexible; the user decides what governance looks like.

## Presets

`diffguard init` should offer presets that generate starter configs for common governance models:

| Preset | Gates | Description |
|---|---|---|
| `--conveyor` | 6 | Full governed change conveyor (our reference implementation) |
| `--trunk` | 3 | Minimal for trunk-based development |
| `--regulated` | 8+ | Strict evidence chain for compliance |
| `--solo` | 1 | CI-only, no process gates |
| `--custom` | 0 | Empty config, user defines everything |

Each preset generates:
- A `diffguard.toml` with appropriate rules
- GitHub templates (issue, PR) if applicable
- CI workflow snippets if applicable

The conveyor preset is a reference implementation, not the canonical model.

## What diffguard is NOT

- **Not a workflow engine** — diffguard checks rules, it doesn't orchestrate agents
- **Not the conveyor** — the conveyor is one governance model that uses diffguard primitives
- **Not opinionated about process** — teams choose their own gates, rules, and review process
- **Not a code assistant** — it's a governance tool that produces evidence

## The CI integration story

diffguard outputs (receipts, verdicts, exit codes) are designed to be consumed by CI:

- Exit codes: 0=pass, 1=error, 2=fail, 3=warn — stable API for CI gates
- JSON receipts: structured evidence for downstream tooling
- SARIF output: integrates with GitHub Code Scanning
- GitHub Actions annotations: inline PR feedback

A team's CI pipeline is their governance enforcement layer. diffguard provides the checks that CI runs. The team decides what CI gates to require.

## The sensor.report.v1 envelope

The `sensor.report.v1` schema is the integration surface for the broader toolchain ecosystem. It carries:

- Tool metadata (what ran)
- Run metadata (when, how long, what capabilities)
- Verdict (overall pass/fail)
- Findings (specific violations)
- Artifacts (output files)

This envelope is generic enough to carry any governance evidence — code quality, process compliance, artifact existence, CI status. The conveyor's gate receipts are one use case. The envelope supports all of them.

## Relationship to the conveyor

The conveyor (our governed change methodology) uses diffguard as its code-quality primitive:

- The conveyor defines gates and gate requirements
- diffguard rules provide code-quality evidence for those gates
- diffguard artifact-existence rules provide process-evidence for those gates
- The conveyor composes the evidence into gate verdicts

But the conveyor is one customer of diffguard, not the only one. A team using trunk-based development with no formal gates still benefits from diffguard's code-quality rules. A team using a completely different governance model still benefits from the primitive layer.

**diffguard is the substrate. The conveyor is one shape built on top of it.**
