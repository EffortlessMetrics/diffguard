# Coverage

Codecov coverage is Rust execution-surface evidence.

## What it answers

> Did tests execute this Rust surface?

## What it does not answer

- whether diff parsing is correct,
- whether rule evaluation is correct,
- whether inline suppressions are correct,
- whether Markdown, SARIF, JUnit, Checkstyle, GitLab, CSV, TSV, or sensor rendering is complete,
- whether LSP diagnostics and code actions are correct,
- whether false-positive baselines or trend history are correct,
- whether mutation adequacy is strong,
- whether fuzzing is sufficient,
- whether release readiness is proven.

Those are separate proof lanes:
- **Test**: unit, integration, golden, mutation, fuzz
- **Conformance**: parser correctness, rule semantics, rendering completeness
- **Golden**: expected input/output pairs for parser, rules, and renderers
- **Mutation**: algorithmic adequacy under perturbation
- **Fuzz**: robustness under random input

## Execution surface

The Coverage workflow runs on:
- push to `main`,
- `workflow_dispatch` (manual trigger),
- PRs labeled `coverage`, `full-ci`, or `ci:full`.

## Configuration

Coverage is configured in `codecov.yml` with:
- Project coverage target: auto with 5% threshold (informational only)
- Patch coverage target: 70% with 20% threshold (informational only)
- Codecov comments disabled
- Codecov GitHub check annotations disabled

## Artifacts

Durable receipts are produced:
- `coverage.json` — LLVM coverage report (JSON)
- `coverage.txt` — LLVM coverage report (text)
- `lcov.info` — LCOV coverage data
- `target/coverage/coverage-receipt.json` — claim boundary receipt
- GitHub Actions coverage artifact (stored for 14 days)
- Codecov dashboard (if CODECOV_TOKEN is set)

## Tool

Coverage is collected by `cargo-llvm-cov`, which instruments tests with LLVM profiling and generates LCOV reports.
