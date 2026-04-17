# ADR-001: Add `includes` Directive Example to diffguard.toml.example

## Status
Proposed

## Context
GitHub issue #462 reports that `diffguard.toml.example` does not demonstrate the `includes` directive for config composition. The `includes = ["shared/rules.toml"]` directive is a documented first-class feature (CHANGELOG lines 111-114) that allows users to compose configs from multiple files, which is critical for monorepos and multi-project setups. The README already documents this feature (lines 145-157), but the example configuration file omits it entirely.

The `includes` field is a top-level field in `ConfigFile` struct (lib.rs:234), appearing before `[defaults]` and `[[rule]]` blocks. The LSP handles loading and merging of included configs recursively (config.rs lines 249-329).

## Decision
Add a commented `includes` section to `diffguard.toml.example` near the top of the file, after the existing "Suppression Directives" section but before the `[defaults]` block. The section will include:
- A comment header explaining config composition
- A commented `includes = ["base-rules.toml", "team-overrides.toml"]` line (consistent with README)
- Brief notes on merge semantics (later rules override earlier by rule ID)
- Note about circular include detection (nested includes up to 10 levels deep)

## Consequences

### Benefits
- Example file now demonstrates a documented major feature
- Users can discover config composition from the example without reading the README
- Reduces documentation drift between README and example file
- Enables monorepo adoption by showing how to share rules across projects

### Tradeoffs
- Minimal change with no code impact
- Follows existing commented-example pattern in the file
- TOML validity maintained since all content is commented

### Risks
- TOML validity: commented content must not break syntax if user uncomments (low risk, follows existing pattern)
- Placement: must appear before any `[[rule]]` blocks per TOML conventions (insertion at line 35 ensures this)

## Alternatives Considered

1. **Use `["shared/rules.toml"]` as the example path** — Rejected in favor of README-consistent `["base-rules.toml", "team-overrides.toml"]` which better demonstrates multi-file composition.

2. **Add explanation of merge semantics inline rather than in comments** — Rejected because the file uses a commented-examples pattern; inline comments provide discoverability without changing the file's existing style.

3. **Do nothing** — Rejected because the example file demonstrably lacks a documented feature, creating a poor user experience where users must go elsewhere to learn about config composition.

## Related Artifacts
- Initial Plan: `/home/hermes/.hermes/state/conveyor/work-0ec3b569/initial_plan.md`
- Verification: `/home/hermes/.hermes/state/conveyor/work-0ec3b569/findings/verification-agent-findings.md`
- Plan Review: `/home/hermes/.hermes/state/conveyor/work-0ec3b569/findings/plan-reviewer-findings.md`
- Vision Alignment: `/home/hermes/.hermes/state/conveyor/work-0ec3b569/findings/maintainer-vision-agent-findings.md`
