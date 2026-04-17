# Task List — work-0ec3b569

## Implementation Tasks

- [ ] Edit `diffguard.toml.example` — Insert commented includes section after line 34 (end of suppression directives) before `[defaults]`
- [ ] Verify TOML validity — Ensure the edited file remains valid TOML
- [ ] Verify changes — Confirm the includes section appears correctly and follows existing comment style

## Verification Tasks

- [ ] Run `cargo build --release` to ensure no compilation errors (even though only comments are added)
- [ ] Verify the example file is syntactically valid TOML using a TOML validator or by reviewing the structure

## Review Tasks

- [ ] Confirm the placement is before any `[[rule]]` blocks per TOML conventions
- [ ] Confirm the commented example uses README-consistent paths: `["base-rules.toml", "team-overrides.toml"]`
- [ ] Confirm merge semantics and circular include detection are documented in comments
