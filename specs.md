# Specification: Add `includes` Directive Example to diffguard.toml.example

## Feature Description
Add a commented `includes` section to `diffguard.toml.example` that demonstrates the config composition feature. The `includes` directive allows users to include other TOML config files, with rules merged such that later definitions override earlier ones by rule ID.

## Acceptance Criteria

1. **Example demonstrates includes syntax**: The example file must contain a commented `includes` line showing an array of config file paths, e.g., `# includes = ["base-rules.toml", "team-overrides.toml"]`.

2. **Placement follows TOML conventions**: The `includes` section (as a commented block) must appear before the `[defaults]` section and any `[[rule]]` blocks, as TOML array-of-table headers (`[[rule]]`) cannot follow after a regular table definition (`[defaults]`).

3. **Merge semantics documented**: Comments must explain that rules are merged across included files with later definitions overriding earlier ones by rule ID.

4. **Circular include detection noted**: Comments must mention that circular includes are detected and that nested includes are supported up to 10 levels deep.

5. **TOML validity maintained**: All added content must be commented (no active config keys added), ensuring the file remains valid TOML even if a user uncomments the `includes` line without providing the referenced files.

6. **Style consistency**: The commented section must follow the existing comment block style in the file (e.g., `# =============================================================================` header, explanatory comments in the same format).

## Non-Goals
- No code changes to the Rust implementation
- No changes to the README (already documents this feature)
- No changes to the CHANGELOG
- No changes to any test files
- The example is illustrative only; it does not create functional behavior

## Dependencies
- The `includes` field already exists in `ConfigFile` struct (crates/diffguard-types/src/lib.rs:234)
- The LSP already handles loading and merging (crates/diffguard-lsp/src/config.rs:249-329)
- README already has a "Config Includes" section (lines 145-157) serving as the reference for correct syntax
