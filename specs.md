# Specs — work-bc5e399c

## Feature/Behavior Description

Add an `# Errors` section to the doc comment of `render_gitlab_quality_json` function in `crates/diffguard-core/src/gitlab_quality.rs:86` to satisfy the `clippy::missing_errors_doc` lint.

## Acceptance Criteria

1. **Doc comment updated** — The doc comment for `render_gitlab_quality_json` includes an `# Errors` section that documents `serde_json::Error` as the returned error type.

2. **Lint warning resolved** — Running `cargo clippy -p diffguard-core -- -W clippy::missing_errors_doc` produces no warnings for `gitlab_quality.rs:86`.

3. **No code logic changes** — Only the doc comment is modified; function signature, behavior, and tests remain unchanged.

4. **Consistent with crate style** — The `# Errors` section follows the pattern established in `check.rs:84-92` for documenting error returns.

## Non-Goals

- Fixing other functions with the same `clippy::missing_errors_doc` warning (sarif.rs:230, sensor.rs:134, sensor_api.rs:50)
- Adding `clippy::missing_errors_doc` to the default clippy configuration
- Any changes to code logic or test coverage

## Dependencies

- `serde_json::Error` — the only error type returned by the function
- `clippy::missing_errors_doc` lint — must be explicitly enabled to verify the fix
