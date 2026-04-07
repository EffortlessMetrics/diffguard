# Initial Plan: Add doctor subcommand

## Approach

Add a `Doctor` variant to the `Commands` enum in `crates/diffguard/src/main.rs`, following the same pattern as existing commands (check, validate, init, etc.).

### Implementation Steps

1. **Add `Doctor` to `Commands` enum** with optional `--format` flag (text/json)
2. **Implement `cmd_doctor()`** that runs prerequisite checks:
   - Git availability + version parsing
   - Config file validity (reuse existing validate logic)
   - Rust toolchain version (if relevant)
3. **Format output** — text mode for humans, JSON for CI
4. **Add tests** in `crates/diffguard/tests/cli_misc.rs`

### Command Checks (ordered)

1. **Git available**: Run `git --version`, parse output, report version
2. **Git repo exists**: Check if CWD is inside a git repo (reuse existing pattern)
3. **Config valid**: Load and validate diffguard.toml if present (reuse `cmd_validate` logic)
4. **Diff available**: Verify `git diff` produces output (optional, informational)

### Output Format (text)

```
diffguard doctor

  Git available     ✓  git version 2.43.0
  Git repo          ✓  /home/user/project
  Config file       ✓  diffguard.toml (3 rules, 0 errors)
  Diff available    ✓  42 changed lines in 3 files

All checks passed.
```

### Output Format (json)

```json
{
  "checks": [
    {"name": "git_available", "status": "pass", "detail": "git version 2.43.0"},
    {"name": "git_repo", "status": "pass", "detail": "/home/user/project"},
    {"name": "config_file", "status": "pass", "detail": "3 rules, 0 errors"},
    {"name": "diff_available", "status": "pass", "detail": "42 changed lines in 3 files"}
  ],
  "all_passed": true
}
```

## Risks

- Git version parsing is platform-dependent (Windows git may have different output format)
- Config validation may be slow for large configs (should be fine, existing validate is fast)
- No existing doctor pattern in the codebase to follow exactly (but validate command is close)

## Task Breakdown

1. Add `Doctor` variant + `DoctorArgs` struct to CLI definitions
2. Implement `cmd_doctor()` with git check
3. Add config validation integration
4. Add text output formatting
5. Add JSON output formatting
6. Add CLI tests
7. Update CHANGELOG.md
