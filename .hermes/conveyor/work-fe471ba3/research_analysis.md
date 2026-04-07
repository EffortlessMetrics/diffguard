# Research Analysis: Add doctor subcommand to check environment prerequisites

## Issue Summary and Context

The diffguard CLI tool needs a new `diffguard doctor` subcommand that checks environment prerequisites before running checks. This is a common pattern in CLI tools (like `flutter doctor`, `brew doctor`) that helps users diagnose setup issues.

The doctor command should verify:
1. Git is available and has a compatible version
2. Configuration files are valid (can reuse existing validate logic)
3. Other prerequisites like required tools or environment variables

## Relevant Codebase Areas

### Main CLI Entry Point: `crates/diffguard/src/main.rs`
- **Commands enum** (line 56-86): Defines all subcommands. `Doctor` needs to be added here.
- **Command handler pattern** (line 591-623): Match on `cli.command` and call handler functions like `cmd_check()`, `cmd_rules()`, etc.
- **Git invocation** (lines 2620-2657): Functions `git_diff()` and `git_staged_diff()` show how git is called via `Command::new("git")`.
- **Existing validate command** (lines 680-857): Already validates config files - logic can be reused.

### Test Files
- `crates/diffguard/tests/cli_misc.rs` - Tests for various CLI commands (rules, explain, validate, etc.)
- `crates/diffguard/tests/cli_init.rs` - Tests for init command, shows test patterns

### Git Version Checking Pattern
Currently no explicit git version checking exists. The tool just calls `git diff` and fails if it's not available. For doctor, we should:
1. Run `git --version` to check availability
2. Parse version string to ensure minimum version
3. Report clear status

### Configuration Validation
The existing `validate` command (lines 680-857) already:
- Checks for duplicate rule IDs
- Validates regex patterns
- Validates path globs
- Compiles rules to catch errors
- Can output in text or JSON format

This logic can be reused or called from the doctor command.

## Dependencies and Constraints

### Dependencies
- `clap` - CLI parsing (already used)
- `std::process::Command` - For running git commands (already used)
- `anyhow` - Error handling (already used)
- `tracing` - Logging (already used)

### Constraints
1. **I/O boundary**: The diffguard CLI crate is the I/O boundary - all subprocess calls happen here
2. **Exit codes**: Should follow existing pattern (0=success, 1=error)
3. **Output format**: Should support both text and JSON output (like validate command)
4. **Minimal args**: Doctor typically needs few/no arguments

### No external dependencies needed
Everything required is already in the codebase. No new crate dependencies needed.

## Key Findings

1. **Clear integration point**: The `Commands` enum and match statement in `main.rs` provide a clear pattern to follow.
2. **Git availability check is straightforward**: Just need to run `git --version` and parse the output.
3. **Config validation can be reused**: The existing `cmd_validate()` function has most of the logic needed for config checking.
4. **Test patterns established**: CLI tests use `assert_cmd::Command` with `cargo_bin!("diffguard")` pattern.
5. **No version checking exists**: Currently the tool assumes git is available. Adding version checking would be new functionality.
6. **Doctor should be non-destructive**: Unlike check which may fail with exit code 2, doctor should report status and exit 0 if all checks pass, 1 if any fail.
7. **Consider JSON output option**: Like validate, doctor could support `--format json` for CI integration.
8. **Check categories to consider**:
   - Git availability and version
   - Config file validity (if present)
   - Required environment variables
   - Tool version compatibility
