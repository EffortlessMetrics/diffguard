# Specs: `diffguard doctor` Subcommand

## Overview

The `diffguard doctor` subcommand performs environment prerequisite checks and reports pass/fail status for each. It enables users and CI pipelines to verify that diffguard can operate correctly before running analysis.

## Functional Requirements

### FR1: Git Availability Check

**Acceptance Criteria:**
- WHEN `diffguard doctor` is run, THEN the command attempts to execute `git --version`.
- WHEN git is found on PATH, THEN the output includes "git" with a PASS status and the reported version string.
- WHEN git is NOT found on PATH (command fails or is not executable), THEN the output includes "git" with a FAIL status and a message indicating git was not found.

### FR2: Git Repository Check

**Acceptance Criteria:**
- WHEN the current working directory is inside a git work tree, THEN the output includes "git-repo" with a PASS status.
- WHEN the current working directory is NOT inside a git repository, THEN the output includes "git-repo" with a FAIL status and a message indicating the working directory is not a git repository.
- The check runs `git rev-parse --is-inside-work-tree` (or equivalent).

### FR3: Configuration File Detection

**Acceptance Criteria:**
- WHEN `--config <path>` is provided and the file exists, THEN the command validates that file and reports its path.
- WHEN `--config <path>` is provided and the file does NOT exist, THEN the command reports a FAIL for "config" with a message indicating the file was not found.
- WHEN `--config` is omitted and `./diffguard.toml` exists, THEN the command validates it and reports its path.
- WHEN `--config` is omitted and `./diffguard.toml` does NOT exist, THEN the command reports a PASS with a note that no config file was found (defaults will be used).

### FR4: Configuration File Validation

**Acceptance Criteria:**
- WHEN a config file is found and is valid (parses correctly, no duplicate rule IDs, all regex patterns compile, all globs parse), THEN the output includes "config" with a PASS status.
- WHEN a config file is found but has errors (parse errors, duplicate IDs, invalid regex, etc.), THEN the output includes "config" with a FAIL status and a list of validation errors.
- The validation logic reuses the same checks as `diffguard validate` (lines 680-857 of main.rs).

### FR5: Output Format

**Acceptance Criteria:**
- Output is human-readable, with each check on its own line.
- Each line shows: check name, status indicator (PASS/FAIL), and optional detail.
- Example format:
  ```
  git            PASS  git version 2.43.0
  git-repo       PASS
  config         PASS  diffguard.toml (3 rules)
  ```
- OR on failure:
  ```
  git            PASS  git version 2.43.0
  git-repo       FAIL  not a git repository
  config         FAIL  2 error(s): Rule 'foo': invalid regex; Rule 'bar': duplicate ID
  ```

### FR6: Exit Code

**Acceptance Criteria:**
- WHEN all checks pass, THEN exit code is 0.
- WHEN any check fails, THEN exit code is 1.

### FR7: CLI Integration

**Acceptance Criteria:**
- `diffguard doctor --help` shows usage information.
- The `--config` flag is optional and works identically to `--config` on other subcommands.
- The `--verbose` and `--debug` global flags are supported (debug logging shows check details).

## Edge Cases

### EC1: Git Not Installed
- Command should not panic; it should handle `io::Error` from `Command::new("git")` gracefully and report FAIL.

### EC2: Git Installed But Broken
- If `git --version` returns a non-zero exit code, report FAIL with the stderr output.

### EC3: Config File Is a Symlink to a Non-Existent Target
- Report FAIL for "config" indicating the file could not be read.

### EC4: Config File Has Env Var References
- Environment variable expansion (via `expand_env_vars`) should be performed during validation, matching existing validate behavior. Undefined required vars should be reported as errors.

### EC5: Running Outside a Git Repo with No Config
- Both "git-repo" and "config" should report their respective statuses independently. The command should still complete (not bail early).

### EC6: Very Large Config File
- No special handling needed; validation should complete in reasonable time for typical config sizes (tens of rules).

## Performance Requirements

- The command should complete in under 2 seconds under normal conditions.
- Git subprocess calls (`git --version`, `git rev-parse`) should each have a reasonable timeout or fail fast if git is unresponsive. Standard OS process timeout behavior is acceptable.

## Non-Functional Requirements

### NFR1: Code Location
- All I/O logic stays in `crates/diffguard/src/main.rs` (the CLI crate boundary).
- A new `DoctorArgs` struct and `cmd_doctor` function follow the established pattern.

### NFR2: Testing
- Integration tests use `assert_cmd::Command` with `cargo_bin!("diffguard")` pattern.
- Test cases cover: git available, git not in a repo, config valid, config invalid, no config present.

### NFR3: Documentation
- The `doctor` subcommand appears in `diffguard doctor --help` output.
- The CLAUDE.md command table should be updated to include the new subcommand.

### NFR4: Backward Compatibility
- No existing commands or flags are modified.
- The new subcommand is purely additive.
