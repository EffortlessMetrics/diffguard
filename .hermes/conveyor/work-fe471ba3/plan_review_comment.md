# Plan Review: Add `diffguard doctor` Subcommand

## Plan Strengths

1. **Follows established patterns**: The plan correctly identifies the `Commands` enum + `ValidateArgs` struct + handler function pattern used by existing commands.
2. **Dual format output**: Supporting both text and JSON (like `validate`) is the right call — text for humans, JSON for CI scripting.
3. **Non-destructive design**: Doctor should be read-only and informational, which aligns with the plan's intent.
4. **Reuse of config validation**: Acknowledging that `cmd_validate()` logic can be reused avoids duplicating regex/glob validation code.
5. **Clear task breakdown**: The 7-step implementation sequence is logical and incremental.

## Risks and Concerns

### R1: Exit Code Semantics Conflict (HIGH)

The plan says doctor should "exit 0 if all checks pass, 1 if any fail." But per the stable API contract in `agent-context.md`:
- `0` = pass
- `1` = tool error

If doctor returns `1` when git is missing, that conflates "environment diagnostic failure" with "tool error." The `check` command uses exit code 2 for policy failures. Doctor needs its own convention — consider always returning 0 (report-only mode) or documenting a new exit code specifically for doctor failures.

### R2: Config Validation Reuse is Not Straightforward (HIGH)

The plan says to "reuse `cmd_validate` logic" but `cmd_validate()` (lines 680-857 of `main.rs`) is a full command handler — it reads files, parses TOML, prints output to stdout, and returns an exit code. Calling it directly from doctor would:
- Print validation output mixed with doctor output
- Duplicate the stderr/stdout stream
- Make JSON output impossible to compose cleanly

**Risk**: The implementation will need to either (a) refactor validation into a pure function that returns a `ValidationResult` struct, or (b) duplicate the logic. The plan does not account for this refactor.

### R3: No Minimum Git Version Defined (MEDIUM)

The plan says "parse version string to ensure minimum version" but does not specify what minimum version is needed. diffguard calls `git diff <base>...<head>` with `--unified` and `--cached` flags — these are stable and have been available since git 1.6+. Without a defined minimum, the version check is either useless or arbitrarily restrictive.

### R4: Rust Toolchain Check is Misplaced (LOW)

The plan mentions "Rust toolchain version (if relevant)" but diffguard ships as a compiled binary. End users do not need Rust installed to run `diffguard doctor`. This check should be removed unless there is a specific use case (e.g., checking if the user can build from source).

### R5: "Diff Available" Check is Misleading (MEDIUM)

The plan's check #4 says "Verify `git diff` produces output (optional, informational)." A repo with no uncommitted changes is a perfectly valid state — labeling it as informational with a checkmark or warning could confuse users. This check should be scoped to "can git diff execute without error" rather than "does it produce output."

### R6: No Timeout on Subprocess Calls (MEDIUM)

The existing `git_diff()` and `git_staged_diff()` functions (lines 2620-2657) use `Command::new("git").output()` without a timeout. If `git --version` or `git rev-parse --is-inside-work-tree` hangs (e.g., due to filesystem issues, NFS mounts), the doctor command will hang indefinitely. Consider adding a timeout wrapper, especially since doctor is a diagnostic tool that should be resilient.

### R7: Testing Outside Git Repos (MEDIUM)

The plan does not address testing doctor in non-git directories. The `git_repo` check needs to handle this gracefully (report "not a git repo" as a warning, not a crash). The test in `cli_misc.rs` should include a case that runs doctor in a `TempDir` that is not a git repo.

### R8: main.rs Size Concern (LOW)

`main.rs` is already 5000+ lines. Adding doctor (args struct, handler, tests) will push it further. Consider extracting doctor into `src/doctor.rs` as a separate module. This is not blocking but worth considering for maintainability.

## Missing Considerations

1. **Environment variable checks**: The research mentions checking "required environment variables" but the plan does not include this. diffguard supports `${VAR}` expansion in configs — doctor could warn if referenced env vars are unset.

2. **Config file search path**: Doctor should check the same config search paths as `check` and `validate` (current dir `diffguard.toml`, `--config` flag). The plan does not mention how doctor discovers the config.

3. **`.diffguard.toml` overrides**: The tool supports per-directory overrides via `.diffguard.toml`. Should doctor also validate those files if present?

4. **Version output**: Should doctor report its own version alongside the checks? This helps with bug reports.

5. **JSON schema stability**: If doctor outputs JSON, should the schema be versioned (like `CHECK_SCHEMA_V1` for receipts)? The plan does not address schema stability for the JSON output.

## Recommended Changes

1. **Define exit code strategy**: Either always return 0 (report-only) or document a clear exit code convention for doctor. Do not reuse exit code 1.

2. **Refactor config validation**: Extract the core validation logic from `cmd_validate()` into a pure function (e.g., `validate_config(path) -> ValidationResult`) that returns errors/warnings without side effects. Both `cmd_validate` and `cmd_doctor` can call it.

3. **Remove Rust toolchain check**: It is not relevant for end users running the compiled binary.

4. **Replace "diff available" with "git works"**: Check that `git --version` succeeds rather than checking if diff produces output.

5. **Add subprocess timeout**: Wrap git subprocess calls in doctor with a reasonable timeout (e.g., 5 seconds) to prevent hangs.

6. **Add non-git-repo test case**: Ensure doctor handles being run outside a git repository without panicking.

7. **Extract to module**: Consider putting doctor implementation in `src/doctor.rs` rather than bloating `main.rs` further.
