# Task List: diffguard doctor Subcommand

## Task 1: Add DoctorArgs struct and Doctor variant to Commands enum

**Description:**
Add the `Doctor` variant to the `Commands` enum in `crates/diffguard/src/main.rs`. Create a `DoctorArgs` struct with an optional `--config` field (following the pattern of `ValidateArgs`). Wire the new variant into the `main()` match arm, calling `cmd_doctor(args)`.

**Acceptance Criteria:**
- `DoctorArgs` struct exists with `config: Option<PathBuf>` field and `#[arg(long)]` attribute
- `Commands` enum has a `Doctor(DoctorArgs)` variant with doc comment
- `main()` match arm dispatches to `cmd_doctor(args)`
- `diffguard doctor --help` shows usage information
- `cargo check -p diffguard` passes with no errors

**Dependencies:** None

---

## Task 2: Implement git availability check (FR1)

**Description:**
Implement the git availability check in `cmd_doctor()`. Execute `git --version` via `Command::new("git").arg("--version")`. Handle the case where git is not found (catch `io::Error`) gracefully. Collect the result as a `DoctorCheck` struct with name, status (Pass/Fail), and detail message.

**Acceptance Criteria:**
- When git is on PATH: reports PASS with version string (e.g., "git version 2.43.0")
- When git is not on PATH: reports FAIL with "git not found" message
- No panic occurs when git is missing; `io::Error` is handled gracefully
- Output follows the format: `git            PASS  git version 2.43.0`

**Dependencies:** Task 1

---

## Task 3: Implement git repository check (FR2)

**Description:**
Implement the git repository check in `cmd_doctor()`. Execute `git rev-parse --is-inside-work-tree` and check the output. Report PASS if inside a git work tree, FAIL otherwise. Handle errors gracefully (e.g., git exists but command fails because not in a repo).

**Acceptance Criteria:**
- When inside a git repo: reports PASS for "git-repo"
- When not inside a git repo: reports FAIL for "git-repo" with "not a git repository" message
- Handles case where git is available but command fails (non-zero exit)
- Output follows the format: `git-repo       PASS` or `git-repo       FAIL  not a git repository`

**Dependencies:** Task 2 (shares the git availability result to skip repo check if git is missing)

---

## Task 4: Implement config file detection and validation (FR3, FR4)

**Description:**
Implement config file detection and validation in `cmd_doctor()`. Reuse the validation logic from `cmd_validate` (lines ~680-857 of main.rs). Handle three cases: explicit `--config` path, auto-detected `./diffguard.toml`, and no config file present. When a config file exists, run full validation (parse, regex compilation, duplicate ID detection, glob parsing). Collect validation errors as detail messages.

**Acceptance Criteria:**
- `--config <path>` provided and file exists: validates file, reports PASS with path and rule count
- `--config <path>` provided and file missing: reports FAIL with "file not found" message
- No `--config` and `./diffguard.toml` exists: validates file, reports PASS with path and rule count
- No `--config` and no `./diffguard.toml`: reports PASS with "no config file found (using defaults)" note
- Invalid config (bad regex, duplicate IDs): reports FAIL with list of validation errors
- Env var expansion is performed during validation (matching existing validate behavior)

**Dependencies:** Task 1

---

## Task 5: Implement human-readable output and exit code logic (FR5, FR6)

**Description:**
Design and implement the output formatting for `cmd_doctor()`. Print each check on its own line with aligned columns: check name (left-padded), PASS/FAIL indicator, and optional detail. After all checks, return exit code 0 if all pass, 1 if any fail. Ensure consistent formatting that matches the examples in the specs.

**Acceptance Criteria:**
- Output format matches spec examples:
  ```
  git            PASS  git version 2.43.0
  git-repo       PASS
  config         PASS  diffguard.toml (3 rules)
  ```
- Failure output shows FAIL with error details:
  ```
  git-repo       FAIL  not a git repository
  config         FAIL  2 error(s): Rule 'foo': invalid regex; Rule 'bar': duplicate ID
  ```
- Exit code is 0 when ALL checks pass
- Exit code is 1 when ANY check fails
- All checks run independently (early check failure does not skip later checks)

**Dependencies:** Task 2, Task 3, Task 4

---

## Task 6: Add integration tests (NFR2)

**Description:**
Add integration tests for `diffguard doctor` using the `assert_cmd` pattern. Create test cases covering the key scenarios: git available, not in a git repo, valid config, invalid config, no config present, and `--config` with missing file.

**Acceptance Criteria:**
- Test: `doctor` in a git repo with no config -> all PASS, exit 0
- Test: `doctor` in a non-git directory -> git-repo FAIL, exit 1
- Test: `doctor` with valid diffguard.toml -> config PASS, exit 0
- Test: `doctor` with invalid diffguard.toml (bad regex) -> config FAIL, exit 1
- Test: `doctor --config nonexistent.toml` -> config FAIL, exit 1
- Tests use `assert_cmd::Command` with `cargo_bin!("diffguard")` pattern
- Tests use `tempfile::TempDir` for isolated config files
- `cargo test -p diffguard` passes

**Dependencies:** Task 5

---

## Task 7: Update documentation (NFR3)

**Description:**
Update the CLAUDE.md command table in `crates/diffguard/CLAUDE.md` to include the new `doctor` subcommand. Ensure the `--help` output is complete and clear.

**Acceptance Criteria:**
- CLAUDE.md command table includes `doctor` row with description "Check environment prerequisites"
- `diffguard doctor --help` shows clear usage and description
- No existing documentation is broken

**Dependencies:** Task 1
