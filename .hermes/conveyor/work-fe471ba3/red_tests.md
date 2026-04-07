# Red Tests Summary: diffguard doctor

## Created Files

- **Test file**: `/home/hermes/repos/diffguard/crates/diffguard/tests/doctor.rs`

## Test Results

All 16 tests COMPILE and FAIL as expected.

```
running 16 tests
test doctor_subcommand_exists ... FAILED
test doctor_shows_git_pass_with_version ... FAILED
test doctor_reports_git_repo_pass_in_repo ... FAILED
test doctor_reports_git_repo_fail_outside_repo ... FAILED
test doctor_with_valid_config_passes ... FAILED
test doctor_with_invalid_config_fails ... FAILED
test doctor_no_config_passes_with_defaults_note ... FAILED
test doctor_config_flag_missing_file_fails ... FAILED
test doctor_config_flag_valid_file_passes ... FAILED
test doctor_output_has_human_readable_format ... FAILED
test doctor_exit_code_zero_when_all_pass ... FAILED
test doctor_exit_code_one_when_any_check_fails ... FAILED
test doctor_help_shows_usage ... FAILED
test doctor_config_flag_shown_in_help ... FAILED
test doctor_handles_duplicate_rule_ids ... FAILED
test doctor_all_checks_run_even_if_one_fails ... FAILED

test result: FAILED. 0 passed; 16 failed; 0 ignored; 0 measured; 0 filtered out
```

## Failure Reason

All tests fail because the `doctor` subcommand does not exist yet. Clap returns exit code 2 ("unrecognized subcommand"). This is correct behavior for red tests.

## Test Coverage

| Spec Requirement | Tests |
|-----------------|-------|
| FR1: Git availability | `doctor_shows_git_pass_with_version` |
| FR2: Git repo check | `doctor_reports_git_repo_pass_in_repo`, `doctor_reports_git_repo_fail_outside_repo` |
| FR3/FR4: Config detection & validation | `doctor_with_valid_config_passes`, `doctor_with_invalid_config_fails`, `doctor_no_config_passes_with_defaults_note`, `doctor_config_flag_missing_file_fails`, `doctor_config_flag_valid_file_passes` |
| FR5: Output format | `doctor_output_has_human_readable_format` |
| FR6: Exit codes | `doctor_exit_code_zero_when_all_pass`, `doctor_exit_code_one_when_any_check_fails` |
| FR7: CLI integration | `doctor_help_shows_usage`, `doctor_config_flag_shown_in_help` |
| Edge cases | `doctor_handles_duplicate_rule_ids`, `doctor_all_checks_run_even_if_one_fails` |
| Basic smoke test | `doctor_subcommand_exists` |

## Patterns Used

- `assert_cmd::Command` with `cargo::cargo_bin!("diffguard")` (matches existing tests)
- `tempfile::TempDir` for isolated test directories
- `run_git()` helper for git repo setup (matches `cli_check.rs` pattern)
- `run_doctor()` helper for capturing output and exit code
- No external `predicates` crate (uses standard `assert!` macros instead)
