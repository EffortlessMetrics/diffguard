# Vision Alignment Assessment: Doctor Subcommand

**Work Item**: work-fe471ba3 - Add doctor subcommand to check environment prerequisites

---

## Alignment Assessment: ALIGNED

The doctor subcommand aligns with diffguard's project direction for the following reasons:

1. **Developer Experience focus**: The project is a CLI tool designed for CI/CD integration. A doctor command for environment diagnostics directly supports the "integration tooling" and developer workflow goals outlined in Phase 6 and throughout the README.

2. **Consistent with existing CLI patterns**: The project already has `check`, `validate`, and `init` subcommands. A `doctor` command follows the same pattern and fills a natural gap - users need a quick way to diagnose setup issues before running checks.

3. **Supports adoption**: The README emphasizes quick-start workflows and multiple CI integration paths. A doctor command reduces friction for new users and helps troubleshoot CI pipeline failures (git availability, config validity, diff presence).

4. **Not conflicting with roadmap**: The roadmap's `validate` command (Phase 3, item 3.3) focuses on config file validation specifically. The doctor command is broader - it checks the full environment - and would naturally reuse validate logic rather than duplicating it.

---

## Priority Assessment: REASONABLE TIMING

- All 9 roadmap phases are marked complete. The project is at or past v2.0 scope.
- A doctor command is not explicitly on the roadmap, but it falls into the "developer experience" category that the project has consistently invested in.
- This is a low-effort, low-risk addition (the plan estimates small scope) that provides outsized user value for troubleshooting.
- **Caveat**: Since all roadmap phases are complete, this could be seen as scope creep. However, it is pragmatic DX tooling, not a new feature axis. The risk is low.

---

## Recommendations

1. **Reuse existing logic**: The plan correctly identifies reusing `cmd_validate` logic. Also consider reusing git-detection patterns already present in the codebase for diff sourcing.

2. **Keep it lightweight**: Avoid over-engineering. The four checks proposed (git available, git repo, config valid, diff available) are sufficient for an initial version. Do not expand scope to include toolchain checks (Rust version) unless there is clear user demand.

3. **JSON output is valuable**: The `--format json` option is important for CI automation - teams can pipe doctor output into monitoring or pre-check steps.

4. **Consider placement in roadmap**: If the roadmap is maintained going forward, this could be added as a Phase 3 follow-on item (developer experience tooling) or as a "Future Consideration" that has been promoted.

5. **Test integration**: The plan references `cli_misc.rs` for tests, which aligns with existing test organization. Ensure the doctor output is snapshot-tested for stability.
