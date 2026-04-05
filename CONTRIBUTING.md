# Contributing to diffguard

## The short version

1. Open an issue (scope the problem)
2. Create a branch (`feat/<number>-<slug>`)
3. Open a PR (link the issue, pass CI)
4. Get review, merge

## How changes flow

Every change follows the same path:

```
Issue → Branch → PR → CI → Review → Merge
```

The issue defines **what** and **why**. The PR defines **how**. CI proves it works. Review confirms it's right.

### Issue

Start with an issue. The templates will walk you through scoping the problem. The key sections:

- **Problem** — what's wrong or missing
- **Scope** — what's in and what's out
- **Acceptance criteria** — how we know it's done

An issue without scope is a conversation, not a task.

### Branch

Name branches: `<type>/<issue-number>-<slug>`

- `feat/11-fix-include-recursion`
- `fix/12-defaults-merge`
- `chore/update-deps`

This links the branch to the issue automatically.

### PR

Open a PR that:

1. Links the issue (`Closes #N` in the PR body)
2. Describes the approach
3. Passes CI (format, clippy, tests)
4. Gets at least one review approval

The PR template has a checklist. Use it.

### CI

PRs must pass:

- `cargo fmt --check` — formatting
- `cargo clippy` — lint (warnings are errors)
- `cargo test --workspace` — all tests
- Issue linkage check — PR body references an issue

Branch protection enforces this on `main`.

## Architecture

See [AGENTS.md](AGENTS.md) for the full architecture guide. Key constraints:

- Domain crates (`diffguard-diff`, `diffguard-domain`, `diffguard-types`) must be I/O-free
- Exit codes are stable API (0=pass, 1=error, 2=fail, 3=warn)
- Receipt schemas are versioned — avoid breaking changes

## Development

```bash
cargo build                                          # Build
cargo test --workspace                               # All tests
cargo fmt --check                                    # Format check
cargo clippy --workspace --all-targets -- -D warnings # Lint
cargo run -p xtask -- ci                             # Full CI suite (when working)
```

## Why this structure

The flow is deliberately simple:

- Issues prevent unscoped work
- Branch naming prevents orphan branches
- PR linkage prevents untracked changes
- CI prevents broken merges

These aren't bureaucracy. They're the minimum viable proof that a change is safe to land.
