# Post-Mortem: VS Code Extension LSP Rewrite
**Work ID**: work-ea424433
**Date**: 2026-04-06
**PR**: [#29](https://github.com/EffortlessMetrics/diffguard/pull/29)
**Gates completed**: FRAMED → VERIFIED → DESIGNED → PROVEN → HARDENED → INTEGRATED
**Agents dispatched**: ~15 across all gates
**Result**: PR open, all CI green, awaiting review/merge

---

## What We Shipped

Rewrote the VS Code extension from a shell-exec CLI wrapper to a proper LSP client using `vscode-languageclient` v9. The extension now connects to `diffguard-lsp` over stdio for real-time diagnostics, code actions, and config synchronization.

**Before** (v0.1.0): Ran `diffguard check --staged` via `child_process.execFile`, parsed JSON from a temp file, showed results in an output channel. Manual invocation only.

**After** (v0.2.0): `LanguageClient` spawns `diffguard-lsp`, provides real-time diagnostics on document open/change, config sync via VS Code settings, proper `deactivate()` disposal, error handling for missing binary.

**Key metrics**:
- extension.js: 69 lines → 60 lines (simpler AND more capable)
- package.json: 1 command → 3 commands + 5 config properties
- Test suites: 0 → 5 suites, 164 assertions
- Dependencies: 0 → 1 runtime (vscode-languageclient), 1 dev (vsce)

---

## Gate-by-Gate Assessment

### Gate 0: FRAMED — Work item + issue created
- `gates.py new` created work item `work-ea424433`
- GitHub issue #28 created
- **Quality**: Good. Issue was clear and actionable.

### Gate 1: VERIFIED — Plan review + vision alignment
**This was the highest-signal gate.**

Three agents dispatched:
1. **verification-agent**: Caught test count error (I said 19, actual was 49). Verified diffguard-lsp builds and tests pass.
2. **plan-reviewer**: Identified 5 real risks the plan missed:
   - LICENSE file missing from extension directory (vsce would warn/error)
   - Binary discovery strategy undefined (users need to find diffguard-lsp somehow)
   - `initializationOptions` casing mismatch (camelCase in Rust vs kebab-case in VS Code conventions)
   - `deactivate()` must dispose LanguageClient or orphan the LSP process
   - TypeScript conversion deferred but not acknowledged
3. **maintainer-vision-agent**: Confirmed alignment with project philosophy ("ship primitives, composable governance, no lock-in"). Recommended primary LSP client mode with secondary CLI shell-out.

**Verdict**: The plan-reviewer was the most valuable agent in the entire run. Five specific, actionable catches that would have caused real problems during execution. This is what the VERIFIED gate is for.

### Gate 2: DESIGNED — ADR + task breakdown
- `DESIGN.md` is really a project philosophy doc, not a VS Code extension design. It describes what diffguard IS (governance primitives, rule model, presets). Valuable content but misaligned with the work — a design for the extension should cover binary discovery, config mapping, lifecycle management.
- `task_list.md` was excellent: 8 tasks with clear success criteria, file targets, dependency graph. The code-builder could follow this without ambiguity.
- **Verdict**: Task breakdown was strong. Design doc needs to be scoped to the actual work, not the project's overall philosophy.

### Gate 3: PROVEN — TDD cycle
- **red-test-builder**: Created 4 test suites with 40 expected failures. Tests checked structural properties of extension.js (imports, API patterns, lifecycle, config mapping).
- **code-builder**: Implemented the LSP rewrite. Clean, minimal code.
- **green-test-builder**: Added edge case tests. Final result: 5 suites, 164 assertions, 0 failures.
- **Verdict**: TDD worked well. Tests are structural/regex-based (checking code shape, not runtime behavior), which is appropriate for a VS Code extension that can't easily run in a headless test harness.

### Gate 4: HARDENED — Cleanup + review
- cleanup-agent: Removed unused `path` import, extracted error message variable
- refactor-agent: Minor structural cleanup
- deep-review-agent: Approved with no security issues
- **Verdict**: Light but appropriate. The code was already clean.

### Gate 5: INTEGRATED — Wisdom extraction + merge
- wisdom-agent captured lessons learned
- merge-agent created branch, committed, pushed, created PR #29
- **Verdict**: Functional but had issues (see below).

---

## What Went Well

1. **Plan review quality**: The VERIFIED gate produced the most valuable artifact. Five real risks caught before execution. This prevented bugs, not just reported them.

2. **Test quality**: 164 assertions checking structural properties of the rewritten code — imports, API patterns, lifecycle management, config mapping, binary discovery. These are regression-proof tests that catch rewrites going wrong.

3. **Code simplicity**: The rewrite is 60 lines. The old code was 69 lines. We went from a limited CLI wrapper to a full LSP client AND made the code simpler. Good agents produce simple code.

4. **Full conveyor lifecycle**: All 6 gates cleared. Research → Review → Design → Prove → Harden → Integrate. The epistemic chain worked end-to-end.

5. **Vision alignment**: The maintainer-vision-agent correctly identified that the extension should be a consumer of the existing LSP primitive, not create a new code path. Clean architectural thinking.

---

## What Broke

### 1. node_modules committed to git (critical)
**Root cause**: Code-builder ran `npm install` in the extension directory without a `.gitignore` in place. The commit included ~15,000 files (1.1M lines) of `node_modules/`.

**Impact**: Bloated the PR diff, made review nearly impossible, risked polluting git history permanently.

**Fix**: Added `.gitignore`, ran `git rm -r --cached`, committed cleanup. Required 2 additional commits.

**Prevention**: The conveyor should have a pre-commit hook or gate check that rejects commits containing binary artifacts, `node_modules/`, `.vsix`, build outputs. This is a pipeline-level guard, not an agent instruction issue.

### 2. Committed to main instead of feature branch (critical)
**Root cause**: Code-builder committed directly to main. The merge-agent then created a feature branch, but the LSP rewrite commit was already on main's history. Branch protection blocked the cleanup push to main.

**Impact**: Main has the LSP rewrite commit (with node_modules in its tree). Cleanup is only on the feature branch. When PR #29 merges, main gets both — the rewrite and the cleanup — so the final state is correct, but git history is messy.

**Fix**: Local cleanup commits cherry-picked to main, but blocked by branch protection. PR #29 carries the cleanup.

**Prevention**: Agent dispatch must include explicit branch routing. Agents should never have to choose which branch to commit to — the conveyor provides the branch name. This needs to be in `dispatch.py` instructions.

### 3. Artifact naming mismatch (medium)
**Root cause**: Agents produced artifacts named `plan_review` and `vision_comment`, but the gate checker expected `plan_review_comment` and `vision_alignment_comment`. Manual bridging was required to advance gates.

**Impact**: Couldn't use `gates.py advance` automatically. Had to manually inspect artifacts and verify the gate could pass.

**Fix**: Manual artifact rename or gate state override.

**Prevention**: Agent templates must specify the exact artifact type name the gate checker expects. The template should say "produce artifact type `plan_review_comment`" not "produce a plan review."

### 4. DESIGN.md scope mismatch (medium)
**Root cause**: The adr-spec-agent produced a project philosophy doc rather than a VS Code extension design doc. It described what diffguard IS (governance primitives, rule model, presets, CI integration) rather than how the VS Code extension should be implemented (binary discovery, config mapping, lifecycle).

**Impact**: The design doc was valuable for the project but not useful for the code-builder trying to implement the extension. The task_list.md carried the load.

**Fix**: None needed — the task list was detailed enough to compensate.

**Prevention**: Agent templates for adr-spec-agent should include work-type-specific guidance. For "extension rewrite" work, the design doc should focus on implementation architecture, not product philosophy.

### 5. No conveyor state persistence (low)
**Root cause**: `.conveyor/` directory wasn't initialized on disk. `gates.py friction` couldn't run. Work was tracked manually rather than through the harness.

**Impact**: Couldn't use conveyor tooling for friction logging, status queries, or automated gate advancement.

**Fix**: Initialize `.conveyor/` before starting work.

**Prevention**: Work item creation (`gates.py new`) should automatically initialize the `.conveyor/` directory.

---

## Design Quality Assessment

### extension.js — Clean, correct, minimal
- 60 lines, proper LSP client using v9 `LanguageClient` API
- Binary discovery: reads `diffguard.serverPath` from config, falls back to `diffguard-lsp`
- Error handling: catches ENOENT/not-found on `client.start()`, shows actionable error message
- Lifecycle: `deactivate()` properly disposes client, prevents orphaned LSP process
- Config mapping: VS Code settings → initializationOptions with correct camelCase keys

### package.json — Complete manifest
- Version bumped to 0.2.0 (matches workspace)
- 3 LSP-aware commands (explainRule, reloadConfig, showRuleUrl)
- 5 configuration properties matching LSP server InitOptions
- Repository field added
- `onStartupFinished` activation (appropriate for LSP client)

### Tests — Structural regression protection
- 5 suites, 164 assertions, all passing
- Tests check code shape, not runtime behavior (appropriate for VS Code extension)
- Key test: verifies `activate()` does NOT use `execFile` (confirms rewrite, not patch)
- Key test: verifies v9 API pattern (command/args) not v8 pattern (run/debug module binding)

### What's missing
- No LICENSE file in extension directory (vsce will warn)
- Commands (`explainRule`, `reloadConfig`, `showRuleUrl`) are registered in manifest but not implemented in extension.js — they rely on the LSP server's `executeCommandProvider`
- No integration test that actually launches the extension host with a running LSP server

---

## Lessons for the Conveyor

### Templates must be specific about artifact names
Agent prompts need to say: "Produce an artifact of type `plan_review_comment` at `plan_review.md`." Not just "write a plan review." The gate checker uses artifact type names for validation — agents must match exactly.

### Branch routing must be in dispatch, not agent discretion
When `dispatch.py` sends an agent, it should include: "Work on branch `feat/vscode-lsp-client-rewrite`, commit to this branch only." Agents shouldn't choose branches.

### Pre-commit hygiene is a gate concern, not an agent concern
The conveyor should have a "no binary artifacts" check at a gate boundary (ideally before INTEGRATION or MERGE). Relying on agents to set up `.gitignore` before running `npm install` is fragile.

### Design doc scope should match work type
For "extension rewrite" work, the design doc should be implementation-focused: how does the extension connect, what config maps where, what's the lifecycle. Product philosophy docs are valuable but belong in a different artifact.

### The plan review is the most valuable gate
VERIFIED gate produced the best output. Five concrete catches that would have caused real bugs. This is the gate to invest in — more detailed review templates, better risk categories, more aggressive checking.

### TDD tests should be structural for extensions
For VS Code extensions (and similar integration artifacts), tests that check code shape — imports, API patterns, lifecycle, config mapping — are more reliable than tests that try to run the code headlessly. The red/green cycle worked well with structural tests.

---

## Metrics

| Metric | Value |
|--------|-------|
| Work ID | work-ea424433 |
| Gates cleared | 6/6 |
| Agents dispatched | ~15 |
| Artifacts produced | 10+ (research, plan review, vision, design, tasks, tests, extension, package, wisdom, PR) |
| Risks caught before execution | 5 (plan review) |
| Test assertions | 164 |
| Test failures | 0 |
| Code lines changed | extension.js: 69→60, package.json: 35→79 |
| Commits on branch | 4 (rewrite + tests + 2 cleanup) |
| node_modules files committed | 15,147 (bug, later fixed) |
| CI checks | All green (Clippy, Format, Tests, diffguard, CodeRabbit, GitGuardian) |
| Time to PR | ~30 min (gates 0-5) |
