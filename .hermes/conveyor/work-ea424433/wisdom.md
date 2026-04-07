# Wisdom: VS Code Extension LSP Rewrite
**Work ID**: work-ea424433
**Gate**: INTEGRATED
**Date**: 2026-04-06
**PR**: [#29](https://github.com/EffortlessMetrics/diffguard/pull/29)
**Full post-mortem**: `docs/postmortems/work-ea424433-vscode-lsp-rewrite.md`

## What Went Well

1. **Clean architecture pivot**: Rewrote from shell-exec stub (spawned `diffguard check --staged`, parsed JSON) to proper LSP client using `vscode-languageclient` v9. The new approach gives real-time diagnostics without manual command invocation.

2. **Simpler, more capable code**: New `extension.js` is 60 lines vs ~69 lines old code, but gains real-time diagnostics, config synchronization, and proper error handling for missing server binary.

3. **Good configuration surface**: Added 5 settings (`serverPath`, `configPath`, `noDefaultRules`, `maxFindings`, `forceLanguage`) and 3 commands (`explainRule`, `reloadConfig`, `showRuleUrl`). Clean separation of concerns.

4. **Full conveyor lifecycle**: Successfully completed all 6 gates (FRAMED → VERIFIED → DESIGNED → PROVEN → HARDENED → INTEGRATED) with ~15 agents.

5. **Plan review caught 5 real risks**: The VERIFIED gate's plan-reviewer identified missing LICENSE, undefined binary discovery, initOptions casing mismatch, missing deactivate disposal, and TypeScript deferral. These would have caused real bugs.

6. **Tests remain green**: 164+ workspace test assertions passing. VSIX package built successfully.

## Friction Points

1. **node_modules committed to git**: The commit included ~15,000 files because `node_modules/` was not excluded. Required 2 cleanup commits. This is a pipeline-level guard — the conveyor needs a pre-commit hook that rejects binary artifacts.

2. **Committed to main instead of branch**: Code-builder went to main instead of the feature branch. Branch protection blocked the cleanup push. PR #29 carries the fix but git history is messy.

3. **Artifact naming mismatch**: Agents produced `plan_review` and `vision_comment` but gates expected `plan_review_comment` and `vision_alignment_comment`. Templates must specify exact artifact type names.

4. **DESIGN.md mis-scoped**: The design doc is a project philosophy doc, not an implementation design for the VS Code extension. The task_list.md carried the execution load.

5. **No conveyor state persistence**: `.conveyor/` directory wasn't initialized. `gates.py friction` and automated gate advancement couldn't run.

## Key Learnings (see full skill: conveyor-run-postmortem)

- Templates must specify exact artifact type names the gate checker expects
- Branch routing must be in dispatch instructions, not agent discretion
- Pre-commit hygiene (no binary artifacts) is a pipeline concern
- Plan review is the highest-signal gate — invest in detailed review templates
- Structural tests beat runtime tests for extension artifacts
- Design doc scope should match work type (implementation, not philosophy)

## Recommendations for Next Time

1. **Git hygiene**: Ensure `.gitignore` exists before running `npm install`. Make this a pipeline check, not an agent instruction.
2. **Branch routing**: `dispatch.py` must specify the target branch explicitly.
3. **Artifact naming**: Templates must include exact artifact type names.
4. **Conveyor state**: Initialize `.conveyor/` before starting work.
5. **Design scoping**: adr-spec-agent should receive work-type-specific guidance for what the design doc should cover.
