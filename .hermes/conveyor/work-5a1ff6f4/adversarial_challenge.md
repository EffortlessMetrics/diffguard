# Adversarial Design Challenge: Baseline/Grandfather Mode

## Current Approach Summary

The proposed solution adds a `--baseline` flag to the `check` command that:
1. Accepts path to a previous receipt JSON file
2. Compares findings against the baseline receipt using fingerprint matching
3. Annotates findings as "baseline" (pre-existing) vs "new"
4. Returns exit code 0 if only pre-existing violations found, exit 2 if new violations introduced
5. Provides `--report-mode=new-only` to filter output

**Key design decisions in current approach:**
- Baseline is a full receipt JSON from a prior run
- Fingerprint matching uses SHA-256 of `rule_id:path:line:match_text`
- Comparison happens as post-processing in CLI layer (core engine unchanged)
- Output shows ALL findings with classification annotation

---

## Alternative Approach 1: "Negative Baseline" (Acceptance Workflow)

**Instead of providing a historical receipt, use a two-step acceptance workflow:**

1. **Phase 1 - Discovery**: Run `diffguard check` normally. Output shows all violations but exits 0.
2. **Phase 2 - Acceptance**: Run `diffguard accept --current` to mark current violations as the baseline. This writes a `.diffguard/accepted.json` file.

**Why this might be BETTER:**
- **No historical archaeology**: Users don't need to find an old receipt file. They run, see what's failing, and explicitly accept the current state as baseline.
- **Closer to git semantics**: `git add` followed by `git commit` - you stage current state, that's the baseline. More intuitive than "here's a JSON from 3 months ago."
- **Reduces error surface**: No risk of loading the wrong receipt file or mismatched scope.
- **Audit trail implicit**: Every acceptance is a deliberate action, not passive comparison.

**What current approach sacrifices:**
- The ability to restore baseline from any point in time (but do enterprises actually need this, or just need to start from current state?)

---

## Alternative Approach 2: "Delta Scope Control" (Per-Rule/Directory Baseline)

**Allow baseline to be scoped to specific rules or directories, not globally applied:**

- `--baseline=path/to/receipt.json` remains global
- NEW: `--baseline-rule=sensitive-*` only applies baseline to rules matching pattern
- NEW: `--baseline-path=src/internal/**` only applies baseline to paths matching pattern

**Why this might be BETTER:**
- **Granular adoption**: Enterprise might want to grandfather `style-*` rules everywhere but enforce `security-*` rules strictly from day one.
- **Aligned with how teams actually adopt**: You don't adopt all rules at once. You adopt categories incrementally.
- **Future-proof**: As you enable new rules, you can baseline them individually without losing baseline on existing rules.

**What current approach sacrifices:**
- Simplicity (single flag vs pattern matching)
- But the loss is worth it if it removes the #1 complaint: "I want to baseline rule X but not rule Y"

---

## Alternative Approach 3: "Baseline as Infrastructure" (Push-based State)

**Instead of file-based baseline, maintain a lightweight baseline service:**

1. `diffguard check --baseline-push` - Push current findings to a central baseline store
2. `diffguard check --baseline-pull` - Pull baseline from central store (default)

**Why this might be BETTER:**
- **Single source of truth**: No managing receipt files across repos, branches, machines. Baseline is version-controlled alongside code but stored centrally.
- **Team-level baseline**: An enterprise can have one baseline per repo, shared across all engineers. Not per-developer receipt files.
- **History and rollback**: You can query "what was the baseline on main at commit abc123?"
- **CI/CD natural fit**: CI pulls baseline, doesn't need to receive a file artifact.

**What current approach sacrifices:**
- Offline operation (requires baseline service)
- Simplicity (adds infrastructure dependency)
- But for enterprise adoption, infrastructure is often already there.

---

## Assessment

**Recommendation: MODIFY current approach**

The current approach is fundamentally sound but has a critical gap: **it treats baseline as a single global state when enterprises actually need incremental adoption**.

### Strongest Argument Against Current Approach

The `--baseline` flag is all-or-nothing. If an enterprise has 10,000 pre-existing violations across 50 rules, they must baseline ALL of them or NONE. They cannot:
- Baseline rules 1-20 (which they accept)
- Immediately start enforcing rules 21-50 (new violations fail)

This is the real-world adoption pattern: you grandfather existing violations for rules you're still configuring, but you enforce strict rules you've already validated.

### Specific Risks of Current Approach

1. **All-or-nothing adoption creates adoption paralysis**: If you can't baseline partially, teams won't adopt incrementally - they'll either skip baseline entirely or delay adoption indefinitely.

2. **Receipt file management at scale**: Enterprise with 50 developers, 10 repos, multiple branches = chaos of receipt files. No clear story for "which receipt is the baseline for main?"

3. **Fingerprint instability across scope changes**: The current design acknowledges "what if baseline diff scope differs from current?" but answers it with "compare findings, not scope." This ignores that a finding's fingerprint includes `match_text` - if code changes around a violation, the fingerprint changes even if the violation is semantically the same.

4. **No rollback mechanism**: If you accept a baseline that includes a security vulnerability you meant to fix, how do you un-baseline just that one finding? Current approach offers no selective removal.

### Modifications Recommended

1. **Add `--baseline-include-rule` and `--baseline-exclude-rule` patterns** to allow partial baseline adoption
2. **Design a "baseline diff" concept** so you can see what changed between baseline and current
3. **Consider acceptance workflow** as complementary to receipt-based baseline (not replacement)

---

## Files Produced

This adversarial challenge document produced by `adversarial-design-agent` for work-5a1ff6f4.

**Verdict: MODIFY current approach** - The core post-processing pattern is correct, but the all-or-nothing baseline scope is inadequate for enterprise adoption. Add rule-pattern scoping to allow incremental adoption.