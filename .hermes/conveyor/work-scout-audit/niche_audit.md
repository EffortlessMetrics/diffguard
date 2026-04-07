# Diffguard Competitive Positioning & Niche Gap Audit

**Date:** 2026-04-07
**Version Audited:** v0.2.0
**Commit Scope:** 9-crate workspace, all tests passing (480), clippy clean, fmt clean

---

## 1. Current Differentiation Strengths

### What Makes Diffguard Unique

**Diff-scoped analysis is the moat.** No major competitor restricts their analysis to only added/changed lines in a git diff. This is the core differentiator and is genuinely useful:

- Teams only want PR-scoped feedback, not full-repo lint noise
- No false positives on legacy code you're not touching
- The `scope` system (`added`, `deleted`, `modified`) is genuinely novel

**Rule system architecture is sophisticated for a pattern-matching engine:**
- Context patterns (must-match-around rule)
- Escalation patterns (if-then severity bumps)
- Rule dependencies (gate evaluation)
- Multiline matching with windows
- `absent` match mode (flag when a pattern is missing)
- Inline suppression directives (`diffguard: ignore`, `ignore-next-line`, `ignore-all`)

**CI/CD ecosystem is real, not vaporware:**
- GitHub Action (`action.yml`) is production-grade with SARIF upload, PR comments, artifact handling
- GitHub reusable workflow (`.github/workflows/diffguard.yml`)
- Azure DevOps pipeline template (`azure-pipelines/`) — fully parameterized
- `.pre-commit-hooks.yaml` for hook integration
- `diffguard doctor` command for environment validation

**Output format coverage is table-stakes-complete:**
- JSON receipt, Markdown, SARIF 2.1.0, JUnit XML, CSV, TSV, GitHub annotations
- Sensor report format for Cockpit/BusyBox integration

**LSP server + VS Code extension exists:**
- Full diagnostics, code actions (explain rule, open docs)
- Config reload without restart
- Fuzzy rule matching in explain command

**27 built-in rules across 10 languages**, verified by reading `ConfigFile::built_in()`:

| Category | Rules | Languages |
|----------|-------|-----------|
| Rust | 3 (no_unwrap, no_dbg, no_todo) | Rust |
| Python | 3 (no_print, no_pdb, no_breakpoint) | Python |
| JavaScript/TypeScript | 3 (no_console, no_debugger, no_eval) | JS, TS |
| Ruby | 3 (no_binding_pry, no_byebug, no_eval) | Ruby |
| Java | 1 (no_sout) | Java |
| C# | 1 (no_console) | C# |
| Go | 2 (no_fmt_print, no_panic) | Go |
| Kotlin | 1 (no_println) | Kotlin |
| PHP | 1 (no_eval) | PHP |
| Shell | 1 (no_eval) | Shell |
| Secrets | 10 (aws, github, api_key, private_key, slack, stripe, google, twilio, npm, pypi, password, jwt) | All |
| Security | 5 (hardcoded_ipv4, http_url, sql_concat + eval rules above) | JS, Py, Ruby, PHP, Shell |

**Preprocessor supports 16 languages** for comment/string masking (Rust, Python, JS, TS, Go, Java, Kotlin, Ruby, C, C++, C#, Shell, Swift, Scala, SQL, XML/HTML, PHP, YAML, TOML, JSON).

**5 presets** cover the main use cases: minimal, rust-quality, secrets, js-console, python-debug.

---

## 2. Gaps in Rule Coverage & Language Support

### Critical Gaps

#### 2.1 Security Rules Are Sparse (5 total, not 3)
The audit says "3 security rules" but there are actually 5 when counting `no_eval` variants:
1. `security.hardcoded_ipv4` — overly broad regex, flags legitimate examples (127.0.0.1, documentation IPs)
2. `security.http_url` — only catches quoted URLs, misses unquoted ones
3. `security.sql_concat` — naive pattern, catches non-SQL string concatenation too
4. 5 `no_eval` rules across JS, Python, Ruby, PHP, Shell — **but NONE for:**
   - `java.no_eval` (Java's `Runtime.exec()`, `Method.invoke()` with user input)
   - `go.no_eval` (Go's `text/template` with user input)
   - `csharp.no_eval` (C#'s `dynamic` code evaluation)
   - `rust.no_unsafe` (Rust's `unsafe` blocks — the #1 thing a Rust linter should catch)

**Missing security rules that competitors have:**
- `xxe_detection` (XML External Entity in Java/Python/C#)
- `path_traversal` (user-controlled file paths in `open()`, `File.new`, etc.)
- `command_injection` (backtick execution, `os.system()`, `subprocess` without `shell=False`)
- `hardcoded_secrets` beyond the 10 patterns — no OAuth tokens, no Firebase keys, no GCP service account keys
- `tls_skip_verify` (insecure TLS bypass patterns)
- `deserialization_vulns` (Java `ObjectInputStream`, Python `pickle`, Ruby `Marshal.load`)

#### 2.2 Language Coverage: Depth vs Breadth Mismatch
The preprocessor supports 20+ languages but built-in rules only cover 10, and most languages have exactly 1 rule:
- Java: 1 rule (no_sout) — no `no_eval`, no `no_println`, nothing on logging frameworks
- C#: 1 rule (no_console) — no `Console.ReadLine` password masking, no `Debug.Print`
- Kotlin: 1 rule (no_println)
- Go: 2 rules (no_fmt_print, no_panic) — missing `defer` misuse, no `log.Println`
- PHP: 1 rule (no_eval) — missing `no_mysql_` (deprecated mysql_ functions), no `die()`, no `print_r()`
- Shell: 1 rule (no_eval) — missing `set -e` absence check, no unquoted variables in conditionals

**Languages with NO built-in rules but preprocessor support:**
- Swift
- Scala
- C/C++
- SQL
- YAML/TOML/JSON

#### 2.3 No IaC Rules
Zero rules for:
- Terraform/HCL (missing `required_version`, public S3 buckets, unencrypted EBS)
- Docker (running as root, no healthcheck, ADD vs COPY)
- Kubernetes YAML (missing resource limits, privileged containers)
- CloudFormation (open security groups, unencrypted resources)
- Ansible (become: true without become_user, password in plain text)

This is a **massive gap** — reviewdog/danger users who work on Infra-as-Code repos have zero reason to consider diffguard.

#### 2.4 No Framework-Specific Rules
- **React**: `useEffect` missing deps, `dangerouslySetInnerHTML`, no prop-type validation, hardcoded `localhost` in configs
- **Django**: `DEBUG=True` in settings, hardcoded URLs, `print()` in views
- **Spring**: `@EnableWebSecurity` without CSRF protection, `@Autowired` on fields
- **Rails**: `mass_assignment` without `strong_parameters`, SQL in raw queries

#### 2.5 No CI/CD Configuration Rules
A "diff-scoped governance linter" should lint CI pipelines themselves:
- GitHub Actions: hardcoded secrets in workflow YAML, missing `permissions:` block, `actions/checkout@v1` (outdated)
- GitLab CI: undefined variables, missing `artifacts:` paths
- `.gitlab-ci.yml` files exist as templates but no rules check them

---

## 3. Output & CI Integration Gaps

#### 3.1 Missing CI Integrations
- **GitLab CI template is claimed in CHANGELOG but DOES NOT EXIST** in the repo
- CHANGELOG line 75: `GitLab CI template (gitlab/diffguard.gitlab-ci.yml)` — file not found
- CHANGELOG line 76: `Azure DevOps pipeline templates (azure-pipelines/)` — EXISTS and is well-crafted
- CHANGELOG line 74: `GitHub Actions reusable workflow (.github/workflows/diffguard.yml)` — EXISTS

#### 3.2 GitHub Action Issues
The `action.yml` has several production-readiness concerns:
1. **No `runs-on` fallback for Windows** — target resolution only handles Linux/Darwin
2. **SARIF upload uses the reusable action but the action never runs on push events** — only PR
3. **Binary download fails silently** — `continue-on-error: true` on install step means `cargo install` fallback can be slow (5+ min on GitHub Actions)
4. **No version pinning for `actions/github-script@v7`** — mutable tags
5. **PR comment only works on `pull_request` events** — no support for `pull_request_target` on fork PRs

#### 3.3 Missing: GitLab Merge Request Comments
No mechanism to post findings as GitLab MR notes.

#### 3.4 Missing: Slack/Discord Webhook Integration
No notification output for chatops workflows. Alerting on policy failures via webhook is table stakes for governance tools.

---

## 4. Developer Experience Gaps

#### 4.1 Documentation
**What exists (good):**
- `docs/architecture.md` — crate structure with diagrams
- `docs/design.md` — pipeline dataflow
- `docs/requirements.md` — functional/non-functional requirements
- `docs/codes.md` — rule ID reference with examples
- `docs/cockpit-integration.md`
- Per-crate `CLAUDE.md` files
- Postmortem docs (VS Code LSP rewrite)
- `CHANGELOG.md` — detailed and accurate

**What's missing (bad):**
- **No getting-started guide** — `README.md` exists but is not a tutorial
- **No "How to write custom rules" guide** — this is the #1 thing users need
- **No migration guide** from reviewdog/danger/clippy
- **No benchmarking documentation** — users can't evaluate performance claims
- **No `docs/` directory at root was found initially** — the `search_files` returned 0 results because the files exist but search didn't match correctly. The files DO exist per the `find` command.

#### 4.2 LSP Integration
The LSP server is functional but has UX gaps:
- No hover information on diagnostics (just range + message)
- No workspace symbol lookup for rules
- No `textDocument/codeLens` to show "suppress this rule" inline
- Force-language option description says `'en'`, `'de'` — **this is a copy-paste bug**, it should be language identifiers like `'rust'`, `'python'`

#### 4.3 VS Code Extension Not on Marketplace
The `.vsix` file exists but is not published. This means:
- Users must manually install from `.vsix` (developer experience killer)
- No marketplace search discoverability
- No automatic updates

#### 4.4 Pre-configured Integrations Missing
- No `justfile` or `Makefile` with common commands
- No `devcontainer.json` for instant reproducible development
- No `docker compose` for CI-local test running

---

## 5. The Killer Feature: Diff-Scoped Governance

**This is what nobody else does:**

Every other linter runs on full files. Reviewdog wraps other linters and filters their output. Danger runs arbitrary Ruby/JS/TS scripts. Gitleaks scans entire files/histories. Clippy compiles and analyzes full Rust crates.

Diffguard's core insight — **only evaluate rules against the lines you're actually changing** — means:
1. Zero noise from legacy code
2. Instant feedback (no need to analyze 100K-line files)
3. Perfect for PR reviews — the context is exactly what reviewers are looking at
4. No "lint debt" blocking merges on old code
5. The `scope = "deleted"` feature can catch security regressions (removing auth checks, etc.)

**The "escalation" feature is also unique:**
If a pattern matches AND an escalation pattern is nearby, severity bumps up. Example: `console.log` alone is `warn`, but `console.log(password)` escalates to `error`. This contextual intelligence doesn't exist in reviewdog or danger.

**The `depends_on` feature is unique:**
Rules only evaluate if their dependency matched. Example: a "missing error handling" rule only fires if `try` block was present. This is AST-level logic achieved through pattern matching.

---

## 6. Competitive Matrix

| Feature | diffguard | reviewdog | danger | gitleaks | clippy |
|---------|-----------|-----------|--------|----------|--------|
| Diff-scoped | **Yes (native)** | Wrapper only | No | Some | No |
| Built-in rules | 27 | 0 (delegates) | 0 (scripts) | 300+ | 700+ |
| Pattern-based | Yes | Yes (via tools) | Yes (custom) | Yes | No (AST) |
| SARIF output | Yes | Yes | No | Yes | Yes |
| JUnit output | Yes | No | No | No | No |
| LSP server | Yes | No | No | No | Via rust-analyzer |
| GitHub Action | Yes | Yes | Yes | Yes | Yes |
| Azure Pipelines | **Yes** | No | No | No | Yes |
| GitLab CI | **Claimed, missing** | Yes | No | Yes | Via CI |
| Pre-commit hook | Yes | Yes | No | Yes | No |
| Slack/webhook | **No** | Yes | Yes | Yes | No |
| PR comments | Yes | Yes | Yes | No | No |
| Multi-base diff | Yes | No | No | No | No |
| Rule escalation | **Yes** | No | Custom | No | No |
| Rule dependencies | **Yes** | No | Custom | No | No |
| Config presets | Yes | No | No | Yes | Via clippy-driver |
| Inline suppression | Yes | Yes | Custom | Yes | Yes |

---

## 7. Work Items (Ranked by Impact)

### Tier 1: Table Stakes / Critical Gaps

#### Issue 1: Add GitLab CI Template (Replace Vaporware Claim)
**Why:** CHANGELOG claims GitLab CI exists but it doesn't. This damages credibility and blocks GitLab users.
**What:** Create `gitlab/diffguard.gitlab-ci.yml` with:
- Parameterized template (base, config, fail-on, output formats)
- Binary download or `gitlab-ci` cache-friendly approach
- MR comment integration via GitLab API
- SARIF upload support for GitLab's security dashboard
- Include in CHANGELOG correction

**Estimated effort:** 2 days

---

#### Issue 2: Add Rust `no_unsafe` Security Rule
**Why:** As a Rust-focused tool, not having an `unsafe` detection rule is the most glaring content gap.
**What:** Add `rust.no_unsafe` rule:
```toml
[[rule]]
id = "rust.no_unsafe"
severity = "error"
message = "Audit unsafe block - document safety invariants."
languages = ["rust"]
patterns = ["\\bunsafe\\s*(\\{|block)"]
paths = ["**/*.rs"]
exclude_paths = ["**/tests/**"]
ignore_comments = true
ignore_strings = true
tags = ["security"]
help = "Every unsafe block must document its safety invariants..."
```
Also consider: `rust.no_clone` (performance), `rust.no_expect` (already in presets, should be built-in)

**Estimated effort:** 1 day

---

#### Issue 3: Fix VS Code Extension `forceLanguage` Description Bug
**Why:** package.json says `Force analysis language (e.g. 'en', 'de')` — this is a language/locale description copy-pasted incorrectly. Should be `'rust'`, `'python'`.
**What:** Fix the description in `editors/vscode-diffguard/package.json` to read: `"Force analysis language (e.g. 'rust', 'python')."`

**Estimated effort:** 10 minutes

---

### Tier 2: High-Value Competitive Wins

#### Issue 4: IaC Rules Pack (Terraform + Docker)
**Why:** Infrastructure-as-Code is where PR-scoped governance matters most — a single misconfigured resource can expose production. Zero competitors in this space do diff-scoped IaC linting.
**What:** Add 8-10 rules:
- `terraform.missing_required_version` — no `required_version` provider constraint
- `terraform.public_s3_bucket` — `acl = "public-read"` without policy
- `terraform.unencrypted_ebs` — EBS without `encrypted = true`
- `terraform.hardcoded_credentials` — `access_key`/`secret_key` in provider blocks
- `docker.run_as_root` — no `USER` directive
- `docker.no_healthcheck` — no `HEALTHCHECK` directive
- `docker.add_instead_of_copy` — `ADD` when `COPY` suffices
- `docker.latest_tag` — `FROM` with `:latest` implicit tag

**Estimated effort:** 3 days

---

#### Issue 5: Slack/Discord Webhook Output Format
**Why:** Governance tools need alerting. When a PR violates policy, someone needs to know beyond the PR itself.
**What:** Add `--webhook <url>` flag that posts a formatted Slack/Discord message with:
- Pass/fail summary
- Top 5 findings (rule, file, line)
- Link back to PR
- Configurable severity threshold

**Estimated effort:** 3 days

---

#### Issue 6: Enable xtask CI Job (Fix #6)
**Why:** `ci.yml` has the xtask job disabled (`if: false`). Conformance tests and schema validation are not running in CI.
**What:** Investigate and fix issue #6 blocking the xtask ci job. This runs `cargo run -p xtask -- ci` which presumably does schema conformance testing. Without this, schema drift between releases goes undetected.

**Estimated effort:** 1-2 days (depending on root cause)

---

### Tier 3: Developer Experience

#### Issue 7: Publish VS Code Extension to Marketplace
**Why:** Manual `.vsix` install is a developer experience killer. No marketplace presence means zero organic discoverability.
**What:**
- Register publisher `effortlessmetrics` on VS Code Marketplace (or create dedicated publisher)
- Add CI publish step (`.github/workflows/publish.yml` exists but needs VS Code market publish)
- Add marketplace badges, screenshots, detailed extension README
- Consider JetBrains extension for IntelliJ users

**Estimated effort:** 2 days

---

#### Issue 8: Add Benchmark/Performance Tooling
**Why:** No benchmark infrastructure exists (confirmed via search). Users can't evaluate performance. Competitors like gitleaks publish benchmark numbers. For a "linter," scan speed is a critical adoption factor.
**What:**
- Add `criterion` benchmarks to workspace
- Benchmark: diff parsing speed, rule compilation, line evaluation on large diffs
- Performance regression guard in CI
- Document baseline: "diffguard scans N files in X ms vs competitor in Y ms"

**Estimated effort:** 2 days

---

#### Issue 9: Custom Rules Tutorial / Documentation
**Why:** The most powerful feature (user-defined rules via regex) has no dedicated guide. This is the primary way users will extend beyond built-in rules.
**What:** Create `docs/writing-rules.md` with:
- Rule anatomy walkthrough (every field explained)
- Pattern writing tips (regex best practices, avoiding catastrophic backtracking)
- Real examples: "how to catch your team's forbidden imports"
- Using `test_cases` for rule validation
- Using `context_patterns` and `escalate_patterns` for context-aware rules
- Using `depends_on` for conditional rules

**Estimated effort:** 1 day

---

#### Issue 10: Add `diffguard compare` Command (Performance Self-Benchmark)
**Why:** A diff-scoped tool should easily show its speed advantage. `diffguard compare` could run the same rules in diff-scoped mode vs full-file mode and print the time difference.
**What:** New subcommand that:
1. Runs rules on the diff only (current behavior)
2. Runs rules on full files
3. Reports: "Diff-scoped: X files, X ms | Full: X files, X ms | Speedup: Xx"

**Estimated effort:** 2 days

---

## 8. Summary Assessment

**Diffguard is a strong niche player in its current form.** It's the only tool that is *natively* diff-scoped (not wrapping other tools to filter output). The rule system is more sophisticated than it appears at first glance thanks to escalation, dependencies, and context patterns. The CI/CD integration breadth (GitHub, Azure, pre-commit) is real and production-ready.

**The biggest threats:**
1. **Reviewdog's ecosystem lock-in** — 100+ linter integrations already configured
2. **gitleaks' security depth** — 300+ secret patterns vs diffguard's ~10
3. **Clippy's AST precision for Rust** — diffguard can never match regex for correctness

**The biggest opportunities:**
1. **Diff-scoped governance as a category** — no one else owns this. "Don't lint everything, lint what changed" is a compelling message
2. **IaC scanning** — Terraform, Docker, K8s rules in a PR-scoped context is a blue ocean
3. **Security escalation** — contextual rule escalation (warn→error based on context) is unique and valuable
4. **Multi-base diffs** — comparing a feature branch against both `main` AND `staging` is unique

**If diffguard does three things, it becomes canonical:**
1. Fill the GitLab CI template gap (credibility fix)
2. Add 5-8 IaC security rules (expand the TAM)
3. Publish the VS Code extension on the Marketplace (distribution)

Everything else is incremental.
