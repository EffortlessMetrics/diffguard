# Diffguard Roadmap

This document outlines the development roadmap for diffguard, organized into phases. Items are prioritized based on user value, complexity, and alignment with project goals.

## Legend

- **Status**: `planned` | `in-progress` | `complete`
- **Priority**: `P0` (critical) | `P1` (high) | `P2` (medium) | `P3` (low)
- **Effort**: `S` (small, <1 day) | `M` (medium, 1-3 days) | `L` (large, 3-7 days) | `XL` (extra large, >1 week)

---

## Phase 1: Test Coverage Completion

Complete the remaining tasks from the comprehensive-test-coverage spec to ensure production readiness.

| Item | Description | Priority | Effort | Status |
|------|-------------|----------|--------|--------|
| 1.1 | DiffStats accuracy property test | P1 | S | planned |
| 1.2 | Empty diff and context-only diff edge case tests | P1 | S | planned |
| 1.3 | Rule compilation success property test | P1 | S | planned |
| 1.4 | Rule applicability filtering property test | P1 | S | planned |
| 1.5 | Preprocessor line length preservation property test | P1 | S | planned |
| 1.6 | Evaluation count accuracy property test | P1 | S | planned |
| 1.7 | Error condition tests (malformed config, bad patterns) | P1 | M | planned |
| 1.8 | Exit code property tests for all fail_on combinations | P1 | S | planned |
| 1.9 | Markdown rendering property tests | P1 | S | planned |
| 1.10 | GitHub annotation format property tests | P1 | S | planned |
| 1.11 | Config parse fuzz target | P1 | M | planned |
| 1.12 | evaluate_lines fuzz target | P1 | M | planned |
| 1.13 | BDD integration tests for CLI workflows | P1 | M | planned |
| 1.14 | Snapshot tests for JSON receipt output | P2 | S | planned |
| 1.15 | Snapshot tests for GitHub annotation format | P2 | S | planned |
| 1.16 | Mutation testing analysis across all crates | P2 | L | planned |

---

## Phase 2: Output Format Expansion

Add industry-standard output formats for broader CI/CD integration.

| Item | Description | Priority | Effort | Status |
|------|-------------|----------|--------|--------|
| 2.1 | **SARIF output format** - Industry standard for static analysis results | P1 | L | planned |
| 2.2 | JUnit XML output - Common CI format for test results | P2 | M | planned |
| 2.3 | CSV/TSV export - Tabular format for spreadsheet analysis | P3 | S | planned |
| 2.4 | SARIF upload GitHub Action integration | P2 | M | planned |

**SARIF benefits:**
- Native GitHub Security tab integration
- Unified vulnerability dashboard
- Rich code flow and location tracking
- Industry standard (OASIS/NIST)

---

## Phase 3: Rule System Enhancements

Improve rule flexibility and user experience.

| Item | Description | Priority | Effort | Status |
|------|-------------|----------|--------|--------|
| 3.1 | **Inline suppression comments** (`# diffguard:disable=rule.id`) | P1 | M | planned |
| 3.2 | Rule tagging/grouping for selective enable/disable | P2 | M | planned |
| 3.3 | Config file validation CLI command (`diffguard validate`) | P2 | S | planned |
| 3.4 | Rule testing framework (example inputs with expected matches) | P2 | L | planned |
| 3.5 | Environment variable expansion in config (`${VAR}`) | P3 | S | planned |
| 3.6 | Config inheritance/composition (`includes = ["base.toml"]`) | P3 | M | planned |
| 3.7 | Per-directory rule overrides (.diffguard.toml lookup) | P3 | M | planned |

**Inline suppression format:**
```rust
// diffguard:disable=rust.no_unwrap
let value = map.get("key").unwrap(); // Intentional - key guaranteed present
// diffguard:enable=rust.no_unwrap
```

---

## Phase 4: Language Support Expansion

Extend preprocessing support to additional languages.

| Item | Description | Priority | Effort | Status |
|------|-------------|----------|--------|--------|
| 4.1 | **Shell/Bash** preprocessing (# comments) | P1 | S | planned |
| 4.2 | **PHP** preprocessing (// and # comments, various strings) | P2 | M | planned |
| 4.3 | **Swift** preprocessing (// and /* */ comments) | P2 | S | planned |
| 4.4 | **Scala** preprocessing (// and /* */ nested comments) | P3 | S | planned |
| 4.5 | SQL preprocessing (-- comments, /* */ blocks) | P3 | M | planned |
| 4.6 | XML/HTML comment preprocessing (<!-- -->) | P3 | M | planned |
| 4.7 | YAML/TOML/JSON comment handling | P3 | M | planned |
| 4.8 | Language override flag (`--language=rust` for non-standard extensions) | P2 | S | planned |

---

## Phase 5: Built-in Rules Expansion

Add more built-in rules for common patterns.

| Item | Description | Priority | Effort | Status |
|------|-------------|----------|--------|--------|
| 5.1 | **Security-focused rules pack** | P1 | L | planned |
| 5.2 | Python: no_breakpoint (breakpoint() calls) | P2 | S | planned |
| 5.3 | Ruby: no_binding_pry, no_byebug | P2 | S | planned |
| 5.4 | Java: no_sout (System.out.println) | P2 | S | planned |
| 5.5 | C#: no_console (Console.WriteLine) | P2 | S | planned |
| 5.6 | Go: no_panic | P2 | S | planned |
| 5.7 | Kotlin: no_println | P2 | S | planned |
| 5.8 | **Credential detection rules** (API keys, tokens, secrets) | P1 | M | planned |

**Security rules pack (5.1) would include:**
- Hardcoded IP addresses
- Suspicious URLs
- Common secret patterns
- Insecure function calls (eval, exec, etc.)

---

## Phase 6: Integration Tooling

Improve developer workflow integration.

| Item | Description | Priority | Effort | Status |
|------|-------------|----------|--------|--------|
| 6.1 | **pre-commit hook integration** (pre-commit framework) | P1 | M | planned |
| 6.2 | Git commit-msg hook sample | P3 | S | planned |
| 6.3 | GitHub Action reusable workflow | P1 | M | planned |
| 6.4 | GitLab CI template | P2 | S | planned |
| 6.5 | Azure DevOps pipeline template | P3 | S | planned |
| 6.6 | VS Code extension (basic) | P3 | XL | planned |
| 6.7 | LSP server for IDE integration | P3 | XL | planned |

**pre-commit integration (6.1):**
```yaml
repos:
  - repo: https://github.com/owner/diffguard
    rev: v1.0.0
    hooks:
      - id: diffguard
        args: [check, --base, origin/main]
```

---

## Phase 7: Observability & Analytics

Add visibility into rule performance and effectiveness.

| Item | Description | Priority | Effort | Status |
|------|-------------|----------|--------|--------|
| 7.1 | Verbose/debug logging (`--verbose`, `--debug`) | P2 | S | planned |
| 7.2 | Performance timing metrics in receipt | P3 | S | planned |
| 7.3 | Rule hit statistics aggregation | P3 | M | planned |
| 7.4 | False positive tracking mechanism | P3 | L | planned |
| 7.5 | Historical trend analysis (cross-run metrics) | P3 | XL | planned |

---

## Phase 8: Advanced Rule Semantics

Enable more sophisticated matching patterns.

| Item | Description | Priority | Effort | Status |
|------|-------------|----------|--------|--------|
| 8.1 | Multi-line pattern matching (across consecutive lines) | P2 | L | planned |
| 8.2 | Negative patterns (flag if pattern NOT present) | P3 | M | planned |
| 8.3 | Context requirements (require pattern A near pattern B) | P3 | L | planned |
| 8.4 | Semantic severity escalation (warn→error based on context) | P3 | M | planned |
| 8.5 | Rule dependencies (if rule A matches, also check rule B) | P3 | M | planned |

---

## Phase 9: Scope Expansion

Extend diff analysis capabilities.

| Item | Description | Priority | Effort | Status |
|------|-------------|----------|--------|--------|
| 9.1 | `scope = "deleted"` - Flag removal of certain patterns | P2 | M | planned |
| 9.2 | `scope = "modified"` - Changed lines only, not pure additions | P3 | S | planned |
| 9.3 | Non-git diff sources (patch files, arbitrary diffs) | P3 | L | planned |
| 9.4 | Multiple base comparison (`--base main --base release/1.0`) | P3 | L | planned |
| 9.5 | Blame-aware filtering (by author, age) | P3 | XL | planned |

---

## Future Considerations

Items that may be considered based on community feedback:

- **Plugin system** - Dynamic rule loading (WASM or native)
- **AST-aware rules** - Tree-sitter integration for semantic matching
- **Auto-fix suggestions** - Machine-generated fix recommendations
- **Caching layer** - Skip unchanged files between runs
- **Distributed execution** - Parallel processing for large diffs
- **Custom severity levels** - User-defined beyond info/warn/error
- **SBOM integration** - Software bill of materials awareness
- **License scanning** - Built-in license header detection

---

## Version Milestones

### v1.0 (Stability Release)
- Phase 1 complete (full test coverage)
- All P0 items from Phases 2-6
- Stable public API guarantee

### v1.1 (Output Formats)
- SARIF output
- JUnit XML output
- GitHub Security integration

### v1.2 (Developer Experience)
- Inline suppression comments
- pre-commit integration
- Config validation command

### v2.0 (Advanced Features)
- Multi-line patterns
- Extended language support
- Plugin system (if demand exists)

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

To propose additions to this roadmap:
1. Open an issue describing the feature
2. Include use cases and expected behavior
3. Tag with `roadmap` label

---

*Last updated: 2026-02-03*
