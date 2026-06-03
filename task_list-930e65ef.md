# Task List — work-930e65ef

## Implementation Tasks (19 format string fixes in server.rs)

1. [ ] Fix server.rs:140 — config_label, err → {config_label}, {err}
2. [ ] Fix server.rs:299 — err → {err}
3. [ ] Fix server.rs:320 — rule_id → {rule_id}
4. [ ] Fix server.rs:326 — rule_id → {rule_id}
5. [ ] Fix server.rs:368 — err → {err}
6. [ ] Fix server.rs:438 — rule_id → {rule_id}
7. [ ] Fix server.rs:443 — label, url → {label}, {url}
8. [ ] Fix server.rs:470 — rule_id → {rule_id}
9. [ ] Fix server.rs:474 — suggestion → {suggestion}
10. [ ] Fix server.rs:494 — err → {err}
11. [ ] Fix server.rs:519 — err → {err}
12. [ ] Fix server.rs:546 — err → {err}
13. [ ] Fix server.rs:581 — err → {err}
14. [ ] Fix server.rs:599 — err → {err}
15. [ ] Fix server.rs:639 — count → {count}
16. [ ] Fix server.rs:647 — err → {err}
17. [ ] Fix server.rs:702 — err → {err}
18. [ ] Fix server.rs:728 — err → {err}
19. [ ] Fix server.rs:760 — relative_path, err → {relative_path}, {err}

## Verification Tasks

1. [ ] Run cargo test -p diffguard-lsp — all tests pass
2. [ ] Run cargo clippy -p diffguard-lsp -- -D warnings — zero warnings
3. [ ] Run cargo clippy -p diffguard-lsp -- -W clippy::uninlined_format_args — verify 0 warnings

## Documentation Tasks

1. [ ] PR description: CI does NOT enforce clippy::uninlined_format_args
2. [ ] PR description: Note remaining ~380 workspace occurrences for follow-up
