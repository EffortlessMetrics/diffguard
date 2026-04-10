# ADR: Per-Item State Isolation for Parallel Conveyor Pipeline

## Status

**Accepted**

## Context

The Hermes gated change conveyor previously used a single shared state file (`conveyor-work-items.json`) for tracking all work items. This design created race conditions when multiple cron jobs or manual runs attempted concurrent writes to the same file, leading to potential state corruption or lost updates.

The conveyor needs to support parallel processing of multiple work items simultaneously without coordination overhead between runs.

## Decision

We adopted **per-item state isolation** with **atomic claim tokens** for the conveyor pipeline:

1. **Per-item state files**: Each work item has its own `state.json` at `~/.hermes/state/conveyor/work-items/{work_id}/state.json`. The source of truth is the per-item file.

2. **Atomic claims via `mkdir`**: The `claim_item(work_id, run_id)` function uses `mkdir(exist_ok=False)` to atomically claim a work item. If the claim directory already exists, the claim fails, preventing double-processing.

3. **Atomic writes via temp file + rename**: `save_item_state()` writes to a temporary file then atomically renames it, preventing partial writes.

4. **Lazy migration from legacy state**: `load_item_state()` falls back to the old single-file state during migration and migrates on first access.

5. **Deprecated `_sync_to_old_state()`**: The old file is maintained during migration via `_sync_to_old_state()` which has a known race condition (acceptable because per-item files are source of truth).

## Consequences

### Tradeoffs

| Aspect | Before | After |
|--------|--------|-------|
| State storage | Single JSON file | Per-item directories |
| Concurrent writes | Read-modify-write race | No shared write surface |
| Claim mechanism | None (race-prone) | Atomic mkdir |
| Migration | N/A | Lazy migration with deprecated sync |

### Risks

1. **`_sync_to_old_state()` race condition (MEDIUM, bounded)**: The sync function reads the old file and writes back, creating a read-modify-write race if two parallel runs save different work items simultaneously. Impact is bounded: only the deprecated migration file is affected, not the per-item source-of-truth files.

2. **Stale lock accumulation (MEDIUM)**: If a cron job crashes after claiming but before releasing, the claim file remains until manually cleaned. No mtime-based stale lock GC is implemented.

3. **`INDEX_FILE` is dead code (LOW)**: The `index.json` file is never read by `list_work_items()` and is stale. Harmless but should be removed.

### Benefits

- **No double-processing**: Atomic mkdir claims prevent two runs from processing the same work item
- **No state corruption**: Atomic writes prevent partial state files
- **Safe parallelization**: Different work items can be processed concurrently without coordination
- **Horizontal scaling**: The per-item model supports scaling the conveyor pipeline
- **Fault isolation**: A crash in one work item's processing doesn't corrupt another's state

## Alternatives Considered

### 1. Event Sourcing (Rejected)
Instead of per-item state files, use an event log for all state transitions. This would eliminate races entirely but adds significant complexity (event store, event replay, snapshot management) not warranted at current scale (dozens of work items, occasional parallel runs).

### 2. Database with Transactions (Rejected)
Use SQLite or PostgreSQL with proper transaction isolation. Adds external dependency and operational overhead. The file-based per-item approach is simpler and sufficient.

### 3. Distributed Lock Service (Rejected)
Use Redis or etcd for distributed locking. Adds external dependency and network round-trips. The local filesystem `mkdir` approach is faster and simpler for single-machine conveyor.

## Recommendations

1. **Accept the bounded race in `_sync_to_old_state()`**: Document as known limitation during migration period. Per-item files are the source of truth.

2. **Remove `INDEX_FILE` dead code**: The per-item directories are the source of truth. Remove the unused constant in a maintenance pass.

3. **Implement mtime-based stale lock cleanup (low priority)**: Add `cleanup_stale_claims(max_age_minutes=60)` function for production scale.

4. **Do NOT adopt event sourcing now**: The per-item state model is sufficient for current and near-term scale.

## References

- Verification findings: `work-8d7001a2/verification_comment.md`
- Implementation: `~/.hermes/runtime-overlays/conveyor/gates.py`
- State directory: `~/.hermes/state/conveyor/work-items/`
