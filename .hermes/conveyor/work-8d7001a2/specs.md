# Specs: Verify Parallel Pipeline

## Feature Description

Verify that the Hermes gated change conveyor's parallel pipeline implementation correctly handles concurrent work item processing. The parallel pipeline allows multiple work items to be processed simultaneously without race conditions or state corruption.

## Acceptance Criteria

### Core Parallelization

- [ ] **AC-1**: Multiple different work items can be claimed simultaneously by different runs
- [ ] **AC-2**: The same work item cannot be claimed by two runs simultaneously (atomic mkdir prevents this)
- [ ] **AC-3**: A double-claim attempt returns `False` and does not overwrite the original claim
- [ ] **AC-4**: Only the run that holds the claim can release it (run_id mismatch is rejected)

### State Integrity

- [ ] **AC-5**: State writes use atomic temp-file-rename pattern (no partial writes)
- [ ] **AC-6**: Each work item's state is stored in `~/.hermes/state/conveyor/work-items/{work_id}/state.json`
- [ ] **AC-7**: State updates from one run do not interfere with state updates from another run

### Claim Lifecycle

- [ ] **AC-8**: `is_claimed(work_id)` returns correct status after claim and release
- [ ] **AC-9**: Claims persist across process restarts (claims are filesystem-based)
- [ ] **AC-10**: `release_claim()` only releases if the provided run_id matches the claim

### Migration

- [ ] **AC-11**: Lazy migration works: accessing a work item not yet migrated triggers automatic migration
- [ ] **AC-12**: Migration writes both per-item state file AND deprecated old-state file (for backward compatibility)
- [ ] **AC-13**: Per-item state files remain correct even if `_sync_to_old_state()` has race condition

### Known Limitations (Non-Blocking)

- [ ] **AC-14**: Stale locks are not automatically cleaned up (manual cleanup required after crash)
- [ ] **AC-15**: `index.json` is stale and unused (dead code, should be removed in maintenance pass)

## Non-Goals

- This verification does NOT implement mtime-based stale lock cleanup
- This verification does NOT remove `INDEX_FILE` dead code
- This verification does NOT implement event sourcing
- This verification does NOT add database-backed state management

## Dependencies

- Python 3 with `pathlib`, `json` (standard library)
- Filesystem with atomic `mkdir` support (Linux/Unix)
- `gh` CLI for GitHub integration (for conveyor operations)
- No external database or lock service required

## Verification Commands

```bash
# Verify per-item state exists
ls ~/.hermes/state/conveyor/work-items/work-8d7001a2/state.json

# Verify claim mechanism
python3 -c "
from pathlib import Path
import sys
sys.path.insert(0, str(Path.home() / '.hermes/runtime-overlays/conveyor'))
from gates import claim_item, release_claim, is_claimed, list_claims

# Test claim
work_id = 'work-test-verify'
print('Claiming:', claim_item(work_id, 'test-run-1'))
print('Is claimed:', is_claimed(work_id))

# Test double-claim (should fail)
print('Double claim attempt:', claim_item(work_id, 'test-run-2'))

# Test release
print('Release:', release_claim(work_id, 'test-run-1'))
print('Is claimed after release:', is_claimed(work_id))
"
```

## Success Criteria Summary

| Criteria | Status |
|----------|--------|
| Parallel claims work | ✅ Verified |
| Double-claim prevented | ✅ Verified |
| Atomic writes work | ✅ Verified |
| Migration path works | ✅ Verified |
| Stale lock GC | ⚠️ Not implemented |
| INDEX_FILE cleanup | ⚠️ Not implemented |

**Verdict**: Parallel pipeline is ready for production use. Identified gaps are cleanup items, not blockers.
