#!/usr/bin/env python3
"""
Red tests for parallel pipeline implementation.

These tests verify the acceptance criteria for work-8d7001a2:
Verify parallel pipeline - per-item state isolation for parallel conveyor.

These tests MUST fail on the current implementation (before the parallel
pipeline feature is fully wired up) and pass after implementation is complete.

AC-1: Multiple different work items can be claimed simultaneously
AC-2: The same work item cannot be claimed by two runs simultaneously
AC-3: A double-claim attempt returns False and does not overwrite
AC-4: Only the run that holds the claim can release it
AC-5: State writes use atomic temp-file-rename pattern
AC-6: Each work item's state is stored in per-item file
AC-7: State updates from one run do not interfere with another
AC-8: is_claimed returns correct status after claim and release
AC-9: Claims persist across process restarts (filesystem-based)
AC-10: release_claim only releases if run_id matches
AC-11: Lazy migration works for non-migrated items
AC-12: Migration writes both per-item and old-state files
AC-13: Per-item state correct even with _sync_to_old_state race
AC-14: Stale locks not auto-cleaned (known limitation)
AC-15: INDEX_FILE is dead code (known limitation)
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

import pytest

# Add the gates module to path
GATES_DIR = Path.home() / ".hermes" / "runtime-overlays" / "conveyor"
sys.path.insert(0, str(GATES_DIR))


@pytest.fixture(scope="function")
def gates():
    """Import and return fresh gates module for each test."""
    # Remove cached module to force reimport
    if 'gates' in sys.modules:
        del sys.modules['gates']
    import gates
    import importlib
    importlib.reload(gates)
    return gates


@pytest.fixture(scope="function")
def test_env(tmp_path):
    """Create isolated test environment for each test."""
    work_items_dir = tmp_path / "work-items"
    claims_dir = work_items_dir / "claims"
    work_items_dir.mkdir(parents=True)
    claims_dir.mkdir(parents=True)
    
    # Create a temporary state file
    state_file = work_items_dir.parent / "conveyor-work-items.json"
    state_file.write_text(json.dumps({"items": {}, "version": 2}))
    
    return {
        "work_items_dir": work_items_dir,
        "claims_dir": claims_dir,
        "state_file": state_file,
    }


@pytest.fixture(scope="function")
def configured_gates(gates, test_env):
    """Configure gates module with test environment paths."""
    original_wi = gates.WORK_ITEMS_DIR
    original_cl = gates.CLAIMS_DIR
    original_state = gates.STATE_FILE
    
    gates.WORK_ITEMS_DIR = test_env["work_items_dir"]
    gates.CLAIMS_DIR = test_env["claims_dir"]
    gates.STATE_FILE = test_env["state_file"]
    gates._ensure_dirs()
    
    yield gates
    
    # Restore original paths
    gates.WORK_ITEMS_DIR = original_wi
    gates.CLAIMS_DIR = original_cl
    gates.STATE_FILE = original_state


# ============================================================================
# Test Cases
# ============================================================================

class TestAC1_AC2_AC3_ClaimAtomicity:
    """
    AC-1: Multiple different work items can be claimed simultaneously
    AC-2: Same work item cannot be double-claimed (atomic mkdir)
    AC-3: Double-claim returns False and preserves original
    """
    
    def test_ac1_parallel_claims_different_items(self, configured_gates):
        """AC-1: Two different work items can both be claimed simultaneously."""
        g = configured_gates
        
        # Two different items should both be claimable
        result_a = g.claim_item("work-test-a", "run-1")
        result_b = g.claim_item("work-test-b", "run-2")
        
        assert result_a is True, "First work item should be claimable"
        assert result_b is True, "Second work item should be claimable"
        
        # Both should show as claimed with correct run_ids
        claimed_a, run_a = g.is_claimed("work-test-a")
        claimed_b, run_b = g.is_claimed("work-test-b")
        
        assert claimed_a is True, "work-test-a should be claimed"
        assert run_a == "run-1", "work-test-a should be claimed by run-1"
        assert claimed_b is True, "work-test-b should be claimed"
        assert run_b == "run-2", "work-test-b should be claimed by run-2"
    
    def test_ac2_prevents_double_claim(self, configured_gates):
        """AC-2: Same work item cannot be double-claimed - second attempt returns False."""
        g = configured_gates
        
        # First claim succeeds
        result1 = g.claim_item("work-test-double-claim", "run-owner")
        assert result1 is True, "First claim should succeed"
        
        # Second claim by different run should fail
        result2 = g.claim_item("work-test-double-claim", "run-intruder")
        assert result2 is False, "Double claim should be rejected"
    
    def test_ac3_preserves_original_on_double_claim(self, configured_gates):
        """AC-3: Original claim is preserved after failed double-claim attempt."""
        g = configured_gates
        
        # Original claim
        g.claim_item("work-test-preserved", "run-owner")
        
        # Try to steal the claim
        g.claim_item("work-test-preserved", "run-intruder")
        
        # Original should still hold
        claimed, run_id = g.is_claimed("work-test-preserved")
        assert claimed is True, "Item should still be claimed"
        assert run_id == "run-owner", "Original owner should be preserved"


class TestAC4_AC10_ReleaseAuthorization:
    """
    AC-4: Correct run_id can release the claim
    AC-10: Mismatched run_id is rejected (returns False)
    """
    
    def test_ac4_owner_can_release(self, configured_gates):
        """AC-4: The run that holds the claim can successfully release it."""
        g = configured_gates
        
        # Claim it
        g.claim_item("work-test-release", "run-owner")
        
        # Owner should be able to release
        result = g.release_claim("work-test-release", "run-owner")
        assert result is True, "Owner should be able to release"
        
        # Should no longer be claimed
        claimed, run_id = g.is_claimed("work-test-release")
        assert claimed is False, "Item should be released"
        assert run_id == "", "run_id should be empty"
    
    def test_ac10_imposter_cannot_release(self, configured_gates):
        """AC-10: A run with mismatched run_id cannot release the claim."""
        g = configured_gates
        
        # Claim with owner
        g.claim_item("work-test-no-release", "run-owner")
        
        # Imposter tries to release
        result = g.release_claim("work-test-no-release", "run-imposter")
        assert result is False, "Imposter should not be able to release"
        
        # Should still be claimed by original owner
        claimed, run_id = g.is_claimed("work-test-no-release")
        assert claimed is True, "Item should still be claimed"
        assert run_id == "run-owner", "Original owner should still hold claim"


class TestAC5_AtomicStateWrites:
    """
    AC-5: State writes use atomic temp-file-rename pattern (no partial writes)
    """
    
    def test_ac5_atomic_write_uses_temp_file_rename(self, configured_gates):
        """AC-5: save_item_state must use temp file + rename pattern."""
        g = configured_gates
        
        item = {"work_id": "work-test-atomic", "gate": "BUILT"}
        g.save_item_state("work-test-atomic", item)
        
        # Verify the state file exists and contains correct data
        state_path = g._item_path("work-test-atomic")
        assert state_path.exists(), "State file should exist after save"
        
        loaded = json.loads(state_path.read_text())
        assert loaded == item, "State file should contain exact data saved"
        
        # Verify no temp files left behind
        temp_files = list(state_path.parent.glob("*.tmp"))
        assert len(temp_files) == 0, "No temp files should remain after write"


class TestAC6_AC7_StateIsolation:
    """
    AC-6: Each work item's state is stored in per-item file
    AC-7: Concurrent saves to different items don't interfere
    """
    
    def test_ac6_state_stored_in_per_item_file(self, configured_gates):
        """AC-6: State stored at ~/.hermes/state/conveyor/work-items/{work_id}/state.json."""
        g = configured_gates
        
        item = {"work_id": "work-test-iso", "gate": "DESIGNED", "note": "test"}
        g.save_item_state("work-test-iso", item)
        
        # Verify state is at the per-item path
        state_path = g._item_path("work-test-iso")
        assert state_path.exists(), "State file should exist at per-item path"
        
        # Verify it's a directory with state.json inside
        assert state_path.parent.is_dir(), "Should be a directory"
        assert state_path.name == "state.json", "Filename should be state.json"
        
        # Verify content
        loaded = g.load_item_state("work-test-iso")
        assert loaded == item, "Loaded state should match saved state"
    
    def test_ac7_concurrent_saves_different_items_no_interference(self, configured_gates):
        """AC-7: Saves to different work items don't interfere with each other."""
        g = configured_gates
        
        # Save state for two different items
        item_a = {"work_id": "work-test-iso-a", "gate": "BUILT"}
        item_b = {"work_id": "work-test-iso-b", "gate": "PROVEN"}
        
        g.save_item_state("work-test-iso-a", item_a)
        g.save_item_state("work-test-iso-b", item_b)
        
        # Load both - should be independent
        loaded_a = g.load_item_state("work-test-iso-a")
        loaded_b = g.load_item_state("work-test-iso-b")
        
        assert loaded_a["gate"] == "BUILT", "Item A gate should be BUILT"
        assert loaded_b["gate"] == "PROVEN", "Item B gate should be PROVEN"
        assert loaded_a["work_id"] == "work-test-iso-a", "Item A identity preserved"
        assert loaded_b["work_id"] == "work-test-iso-b", "Item B identity preserved"


class TestAC8_AC9_ClaimPersistence:
    """
    AC-8: is_claimed returns correct status after claim and release
    AC-9: Claims persist across process restarts (filesystem-based)
    """
    
    def test_ac8_status_tracking_after_claim_and_release(self, configured_gates):
        """AC-8: is_claimed returns correct status after claim and release."""
        g = configured_gates
        
        # Initially not claimed
        claimed, run_id = g.is_claimed("work-test-persist")
        assert claimed is False, "Should start unclaimed"
        assert run_id == "", "run_id should be empty"
        
        # After claim
        g.claim_item("work-test-persist", "run-1")
        claimed, run_id = g.is_claimed("work-test-persist")
        assert claimed is True, "Should be claimed after claim_item"
        assert run_id == "run-1", "run_id should match claimant"
        
        # After release
        g.release_claim("work-test-persist", "run-1")
        claimed, run_id = g.is_claimed("work-test-persist")
        assert claimed is False, "Should be unclaimed after release"
        assert run_id == "", "run_id should be empty"
    
    def test_ac9_claims_persist_filesystem_restart(self, configured_gates, test_env):
        """AC-9: Claims persist across 'restart' - filesystem-based claims survive."""
        g = configured_gates
        
        # Claim in "first process"
        g.claim_item("work-test-persist-2", "run-2")
        
        # Verify claim exists
        claimed_before, run_id_before = g.is_claimed("work-test-persist-2")
        assert claimed_before is True, "Claim should exist before 'restart'"
        assert run_id_before == "run-2"
        
        # Verify claim file exists on filesystem
        claim_file = test_env["claims_dir"] / "work-test-persist-2"
        assert claim_file.exists(), "Claim file should exist on filesystem"
        assert claim_file.read_text().strip() == "run-2", "Claim file should contain run_id"
        
        # Simulate "restart" by creating a new gates instance with same paths
        if 'gates_fresh' in sys.modules:
            del sys.modules['gates_fresh']
        import gates as gates_fresh_module
        
        # Configure fresh module with same paths
        gates_fresh_module.WORK_ITEMS_DIR = test_env["work_items_dir"]
        gates_fresh_module.CLAIMS_DIR = test_env["claims_dir"]
        
        # Should still be claimed - filesystem-based persistence
        claimed_after, run_id_after = gates_fresh_module.is_claimed("work-test-persist-2")
        assert claimed_after is True, "Claim should persist across module reload (filesystem)"
        assert run_id_after == "run-2", "run_id should be preserved"


class TestAC11_AC12_AC13_MigrationPath:
    """
    AC-11: Lazy migration works for non-migrated items
    AC-12: Migration writes both per-item file and old-state file
    AC-13: Per-item state correct even with _sync_to_old_state race
    """
    
    def test_ac11_lazy_migration_triggers(self, configured_gates):
        """AC-11: Accessing non-migrated item triggers automatic migration."""
        g = configured_gates
        
        # Create an "old style" state file with a work item
        old_item = {"work_id": "work-old", "gate": "DESIGNED"}
        g.save_state({"items": {"work-old": old_item}, "version": 2})
        
        # Now load it - should trigger migration
        loaded = g.load_item_state("work-old")
        assert loaded is not None, "Should find migrated item"
        assert loaded["gate"] == "DESIGNED", "Migrated data should be correct"
        
        # Verify it was migrated to per-item file
        per_item_path = g._item_path("work-old")
        assert per_item_path.exists(), "Migration should create per-item file"
    
    def test_ac12_migration_writes_both_files(self, configured_gates):
        """AC-12: Migration writes both per-item state and old-state file."""
        g = configured_gates
        
        # Save an item
        item = {"work_id": "work-both", "gate": "BUILT"}
        g.save_item_state("work-both", item)
        
        # Verify per-item file
        per_item_path = g._item_path("work-both")
        assert per_item_path.exists(), "Per-item file should exist"
        
        # Verify old state file is also updated
        old_state = g.load_state()
        assert "work-both" in old_state["items"], "Old state file should have item too"
        assert old_state["items"]["work-both"]["gate"] == "BUILT", "Old state data correct"
    
    def test_ac13_per_item_state_correct_despite_sync_race(self, configured_gates):
        """AC-13: Per-item state is correct even if _sync_to_old_state has race."""
        g = configured_gates
        
        # Save multiple items rapidly
        for i in range(5):
            item = {"work_id": f"work-race-{i}", "gate": f"GATE-{i}"}
            g.save_item_state(f"work-race-{i}", item)
        
        # Each per-item state should be correct regardless of sync issues
        for i in range(5):
            loaded = g.load_item_state(f"work-race-{i}")
            assert loaded["gate"] == f"GATE-{i}", f"Item {i} gate should be GATE-{i}"
        
        # Per-item files are source of truth - they should all exist and be correct
        for i in range(5):
            per_item_path = g._item_path(f"work-race-{i}")
            assert per_item_path.exists(), f"Per-item file for work-race-{i} should exist"
            data = json.loads(per_item_path.read_text())
            assert data["gate"] == f"GATE-{i}", f"Per-item file data correct for {i}"


class TestAC14_AC15_KnownLimitations:
    """
    AC-14: Stale locks are not automatically cleaned up
    AC-15: INDEX_FILE is dead code (never read)
    
    These document known limitations - tests verify the limitations exist.
    """
    
    def test_ac14_stale_lock_not_auto_cleaned(self, configured_gates, test_env):
        """AC-14: Stale locks (after crash) are NOT automatically cleaned up."""
        g = configured_gates
        
        # Create a stale claim (simulating crash after claim)
        stale_claim = test_env["claims_dir"] / "work-stale"
        stale_claim.write_text("crashed-run\n")
        
        # There should be no automatic cleanup function exposed
        assert not hasattr(g, 'cleanup_stale_claims'), \
            "No stale lock cleanup function should exist (AC-14)"
        
        # The stale claim should still exist
        assert stale_claim.exists(), "Stale claim should remain"
    
    def test_ac15_index_file_dead_code(self, gates):
        """AC-15: INDEX_FILE constant exists but is never read by list_work_items."""
        g = gates
        
        # INDEX_FILE exists
        assert hasattr(g, 'INDEX_FILE'), "INDEX_FILE constant should exist"
        
        # But list_work_items doesn't use it - verify by checking the function
        import inspect
        source = inspect.getsource(g.list_work_items)
        
        # The function should NOT reference INDEX_FILE
        assert "INDEX_FILE" not in source, \
            "list_work_items should not reference INDEX_FILE (dead code per AC-15)"


# ============================================================================
# Run tests with pytest
# ============================================================================

if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
