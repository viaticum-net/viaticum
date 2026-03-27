# E2E Test Improvements (2026-03-27)

## Summary

Systematic review of all 13 gamma E2E tests identified and fixed several categories of issues:
- **Always-pass bugs** (4 tests) — result labels that could never fail
- **Missing negative tests** (2 tests) — restore of deleted/nonexistent files
- **Missing health assertions** (2 tests) — blocks_at_risk, placement_lost
- **New tech-debt discovered** — restore CLI doesn't reject deleted files

## Changes by Test

### test_backup_restore.py (T2)

**Added Phase 9: Block health check**
- Asserts `blocks_at_risk == 0` after successful backup
- Label: `blocks_not_at_risk`

**Added Phase 10: Negative restore test**
- Attempts `syncback restore /data/files/does_not_exist.txt`
- Verifies no output file is produced
- Label: `negative_restore_no_output`
- Finding: restore CLI returns exit 0 for unknown files (recorded in tech-debt.md)

**Renumbered Phase 11: Status consistency** (was Phase 9)

### test_deletion.py (T7)

**Added Phase 11: Negative restore of deleted file**
- After full deletion pipeline (both cooldowns expired), attempts to restore deleted file
- Verifies no output file produced
- Label: `deleted_file_not_restorable`
- Finding: restore CLI returns exit 0 even for fully-deleted files (tech-debt)

**Fixed Phase 12: `placement_degraded` always-pass bug**
- Before: both `if` and `else` branches appended to `results["passed"]`
- After: added `wait_for` loop (30s) checking `placement_lost > 0` before soft pass fallback
- Still soft pass on timeout (timing-dependent), but now actually waits

### test_disk_pressure.py (T6)

**Fixed Phase 9: `owner_detects_degraded` always-pass bug**
- Same pattern as deletion: both branches were `results["passed"]`
- Added `wait_for` loop (30s) for `placement_lost > 0 or placement_alive < initial`
- Soft pass fallback after timeout (eviction itself is the key assertion)

### test_escrow.py (T8)

**Fixed Phase 4: `restore_denied_early` always-pass bug**
- Before: if no denials detected, silently passed with a note
- After: if both restores succeed AND backup was fast (< 60s elapsed), marks FAIL
- Legitimate timing edge case (backup took > 60s) still gets soft pass

**Fixed Phase 6: `budget_exhausted` always-pass bug**
- Before: if both restores succeed when budget should be exhausted, passed anyway
- After: if both succeed and scaled time < 300 days, marks FAIL
- Guard for extreme time scenarios where budget genuinely grew huge

### test_budget.py (T9)

**Fixed Phase 4: `wave2_standard` always-pass bug**
- Before: `results["passed"].append("wave2_standard")` unconditionally
- After: checks `count_backed_up_in_dir(owner, "/data/files/standard") > 0`
- Fails if no standard files were backed up

### test_repair.py (T4)

**Added Phase 7b: Intermediate placement_lost check**
- After PoS timeout detection, checks `placement_lost > 0`
- Label: `placement_lost_detected`
- Soft pass if already repaired (repair can be faster than the check)

## New Tech-Debt Discovered

### Restore CLI doesn't reject deleted or nonexistent files

`syncback restore /path` returns exit 0 and prints "restore started" even when:
- The file was never backed up
- The file has been fully deleted (both cooldowns expired)

The restore coordinator starts but produces no output file. This is a CLI UX issue, not a data integrity bug. Recorded in `docs/tech-debt.md`.

## E2E Tests Not Modified

- test_discovery.py (T1) — discovery-only, no functional gap worth fixing now
- test_relay_offline.py (T3) — relay offline recovery works correctly
- test_pos_trust.py (T3) — PoS/trust accumulation works but threshold checks could be tighter
- test_board_transport.py (T5) — board transport claim unverifiable without protocol changes
- test_dedup.py (T10) — dedup works; block ID parsing issue is minor
- test_dr.py (T13) — DR flow works; identity re-verification would need CLI changes
- test_cluster_sync.py (T12) — cluster sync works; cross-device catalog not checkable without feature changes

## Potential Further Improvements (not implemented)

1. **test_pos_trust.py**: Assert `trust_above_one` for ALL holders, not just "any"
2. **test_board_transport.py**: Add actual board message count verification
3. **test_dedup.py**: Verify `holdings_total` doesn't increase after dedup
4. **test_dr.py**: Check `node_identity` matches pre/post DR
5. **test_cluster_sync.py**: Verify B can see A's files via `syncback files`
6. **All tests**: Add `no_crashes` check (grep for panic/SIGSEGV in logs)
