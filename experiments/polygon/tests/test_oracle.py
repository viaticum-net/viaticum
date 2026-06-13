#!/usr/bin/env python3
"""Self-test for the polygon oracle ("проверка проверки").

The oracle is the code that judges a run PASS/FAIL — but it is itself untested
code that can lie (it produced false-positives on the first real run: churn-killed
nodes counted as "unexpected death" / "unreadable DB"). This test pins the oracle's
OWN intent with controlled fixtures whose verdict is known by construction:

  - a node taken offline by the CHURN SCHEDULE (intended-down) must NOT be flagged
    as an unexpected death or a corrupt DB (the churn-awareness fix);
  - a node intended UP but unreachable throughout MUST be flagged (a real crash);
  - a restored file whose hash != original MUST fail the no-data-loss gate.

Fixtures are written with the REAL common/churn writers so the on-disk format
matches production exactly. Run: python3 -m unittest tests.test_oracle  (from the
polygon dir) or python3 tests/test_oracle.py.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_POLY = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_POLY))

import common  # noqa: E402
import churn  # noqa: E402
import oracle_bug  # noqa: E402

TIME_SCALE = 30000
SAMPLE_INTERVAL = 6.0
N_TICKS = 60
FLEET_START_ABS = 1_700_000_000.0  # absolute epoch — mimics churn_log's absolute wall


def _vday_at(tick):
    # virtual_day at this tick: wall is RELATIVE (tick*interval), scaled by time_scale.
    return (tick * SAMPLE_INTERVAL * TIME_SCALE) / 86400.0


def _healthy_row(tick, label, archetype, status_ok, up_state, **over):
    """A TimeseriesRow with healthy values when up; daemon fields zeroed when down
    (exactly how the collector records a down node). **over sets per-field overrides."""
    vday = _vday_at(tick)
    r = common.TimeseriesRow(
        tick=tick,
        wall_secs=tick * SAMPLE_INTERVAL,   # RELATIVE wall (as the collector writes)
        virtual_day=vday,
        label=label,
        archetype=archetype,
        up_state=up_state,
        status_ok=1 if status_ok else 0,
        device_id=label.replace("node-", "dev")[:16],
    )
    if status_ok:
        r.peer_count = 39
        r.peer_count_connected = 39
        r.peer_count_authenticated = 39
        r.avg_trust = 1.0
        r.holding_bytes = 50_000_000
        r.backed_up_files = 4
        r.backed_up_bytes = 40_000_000
        r.effective_quota_bytes = 2_000_000_000
        r.used_bytes = 50_000_000
        r.pos_total_challenges = tick          # climbing
        r.pos_total_passes = tick              # climbing in lock-step
        r.placement_count = 10
        r.placement_alive = 10
        r.placement_lost = 0
        r.blocks_ok = 4
        r.blocks_at_risk = 0
        r.tbl_event_log = 100                  # FLAT -> db-bounded slope ~0
        r.tbl_files = 4
        r.ext_rss_kb = 200_000                 # FLAT -> rss-bounded slope ~0
        r.ext_du_holdings_kb = 48_000          # FLAT -> disk-bounded slope ~0
        r.ext_du_db_redb_bytes = 4_000_000
        r.ext_du_datadir_kb = 60_000
    for k, v in over.items():
        setattr(r, k, v)
    return r


def _write_fixture(rdir, rows, events, restore_entries, panic=False, dr_entries=None,
                   dr_victims=None):
    rdir = Path(rdir)
    # timeseries.csv (real writer -> canonical schema)
    fh, _ = common.open_timeseries_writer(rdir / "timeseries.csv")
    for r in rows:
        common.write_timeseries_row(fh, r)
    fh.close()
    # edges.csv (empty but present)
    efh, _ = common.open_edges_writer(rdir / "edges.csv")
    efh.close()
    # churn_log.json (real writer; ChurnEvent carries absolute wall + virtual_day)
    churn.write_churn_log(rdir / "churn_log.json", events)
    # node_index.json
    labels = sorted({r.label for r in rows})
    idx = {lab: {"label": lab, "archetype": next(r.archetype for r in rows if r.label == lab),
                 "device_id": lab.replace("node-", "dev")[:16], "join_virtual_day": 0}
           for lab in labels}
    (rdir / "node_index.json").write_text(json.dumps(idx))
    # restore_results.json (authoritative outcomes the no-data-loss oracle reads)
    (rdir / "restore_results.json").write_text(json.dumps({
        "entries": restore_entries,
        "total": len(restore_entries),
        "restored_ok": sum(1 for e in restore_entries if e["status"] == "ok"),
        "hash_mismatch": sum(1 for e in restore_entries if e["status"] == "hash_mismatch"),
        "not_found": sum(1 for e in restore_entries if e["status"] == "not_found"),
    }))
    # dr_results.json (DR-subset network-recovery ground truth — the authoritative
    # no-data-loss signal). Only written when dr_entries is provided; absence exercises
    # the oracle's INCONCLUSIVE tier-1 fallback path.
    if dr_entries is not None:
        if dr_victims is None:
            dr_victims = [{"label": lab} for lab in sorted({e["label"] for e in dr_entries})]
        (rdir / "dr_results.json").write_text(json.dumps({
            "dr_victims": dr_victims,
            "total": len(dr_entries),
            "restored_ok": sum(1 for e in dr_entries if e["status"] == "ok"),
            "hash_mismatch": sum(1 for e in dr_entries if e["status"] == "hash_mismatch"),
            "not_found": sum(1 for e in dr_entries if e["status"] == "not_found"),
            "entries": dr_entries,
        }))
    # stderr_scans.json (per-label panic/error scan)
    scans = {lab: {"panicked": panic, "error_lines": 0, "first_error": None} for lab in labels}
    (rdir / "stderr_scans.json").write_text(json.dumps(scans))
    # scenario.json (provenance + thresholds source)
    (rdir / "scenario.json").write_text(json.dumps({
        "id": "fixture", "time_scale": TIME_SCALE, "sample_interval_secs": SAMPLE_INTERVAL,
        "warmup_virtual_days": 0, "requested_nodes": len(labels),
    }))


def _ev(event_type, vday, targets):
    """A ChurnEvent with an ABSOLUTE wall_secs (as churn.build_event_queue produces)
    and the matching virtual_day — so a wall-based oracle reads it wrong and a
    virtual_day-based oracle reads it right."""
    return common.ChurnEvent(
        virtual_day=float(vday),
        wall_secs=FLEET_START_ABS + (vday * 86400.0 / TIME_SCALE),
        event_type=event_type,
        targets=list(targets),
    )


def _verdict(rdir):
    oracle_bug.run(str(rdir))
    v = json.loads((Path(rdir) / "verdict.json").read_text())
    bf = v.get("bugfree", v)
    return {c.get("name") or c.get("id"): c for c in bf.get("checks", [])}


def _passed(check):
    return check.get("passed", check.get("pass"))


class OracleSelfTest(unittest.TestCase):
    def test_churned_node_not_flagged_as_death_or_corruption(self):
        """node-A is killed@vday2, restarted@vday40, killed@vday80 (and NOT restarted),
        so it is intended-DOWN for the MAJORITY of the run AND at its final sample.
        Every such status_ok=0 sample is PLANNED churn, not a crash/corruption. This
        reproduces the steady_real1 false-positive (node down >50% of eligible samples
        + down at teardown); a churn-aware oracle must NOT flag it. node-B is always up."""
        rows = []
        for t in range(N_TICKS):
            vday = _vday_at(t)
            a_down = (2.0 < vday < 40.0) or (vday > 80.0)
            rows.append(_healthy_row(t, "node-A", "nomad",
                                     status_ok=not a_down,
                                     up_state="down" if a_down else "up"))
            rows.append(_healthy_row(t, "node-B", "reliable", status_ok=True, up_state="up"))
        events = [_ev("kill", 2.0, ["node-A"]), _ev("restart", 40.0, ["node-A"]),
                  _ev("kill", 80.0, ["node-A"])]
        restore = [{"label": "node-A", "name": "a0.bin", "want_hash": "h1", "got_hash": "h1", "status": "ok"},
                   {"label": "node-B", "name": "b0.bin", "want_hash": "h2", "got_hash": "h2", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, events, restore)
            ch = _verdict(d)
            self.assertTrue(_passed(ch["BUG-no-unexpected-death"]),
                            f"churn-killed node wrongly flagged dead: {ch['BUG-no-unexpected-death']}")
            self.assertTrue(_passed(ch["BUG-db-integrity"]),
                            f"churn-killed node wrongly flagged corrupt: {ch['BUG-db-integrity']}")
            self.assertTrue(_passed(ch["BUG-no-data-loss"]),
                            f"clean restore wrongly failed: {ch['BUG-no-data-loss']}")

    def test_real_crash_is_flagged(self):
        """node-C is intended UP the whole run (no churn events) but unreachable
        throughout -> a real death the oracle MUST catch."""
        rows = []
        for t in range(N_TICKS):
            rows.append(_healthy_row(t, "node-C", "reliable", status_ok=False, up_state="up"))
            rows.append(_healthy_row(t, "node-B", "reliable", status_ok=True, up_state="up"))
        restore = [{"label": "node-B", "name": "b0.bin", "want_hash": "h2", "got_hash": "h2", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore)
            ch = _verdict(d)
            self.assertFalse(_passed(ch["BUG-no-unexpected-death"]),
                             "a node up-but-unreachable-throughout must be flagged dead")

    def test_data_loss_is_flagged(self):
        """A restored file whose hash != original MUST fail no-data-loss (tier-1
        fallback path: no dr_results.json present)."""
        rows = [_healthy_row(t, "node-B", "reliable", status_ok=True, up_state="up")
                for t in range(N_TICKS)]
        restore = [{"label": "node-B", "name": "b0.bin", "want_hash": "h2", "got_hash": "DIFFERENT", "status": "hash_mismatch"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore)
            ch = _verdict(d)
            self.assertFalse(_passed(ch["BUG-no-data-loss"]),
                             "a hash mismatch must fail the no-data-loss gate")

    def test_dr_all_ok_passes_no_data_loss(self):
        """The AUTHORITATIVE path: a DR subset that recovered every file from holders
        (all status=ok) PASSES no-data-loss — even if the tier-1 ledger were absent."""
        rows = [_healthy_row(t, "node-B", "reliable", status_ok=True, up_state="up")
                for t in range(N_TICKS)]
        restore = [{"label": "node-B", "name": "b0.bin", "want_hash": "h2", "got_hash": "h2", "status": "ok"}]
        dr = [{"label": "node-B", "name": "b0.bin", "want_hash": "h2", "got_hash": "h2", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore, dr_entries=dr)
            ch = _verdict(d)
            chk = ch["BUG-no-data-loss"]
            self.assertTrue(_passed(chk),
                            f"all-ok DR recovery must pass no-data-loss: {chk}")
            self.assertEqual(chk["detail"].get("source"), "dr_results.json",
                             "no-data-loss must gate on the DR ground truth when present")

    def test_dr_hash_mismatch_fails_no_data_loss(self):
        """A DR-recovered file whose hash != original MUST hard-fail no-data-loss,
        even when the WEAKER tier-1 local restore reported ok (the exact false-positive
        the DR gate exists to catch)."""
        rows = [_healthy_row(t, "node-B", "reliable", status_ok=True, up_state="up")
                for t in range(N_TICKS)]
        # Tier-1 LIES (local source still present -> ok); DR (network) catches the loss.
        restore = [{"label": "node-B", "name": "b0.bin", "want_hash": "h2", "got_hash": "h2", "status": "ok"}]
        dr = [{"label": "node-B", "name": "b0.bin", "want_hash": "h2", "got_hash": "WRONG", "status": "hash_mismatch"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore, dr_entries=dr)
            ch = _verdict(d)
            self.assertFalse(_passed(ch["BUG-no-data-loss"]),
                             "a DR network-recovery hash mismatch must fail no-data-loss")

    def test_dr_not_found_fails_no_data_loss(self):
        """A DR-victim file that was NEVER recovered from holders MUST fail no-data-loss
        (the network copy did not exist / was unreachable)."""
        rows = [_healthy_row(t, "node-B", "reliable", status_ok=True, up_state="up")
                for t in range(N_TICKS)]
        restore = [{"label": "node-B", "name": "b0.bin", "want_hash": "h2", "got_hash": "h2", "status": "ok"}]
        dr = [{"label": "node-B", "name": "b0.bin", "want_hash": "h2", "status": "not_found"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore, dr_entries=dr)
            ch = _verdict(d)
            self.assertFalse(_passed(ch["BUG-no-data-loss"]),
                             "a DR file never recovered from holders must fail no-data-loss")

    def test_dr_empty_is_inconclusive_not_false_pass(self):
        """A present-but-empty DR result (no eligible victim) must NOT be silently
        treated as the strong proof: the check falls back to the tier-1 signal and marks
        itself INCONCLUSIVE in detail (rather than claiming network recovery succeeded)."""
        rows = [_healthy_row(t, "node-B", "reliable", status_ok=True, up_state="up")
                for t in range(N_TICKS)]
        restore = [{"label": "node-B", "name": "b0.bin", "want_hash": "h2", "got_hash": "h2", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore, dr_entries=[])  # empty DR result on disk
            ch = _verdict(d)
            chk = ch["BUG-no-data-loss"]
            self.assertTrue(chk["detail"].get("inconclusive"),
                            f"empty DR result must mark the check INCONCLUSIVE: {chk}")
            self.assertNotEqual(chk["detail"].get("source"), "dr_results.json",
                                "empty DR result must not be reported as authoritative")

    def test_inconclusive_surfaces_at_top_level_verdict(self):
        """An inconclusive check (passed boolean, but property unproven) must be listed in
        the TOP-LEVEL bugfree.inconclusive — not buried in per-check detail — so a consumer
        reading only bugfree.pass / the exit code is not fooled by a green it can't prove.
        (Reviewer finding C: empty-DR fell back to tier-1 with passed=True; the operator
        must see the inconclusiveness without inspecting each check's detail.)"""
        rows = [_healthy_row(t, "node-B", "reliable", status_ok=True, up_state="up")
                for t in range(N_TICKS)]
        restore = [{"label": "node-B", "name": "b0.bin", "want_hash": "h2", "got_hash": "h2", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore, dr_entries=[])  # empty DR -> inconclusive
            oracle_bug.run(str(d))
            bf = json.loads((Path(d) / "verdict.json").read_text())["bugfree"]
            self.assertIn("BUG-no-data-loss", bf.get("inconclusive", []),
                          f"inconclusive no-data-loss must surface at top level: {bf.get('inconclusive')}")

    def test_holdings_filling_under_quota_not_flagged(self):
        """A node whose holdings du climbs steadily but stays UNDER its quota is FILLING
        allowed space (no disk pressure) — not a leak. Eviction only acts at quota, so
        disk-bounded must NOT flag it. (Reproduces the steady_real1 'fill vs leak' false
        positive: holdings grew because the network kept placing, far under a 2 GB quota.)"""
        rows = []
        for t in range(N_TICKS):
            rows.append(_healthy_row(t, "node-F", "reliable", status_ok=True, up_state="up",
                                     ext_du_holdings_kb=40_000 + t * 3000,          # +3000 KB/tick
                                     holding_bytes=30_000_000 + t * 2_000_000,      # ~148 MB at end
                                     effective_quota_bytes=2_000_000_000))          # 2 GB — stays far under
        restore = [{"label": "node-F", "name": "f0.bin", "want_hash": "h", "got_hash": "h", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore)
            ch = _verdict(d)
            self.assertTrue(_passed(ch["BUG-disk-bounded"]),
                            f"holdings filling under quota wrongly flagged a leak: {ch['BUG-disk-bounded']}")

    def test_disk_leak_at_quota_still_flagged(self):
        """A node AT its quota whose holdings keep climbing = eviction is NOT running =
        a real leak the check must still catch (proves the fill-vs-leak fix didn't
        defang the real signal)."""
        rows = []
        for t in range(N_TICKS):
            rows.append(_healthy_row(t, "node-Q", "reliable", status_ok=True, up_state="up",
                                     ext_du_holdings_kb=1_900_000 + t * 3000,       # climbing
                                     holding_bytes=1_950_000_000 + t * 1_000_000,   # AT/over the 2 GB quota
                                     effective_quota_bytes=2_000_000_000))
        restore = [{"label": "node-Q", "name": "q0.bin", "want_hash": "h", "got_hash": "h", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore)
            ch = _verdict(d)
            self.assertFalse(_passed(ch["BUG-disk-bounded"]),
                             "holdings growing while AT quota (eviction broken) must be flagged")

    def test_backup_live_if_ever_reached_healthy(self):
        """A node that reached healthy replication mid-run but whose holders are down at
        the churn-disrupted final sample (blocks_ok/placement_alive read 0) is NOT a
        wedged pipeline — its data exists and restores. Liveness = EVER reached healthy."""
        rows = []
        for t in range(N_TICKS):
            healthy = t < 40
            rows.append(_healthy_row(t, "node-D", "reliable", status_ok=True, up_state="up",
                                     blocks_ok=4 if healthy else 0,
                                     placement_alive=10 if healthy else 0,
                                     backed_up_files=4))
        restore = [{"label": "node-D", "name": "d0.bin", "want_hash": "h", "got_hash": "h", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore)
            ch = _verdict(d)
            self.assertTrue(_passed(ch["BUG-backup-liveness"]),
                            f"node that reached healthy then dipped at end wrongly flagged: {ch['BUG-backup-liveness']}")

    def test_backup_never_placed_is_flagged(self):
        """A node with own data that NEVER reaches healthy replication = wedged pipeline."""
        rows = [_healthy_row(t, "node-N", "reliable", status_ok=True, up_state="up",
                             blocks_ok=0, placement_alive=0, backed_up_files=4)
                for t in range(N_TICKS)]
        restore = [{"label": "node-N", "name": "n0.bin", "want_hash": "h", "got_hash": "h", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore)
            ch = _verdict(d)
            self.assertFalse(_passed(ch["BUG-backup-liveness"]),
                             "a node that never reached healthy replication must be flagged")


    def test_rss_oscillation_not_flagged(self):
        """RSS that bounces around a stable mean (no sustained growth) is NOT a leak,
        even if a back-half linear fit is spuriously positive. Reproduces steady_real1
        node-05 (RSS oscillated 57-83 MB)."""
        wobble = [73, 74, 82, 84, 65, 66, 61, 57, 75, 70, 72, 79, 60, 68, 71, 64,
                  77, 69, 73, 58, 80, 67, 70, 75]
        rows = []
        for t in range(N_TICKS):
            rss_mb = wobble[t % len(wobble)]
            rows.append(_healthy_row(t, "node-W", "reliable", status_ok=True, up_state="up",
                                     ext_rss_kb=rss_mb * 1024))
        restore = [{"label": "node-W", "name": "w0.bin", "want_hash": "h", "got_hash": "h", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore)
            ch = _verdict(d)
            self.assertTrue(_passed(ch["BUG-rss-bounded"]),
                            f"oscillating RSS wrongly flagged as a leak: {ch['BUG-rss-bounded']}")

    def test_rss_real_leak_flagged(self):
        """RSS that climbs monotonically (e.g. doubles over the run) IS a leak."""
        rows = [_healthy_row(t, "node-L", "reliable", status_ok=True, up_state="up",
                             ext_rss_kb=200_000 + t * 8000)  # 200 MB -> ~660 MB, monotonic
                for t in range(N_TICKS)]
        restore = [{"label": "node-L", "name": "l0.bin", "want_hash": "h", "got_hash": "h", "status": "ok"}]
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, rows, [], restore)
            ch = _verdict(d)
            self.assertFalse(_passed(ch["BUG-rss-bounded"]),
                             "a monotonically climbing RSS must be flagged as a leak")


if __name__ == "__main__":
    unittest.main(verbosity=2)
