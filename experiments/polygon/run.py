#!/usr/bin/env python3
# Viaticum Polygon — L1 top-level orchestrator + entrypoint.
#
# WHY THIS MODULE EXISTS (intent / acceptance criteria — fixed before the code):
#   The polygon is a REUSABLE instrumented E2E proving ground, run MANY TIMES, not a
#   one-shot test. Ilya, before publishing, wants two questions answered against a
#   realistic fleet of REAL viaticum daemons under REAL process churn:
#     (1) does the daemon ever crash / lose data / wedge?  — HARD bug-freeness gate
#     (2) is the trust economy fair from a user's point of view? — SOFT characterizer
#   Every other polygon module owns one slice (archetypes, configs, the fleet
#   primitives, the churn schedule, the collector, the two oracles). THIS module is the
#   conductor: it reads one scenario JSON and walks the whole run end to end so the same
#   code drives any scenario any number of times, each into its own timestamped results
#   dir with a machine-readable verdict.
#
#   AC1 (one scenario in, one verdict out): `python3 run.py <scenario.json>` validates
#        the scenario, builds the fleet plan, runs it, and emits verdict.json (bug-free
#        PASS/FAIL) + fairness_report.json. Process exit code == 0 IFF bug-freeness PASS.
#        Fairness NEVER fails the run (it only characterizes — feeds the future 4R
#        economy redesign).
#   AC2 (fit the box, never silently truncate): before launching the real fleet the
#        orchestrator runs the mandatory warm-up RSS probe and caps N to fit the box,
#        logging the cap explicitly (feasibility.py owns the math; we just call it and
#        honor + log its decision).
#   AC3 (distinct masters / star = transport only): every node init's its OWN master
#        identity (fleet.init_node enforces this); the star connect is network bootstrap,
#        NOT a trust cluster. We never reuse a data-dir and never build a real cluster.
#   AC4 (ground-truth data-loss oracle): the restore ledger captures every honest file's
#        pre-backup content hash; at end of run we request a restore for each and compare
#        the restored bytes' hash to the original. Data loss is judged against the hash,
#        never the owner's optimistic view (exactly as local_delete_test.sh does).
#   AC5 (no gaps in the time series): the collector samples EVERY node every
#        sample_interval, recording status_ok=0 + the intended up/down state for a node
#        that is down, so the slope/leak oracles never see a gap they'd misread.
#   AC6 (--dry-run never starts a fleet): validation + the node plan are printed; no
#        process is launched. Used to sanity-check a scenario before burning a real run.
#
#   This module launches the fleet but introduces NO new daemon Rust. It is observe-only:
#   it spins up the unmodified daemon and reads it. Time is accelerated (cfg.time_scale)
#   while churn + the libp2p/mailbox network are ALWAYS real — the polygon exercises the
#   scaled mailbox poll path (the E1 fix) by construction, because it only runs under
#   time_scale > 1.
#
#   stdlib only (argparse, json, random, shutil, sys, time, traceback, pathlib).
#
# Usage:
#   ./rbuild.sh                                   # build ./target/release/viaticum first
#   python3 run.py scenarios/steady_fairness.json
#   python3 run.py scenarios/steady_fairness.json --dry-run
#   BINARY=/path/to/viaticum python3 run.py scenarios/x.json --results-base /tmp/poly

from __future__ import annotations

import argparse
import dataclasses
import random
import shutil
import sys
import time
import traceback
from pathlib import Path

# Sibling polygon modules. They live in the same directory; run.py is invoked from
# within experiments/polygon/ (or with that dir on sys.path), matching how the
# other modules import each other (flat `import common`, `from fleet import Fleet`).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import archetypes  # noqa: E402
import churn  # noqa: E402
import config_gen  # noqa: E402
import feasibility  # noqa: E402
import oracle_bug  # noqa: E402
import oracle_fair  # noqa: E402
from collector import Collector  # noqa: E402
from common import (  # noqa: E402
    results_dir,
    save_json,
    virtual_to_wall,
    wall_to_virtual,
)
from fleet import Fleet  # noqa: E402

# ----------------------------------------------------------------------------
# Scenario contract.
# ----------------------------------------------------------------------------

# Every scenario JSON must carry these keys (the architect's documented contract).
REQUIRED_SCENARIO_KEYS = (
    "id",
    "archetype_mix",
    "requested_nodes",
    "time_scale",
    "duration_virtual_days",
    "sample_interval_secs",
    "warmup_virtual_days",
    "churn",
    "seed",
    "source_block_size_mb",
)

# Cap on time_scale so the slowest cadence we rely on (weekly PoS, 604800 s) stays a
# few real seconds long; beyond this it pins at the daemon's .max(1) floor and stops
# accelerating (CPU burn, no extra virtual speed). Documented spec assumption.
MAX_SAFE_TIME_SCALE = 100_000

# How long to let the swarm settle / star fully form before the drive loop begins,
# independent of warmup_virtual_days (which is the daemon-internal economy warmup the
# oracles honor). A few real seconds for the connect storm to authenticate.
STAR_SETTLE_SECS = 5.0


# ----------------------------------------------------------------------------
# Logging.
# ----------------------------------------------------------------------------


class _Log:
    """Tee log: stdout + a run.log file under the results dir.

    Created stdout-only first (so feasibility/early errors are visible), then
    redirected to also append to results_dir/run.log once that dir exists.
    """

    def __init__(self) -> None:
        self._fh = None

    def attach_file(self, path: Path) -> None:
        try:
            self._fh = open(path, "a")
        except OSError:
            self._fh = None

    def __call__(self, msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        print(line, flush=True)
        if self._fh is not None:
            try:
                self._fh.write(line + "\n")
                self._fh.flush()
            except OSError:
                pass

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None


# ----------------------------------------------------------------------------
# Scenario loading + validation.
# ----------------------------------------------------------------------------


def load_scenario(path: str) -> dict:
    """Load + validate a scenario JSON. Raises ValueError on a missing/invalid key.

    Validates that every required key is present, that the archetype_mix references
    only known archetypes, and that the numeric knobs are in safe ranges (positive
    node count / duration / interval, time_scale within the accelerated-but-not-pinned
    band). Validation failing loud HERE is far better than a silent misconfiguration
    that the oracles later misread as a daemon bug.
    """
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"scenario file not found: {path}")
    with open(p) as fh:
        import json

        scenario = json.load(fh)
    if not isinstance(scenario, dict):
        raise ValueError("scenario must be a JSON object")

    missing = [k for k in REQUIRED_SCENARIO_KEYS if k not in scenario]
    if missing:
        raise ValueError(f"scenario missing required keys: {', '.join(missing)}")

    mix = scenario["archetype_mix"]
    if not isinstance(mix, dict) or not mix:
        raise ValueError("archetype_mix must be a non-empty object")
    unknown = [a for a in mix if a not in archetypes.ARCHETYPES]
    if unknown:
        raise ValueError(
            f"archetype_mix references unknown archetype(s): {', '.join(unknown)} "
            f"(known: {', '.join(sorted(archetypes.ARCHETYPES))})"
        )
    if any(float(w) < 0 for w in mix.values()):
        raise ValueError("archetype_mix weights must be >= 0")
    if float(sum(float(w) for w in mix.values())) <= 0:
        raise ValueError("archetype_mix weights must sum to a positive value")

    if int(scenario["requested_nodes"]) < 1:
        raise ValueError("requested_nodes must be >= 1")
    if float(scenario["time_scale"]) < 1:
        raise ValueError("time_scale must be >= 1 (the polygon only runs accelerated)")
    if float(scenario["time_scale"]) > MAX_SAFE_TIME_SCALE:
        raise ValueError(
            f"time_scale {scenario['time_scale']} exceeds MAX_SAFE_TIME_SCALE "
            f"{MAX_SAFE_TIME_SCALE}: cadences would pin at the .max(1) floor and stop "
            "accelerating. Lower time_scale."
        )
    if float(scenario["duration_virtual_days"]) <= 0:
        raise ValueError("duration_virtual_days must be > 0")
    if float(scenario["sample_interval_secs"]) <= 0:
        raise ValueError("sample_interval_secs must be > 0")
    if float(scenario["warmup_virtual_days"]) < 0:
        raise ValueError("warmup_virtual_days must be >= 0")
    block = int(scenario["source_block_size_mb"])
    if block < 1 or (block & (block - 1)) != 0:
        raise ValueError("source_block_size_mb must be a power of two >= 1")

    churn_specs = scenario["churn"]
    if not isinstance(churn_specs, (list, dict)):
        raise ValueError("churn must be a list (or single object) of churn specs")

    return scenario


# ----------------------------------------------------------------------------
# Node-plan construction.
# ----------------------------------------------------------------------------


def _build_node_plans(scenario: dict, n_using: int, rng: random.Random) -> list:
    """Expand the archetype_mix into n_using concrete NodePlans.

    Late-joiners (any archetype whose uptime_pattern is 'late_join', i.e. 'newcomer')
    get a join_virtual_day drawn deterministically inside the run window so the churn
    engine onboards them mid-run. Every other node joins at virtual day 0 (it is up
    from the start unless its own churn schedule / a scenario mass_depart takes it down).

    Each plan is decorated with the scenario-level source_block_size_mb
    (config_gen reads it off the plan when not threaded explicitly) and, after the
    config is rendered, with config_toml (fleet.join_node reads plan.config_toml for a
    mid-run fresh onboarding).
    """
    duration = int(scenario["duration_virtual_days"])
    pairs = archetypes.archetype_mix_to_labels(
        scenario["archetype_mix"], n_using, rng
    )

    plans = []
    for label, arch in pairs:
        spec = archetypes.ARCHETYPES[arch]
        if spec.uptime_pattern == "late_join":
            # Onboard somewhere in the first 60% of the run so there is time to observe
            # whether the newcomer can earn its way in (onboarding-fairness metric).
            join_day = max(1, int(round(rng.uniform(0.1, 0.6) * duration)))
        else:
            join_day = 0
        plan = archetypes.build_node_plan(label, arch, join_day, rng, scenario)
        # Thread scenario-level config knobs onto the plan for config_gen + fleet.
        setattr(plan, "source_block_size_mb", int(scenario["source_block_size_mb"]))
        plans.append(plan)
    return plans


def _render_and_record_config(fleet: Fleet, plan) -> str:
    """Render the config.toml for a plan, wiring the absolute watch path for any
    non-neutral importance node, and stash it on the plan + write it to disk.

    config_gen emits a [[watch]] block ONLY when importance_multiplier != 1.0, and that
    block's path comes from plan.watch_path (default 'files'). For those nodes the
    daemon is launched WITHOUT --watch-dir (importance_via_watchblock=True in fleet),
    so the [[watch]] path MUST be the absolute files dir or the daemon watches nothing.
    Neutral-importance nodes emit no [[watch]] block and rely on --watch-dir.
    """
    if abs(float(plan.importance_multiplier) - 1.0) > 1e-9:
        setattr(plan, "watch_path", str(fleet.files_dir(plan.label)))
    toml_text = config_gen.render_config_toml(
        plan,
        source_block_size_mb=int(getattr(plan, "source_block_size_mb")),
    )
    # fleet.join_node (mid-run onboarding) reads plan.config_toml to rebuild the config
    # for a freshly-init'd late joiner; record it now so the same text is reused.
    setattr(plan, "config_toml", toml_text)
    return toml_text


def _print_node_plan(plans: list, log) -> None:
    """Dry-run / provenance dump of the resolved node plan."""
    by_arch: dict[str, int] = {}
    for p in plans:
        by_arch[p.archetype] = by_arch.get(p.archetype, 0) + 1
    log(f"[plan] {len(plans)} nodes, archetype breakdown:")
    for arch in sorted(by_arch):
        log(f"[plan]   {arch:12s} x{by_arch[arch]}")
    late = [p for p in plans if int(p.join_virtual_day) > 0]
    if late:
        log(f"[plan] {len(late)} late-joiner(s):")
        for p in late:
            log(f"[plan]   {p.label} ({p.archetype}) joins at virtual day {p.join_virtual_day}")
    churning = [p for p in plans if p.churn_schedule]
    log(f"[plan] {len(churning)} node(s) with a per-archetype uptime churn schedule")


# ----------------------------------------------------------------------------
# Restore ledger (ground-truth data-loss oracle input).
# ----------------------------------------------------------------------------


def _final_restore_ledger(fleet: Fleet, ledger: list, log) -> dict:
    """At end of run, restore every honest backed-up file and compare its hash.

    WEAKER SIGNAL — tier-1/local-restore sanity, NOT the no-data-loss gate. The daemon's
    restore is by-design 2-tier (restore/mod.rs): it rebuilds a file from the owner's
    LOCAL source first and only fetches from holders if the source is gone. In the polygon
    the watch-dir source is ALWAYS present, so this path ALWAYS uses tier-1 (local) and
    never validates the network copy — a node that placed zero blocks still "restores ok".
    The TRUE no-data-loss ground truth is _dr_recover_subset (wipe + recover from holders);
    this function only confirms the local restore pipeline + staging works end to end.

    `ledger` entries are dicts {label, path, hash, name}. For each, request a restore on
    the owning node, poll for the staged file under <data_dir>/restore/, hash it, and
    compare to the pre-backup original. A node that is DOWN at end of run is restarted
    first (a restore needs a live daemon). Returns a restore-results dict.

    Data loss is judged against the recorded content hash — never the owner's optimistic
    view (mirrors local_delete_test.sh's ground-truth assertion style).
    """
    import hashlib

    results = {
        "total": len(ledger),
        "restored_ok": 0,
        "hash_mismatch": 0,
        "not_found": 0,
        "entries": [],
    }
    # Group by owning node so we restart each down owner at most once.
    owners = sorted({e["label"] for e in ledger})
    for label in owners:
        if not fleet.is_up(label):
            log(f"[restore] owner {label} is down — restarting for end-of-run restore")
            fleet.restart_node(label, [str(fleet.files_dir(label))])

    for entry in ledger:
        label = entry["label"]
        orig_path = entry["path"]
        want_hash = entry["hash"]
        name = entry["name"]
        fleet.request_restore(label, orig_path)

        restored_path = None
        # Restore is async; poll generously (encode/fetch under acceleration is fast,
        # but a churned holder set may need a repair round first).
        for _ in range(60):
            restored_path = fleet.find_restored(label, name)
            if restored_path is not None:
                break
            time.sleep(2.0)

        rec = {"label": label, "name": name, "want_hash": want_hash}
        if restored_path is None:
            results["not_found"] += 1
            rec["status"] = "not_found"
            log(f"[restore] FAIL {label}/{name}: restored file never appeared")
        else:
            got_hash = _hash_file(restored_path, hashlib.md5)
            rec["got_hash"] = got_hash
            if got_hash == want_hash:
                results["restored_ok"] += 1
                rec["status"] = "ok"
            else:
                results["hash_mismatch"] += 1
                rec["status"] = "hash_mismatch"
                log(f"[restore] FAIL {label}/{name}: hash mismatch "
                    f"want={want_hash[:12]} got={got_hash[:12]}")
        results["entries"].append(rec)

    log(f"[restore] {results['restored_ok']}/{results['total']} restored & hash-matched, "
        f"{results['hash_mismatch']} mismatch, {results['not_found']} not found")
    return results


def _hash_file(path: Path, hasher_factory) -> str:
    h = hasher_factory()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ----------------------------------------------------------------------------
# DR-subset network-recoverability check (the TRUE no-data-loss ground truth).
# ----------------------------------------------------------------------------


def _dr_recover_subset(fleet: Fleet, ledger: list, seed_label: str, log, k: int = 2) -> dict:
    """Wipe k nodes entirely and recover their files FROM HOLDERS via disaster recovery.

    This is the load-bearing no-data-loss ground truth. `_final_restore_ledger` is a
    WEAKER signal: the daemon's restore is by-design 2-tier (restore/mod.rs) — it rebuilds
    a file from the owner's LOCAL source first and only fetches from holders if the source
    is gone. In the polygon the watch-dir source is ALWAYS present, so a plain restore
    always uses tier-1 (local) and never validates the network copy; a node that placed
    ZERO blocks still "restores ok". A full data-dir wipe deletes the source too, so the
    post-DR restore is FORCED down tier-2 (fetch symbols from holders, decode) — true
    network recovery.

    Victim choice (so there is something on holders to recover): HONEST (archetype !=
    free_rider), NON-seed (the seed stays live as the DR --peer bootstrap), currently UP,
    not churned-down, and actually placed (placement_alive > 0 in a fresh status sample).
    We pick up to k such victims, preferring those with the most live placements.

    For each victim: collect its ledger files' original hashes, dr_recover() (wipe + dr +
    relaunch), then request a restore per file (now forced to fetch from holders), locate
    the recovered bytes, hash (md5, same as seeding/_final_restore_ledger), compare. Writes
    a dr_results dict shaped like restore_results PLUS a dr_victims list.
    """
    import hashlib

    results = {
        "dr_victims": [],
        "total": 0,
        "restored_ok": 0,
        "hash_mismatch": 0,
        "not_found": 0,
        "entries": [],
    }

    # Group ledger entries by owning node (only owners with files are recoverable).
    by_owner: dict[str, list] = {}
    for e in ledger:
        by_owner.setdefault(e["label"], []).append(e)

    seed_addr = fleet.get_addr(seed_label)
    if not seed_addr:
        log(f"[dr] cannot resolve seed {seed_label} addr — DR subset skipped")
        return results

    # Candidate victims: honest, non-seed, up, with files, that actually placed.
    index = fleet.node_index()
    candidates = []
    plans = getattr(fleet, "_plans", {})
    for label, entries in by_owner.items():
        if label == seed_label:
            continue
        # Archetype from node_index, falling back to the launch plan (free-riders hold
        # ~nothing for others, so wiping one would prove nothing — skip them).
        archetype = (index.get(label) or {}).get("archetype", "")
        if not archetype:
            archetype = getattr(plans.get(label), "archetype", "")
        if archetype == "free_rider":
            continue
        if not fleet.is_up(label):
            continue
        st = fleet.status_json(label) or {}
        placement_alive = int(st.get("placement_alive", 0) or 0)
        blocks_ok = int(st.get("blocks_ok", 0) or 0)
        if placement_alive <= 0 and blocks_ok <= 0:
            continue  # nothing on holders to recover — DR would prove nothing
        candidates.append((placement_alive, blocks_ok, label, entries))

    # Prefer the most-placed victims (strongest ground truth), deterministic on label.
    candidates.sort(key=lambda c: (c[0], c[1], c[2]), reverse=True)
    victims = candidates[: max(0, int(k))]

    if not victims:
        log("[dr] no eligible DR victim (honest, up, non-seed, with live placements) — "
            "DR subset produced no ground truth")
        return results

    log(f"[dr] DR subset: wiping + recovering {len(victims)} node(s) from holders via "
        f"seed {seed_label} ({seed_addr})")

    # NOTE (known limitation, low-risk at k=2): victims are wiped+recovered sequentially.
    # In the polygon every node holds symbols for every other node, and `dr` restores only
    # a node's OWN pointer/metadata — NOT the foreign symbols it was holding. So once
    # victim #1 is wiped it no longer holds victim #2's symbols, shrinking #2's holder set
    # by one. With erasure redundancy (multiple holders/block) and k=2 this is tolerable;
    # under a churned/low-redundancy holder set it could turn a recoverable file into a
    # spurious not_found. If k grows or runs get churn-heavy, pick victims that are not
    # each other's holders, or wipe-recover-verify strictly one at a time before the next.
    for placement_alive, blocks_ok, label, entries in victims:
        results["dr_victims"].append(
            {"label": label, "placement_alive": placement_alive, "blocks_ok": blocks_ok}
        )
        log(f"[dr] victim {label}: placement_alive={placement_alive} blocks_ok={blocks_ok}, "
            f"{len(entries)} file(s)")

        ok = fleet.dr_recover(label, peer_addr=seed_addr)
        if not ok:
            # DR itself failed: every file of this victim is unrecoverable from the network.
            for entry in entries:
                results["total"] += 1
                results["not_found"] += 1
                results["entries"].append(
                    {
                        "label": label,
                        "name": entry["name"],
                        "want_hash": entry["hash"],
                        "status": "not_found",
                        "detail": "dr command failed",
                    }
                )
            log(f"[dr] FAIL {label}: disaster recovery did not complete — files unrecoverable")
            continue

        for entry in entries:
            results["total"] += 1
            name = entry["name"]
            want_hash = entry["hash"]
            # Source file is GONE (wiped) -> this restore is forced down tier-2 (holders).
            fleet.request_restore(label, entry["path"])

            recovered = None
            for _ in range(90):
                recovered = fleet.find_dr_recovered(label, name)
                if recovered is not None:
                    break
                time.sleep(2.0)

            rec = {"label": label, "name": name, "want_hash": want_hash}
            if recovered is None:
                results["not_found"] += 1
                rec["status"] = "not_found"
                log(f"[dr] FAIL {label}/{name}: file never recovered from holders")
            else:
                got_hash = _hash_file(recovered, hashlib.md5)
                rec["got_hash"] = got_hash
                if got_hash == want_hash:
                    results["restored_ok"] += 1
                    rec["status"] = "ok"
                else:
                    results["hash_mismatch"] += 1
                    rec["status"] = "hash_mismatch"
                    log(f"[dr] FAIL {label}/{name}: hash mismatch after DR "
                        f"want={want_hash[:12]} got={got_hash[:12]}")
            results["entries"].append(rec)

    log(f"[dr] DR subset: {results['restored_ok']}/{results['total']} recovered from holders "
        f"& hash-matched, {results['hash_mismatch']} mismatch, {results['not_found']} not found "
        f"(victims: {[v['label'] for v in results['dr_victims']]})")
    return results


# ----------------------------------------------------------------------------
# The run.
# ----------------------------------------------------------------------------


def _run_scenario(scenario: dict, rdir: Path, binary_arg, log) -> dict:
    """Stand up the fleet, drive it, restore-verify, tear down. Returns a run summary.

    The flow mirrors the architecture spec's drive loop exactly:
      1. resolve binary (fleet exits if missing)
      2. warm-up RSS probe -> N_cap -> using N (logged, never silently truncated)
      3. build node plans for the using-N fleet (distinct masters), render configs,
         seed watch dirs (capturing the restore ledger)
      4. launch the day-0 fleet, star-connect, verify the seed sees the others
      5. star settle, then the drive loop: every sample_interval the collector samples
         all nodes while the churn engine applies due kill/restart/join events; the
         orchestrator's wall clock maps to virtual time via common.virtual_to_wall
      6. end-of-run restore ledger (tier-1/local restore sanity — NOT the data-loss gate)
      6b. DR subset: wipe a few honest nodes and recover FROM HOLDERS (the TRUE no-data-loss
          ground truth — forces the daemon's tier-2 network fetch, which the watch-dir-source
          tier-1 restore in step 6 never exercises)
      7. teardown (stderr panic scan BEFORE any -9), keeping the results dir
    """
    time_scale = float(scenario["time_scale"])
    fleet = Fleet(rdir, int(time_scale), log)
    fleet.resolve_binary(binary_arg)

    # ── 2. warm-up RSS probe + N-cap ─────────────────────────────────────────
    requested_n = int(scenario["requested_nodes"])
    probe_dir = rdir / "_probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    try:
        peak_rss_mb = feasibility.probe_peak_rss(
            fleet.binary, scenario, probe_dir, log
        )
    except Exception as exc:  # the probe failing is fatal — a box that can't run one
        log(f"[run] FATAL warm-up probe failed: {exc}")
        log(traceback.format_exc())
        raise
    n_cap = feasibility.compute_n_cap(peak_rss_mb)
    n_using = feasibility.cap_and_log(requested_n, n_cap, log, peak_rss_mb=peak_rss_mb)

    # ── 3. node plans + configs + seeded data ────────────────────────────────
    plan_rng = random.Random(int(scenario["seed"]) & 0xFFFFFFFF)
    plans = _build_node_plans(scenario, n_using, plan_rng)
    _print_node_plan(plans, log)

    # Day-0 nodes are everything that is up at virtual day 0 (join_virtual_day == 0);
    # late-joiners are init'd/launched mid-run by the churn engine via fleet.join_node.
    day0_plans = [p for p in plans if int(p.join_virtual_day) == 0]
    late_plans = {p.label: p for p in plans if int(p.join_virtual_day) > 0}

    for plan in plans:
        fleet.set_plan(plan.label, plan)

    # Content RNG separate from the plan RNG so file CONTENT is reproducible per label
    # without perturbing the plan/churn stream.
    content_rng = random.Random((int(scenario["seed"]) ^ 0xC0FFEE) & 0xFFFFFFFF)
    restore_ledger: list = []

    log(f"[run] initializing {len(day0_plans)} day-0 nodes (distinct masters)...")
    for plan in day0_plans:
        fleet.init_node(plan.label)
        toml_text = _render_and_record_config(fleet, plan)
        fleet.write_config(plan.label, toml_text)
        # Seed the watch dir with the planned files and record the ground-truth hashes.
        files_dir = fleet.files_dir(plan.label)
        for path, digest in config_gen.seed_watch_dir(files_dir, plan, content_rng):
            restore_ledger.append(
                {
                    "label": plan.label,
                    "path": str(path),
                    "hash": digest,
                    "name": Path(path).name,
                }
            )
    # Render configs for late joiners too (config_toml is stashed on the plan now so
    # fleet.join_node can reuse it mid-run); their files are seeded at join time below.
    for plan in late_plans.values():
        _render_and_record_config(fleet, plan)

    save_json(rdir / "restore_ledger.json", restore_ledger)

    # ── 4. launch day-0 fleet + star-connect ─────────────────────────────────
    log(f"[run] launching {len(day0_plans)} daemons under time_scale={int(time_scale)}...")
    for plan in day0_plans:
        importance = abs(float(plan.importance_multiplier) - 1.0) > 1e-9
        fleet.launch_node(
            plan.label, [str(fleet.files_dir(plan.label))],
            importance_via_watchblock=importance,
        )

    ready = 0
    for plan in day0_plans:
        if fleet.wait_ready(plan.label, timeout_s=90):
            ready += 1
        else:
            log(f"[run] WARN {plan.label} not ready after 90s")
    log(f"[run] {ready}/{len(day0_plans)} day-0 daemons ready")
    if ready == 0:
        raise RuntimeError("no day-0 daemon became ready — aborting run")

    seed_label = day0_plans[0].label
    members = [p.label for p in day0_plans[1:]]
    ok = fleet.star_connect(seed_label, members)
    log(f"[run] star-connect: {ok}/{len(members)} members reached seed {seed_label}")

    # A star-connect only authenticates the SEED on each spoke. Placement needs each node
    # to know several HOLDER candidates, which the daemon discovers + dials via Kademlia
    # (dial_discovered_peer) — but that takes time. Without waiting, spokes start backup
    # knowing ~1 peer and place NOTHING (only the hub, which sees everyone, places) → the
    # whole run is degenerate. Block until every day-0 node authenticates a quorum.
    # Kademlia bootstrap + per-peer cert-exchange is REAL-time work (~4 min for ~40 nodes)
    # that time_scale does NOT compress, so the gate must out-wait it before the (compressed)
    # virtual-time drive begins — otherwise the drive runs against an unconverged network.
    _wait_for_discovery(fleet, [p.label for p in day0_plans],
                        target=min(8, len(day0_plans) - 1), timeout_s=600.0, log=log)

    # ── 5. drive loop ────────────────────────────────────────────────────────
    fleet_start_wall = time.time()
    churn_queue = churn.build_event_queue(plans, scenario, fleet_start_wall)
    churn.write_churn_log(rdir / "churn_log.json", churn_queue)
    log(f"[run] churn queue: {len(churn_queue)} event(s)")

    collector = Collector(fleet, churn_queue, scenario, rdir)

    duration_days = float(scenario["duration_virtual_days"])
    run_wall_secs = virtual_to_wall(duration_days, time_scale)
    sample_interval = float(scenario["sample_interval_secs"])
    log(f"[run] driving for ~{run_wall_secs:.0f}s wall "
        f"(= {duration_days} virtual days @ time_scale {int(time_scale)}); "
        f"sampling every {sample_interval}s")

    # Let the star fully authenticate before the first sample / any churn.
    time.sleep(STAR_SETTLE_SECS)

    tick = 0
    last_wall = 0.0  # wall-secs-since-fleet-start of the previous churn check
    deadline = fleet_start_wall + run_wall_secs
    while True:
        now = time.time()
        now_rel = now - fleet_start_wall
        if now >= deadline:
            break

        # Apply any churn events that fell due in (last_wall, now] (absolute wall time).
        due = churn.due_events(churn_queue, now, fleet_start_wall + last_wall)
        for ev in due:
            _apply_churn_event(fleet, ev, late_plans, seed_label, content_rng,
                               restore_ledger, rdir, log)
        last_wall = now_rel

        # Sample every node (down nodes recorded status_ok=0 with their intended state).
        try:
            collector.sample(tick, now_rel)
        except Exception:
            log("[run] WARN collector.sample raised:\n" + traceback.format_exc())

        vday = wall_to_virtual(now_rel, time_scale)
        if tick % 10 == 0:
            up = sum(1 for p in plans if fleet.is_up(p.label))
            log(f"[run] tick {tick} | virtual_day {vday:.2f} | {up} nodes up "
                f"| {len(due)} churn event(s) applied")
        tick += 1

        # Sleep to the next sample boundary (account for sampling time already spent).
        elapsed = time.time() - now
        sleep_for = sample_interval - elapsed
        if sleep_for > 0:
            time.sleep(sleep_for)

    # Final sample at the run boundary so the time series covers the full window.
    final_rel = time.time() - fleet_start_wall
    try:
        collector.sample(tick, final_rel)
    except Exception:
        log("[run] WARN final collector.sample raised:\n" + traceback.format_exc())
    collector.finalize()
    log(f"[run] drive loop complete: {tick + 1} sample tick(s)")

    # ── 6. end-of-run restore ledger (tier-1 local-restore sanity, NOT the gate) ─
    log("[run] requesting end-of-run restores (tier-1/local sanity signal)...")
    restore_results = _final_restore_ledger(fleet, restore_ledger, log)
    save_json(rdir / "restore_results.json", restore_results)

    # ── 6b. DR subset (TRUE no-data-loss ground truth: recover FROM HOLDERS) ──
    # Must run while the seed + holders are still UP (before teardown). A few honest
    # nodes lose their whole data-dir and rebuild from the network — the only signal
    # that proves the network copy is real (tier-1 above never touches holders).
    log("[run] DR subset: wiping a few honest nodes and recovering FROM HOLDERS "
        "(the true no-data-loss ground truth)...")
    dr_results = _dr_recover_subset(fleet, restore_ledger, seed_label, log, k=2)
    save_json(rdir / "dr_results.json", dr_results)

    # ── 7. teardown (panic scan BEFORE any -9) ───────────────────────────────
    td = fleet.teardown(scan_first=True)
    save_json(rdir / "stderr_scans.json", td.get("scans", {}))

    return {
        "n_requested": requested_n,
        "n_cap": n_cap,
        "n_using": n_using,
        "peak_rss_mb": peak_rss_mb,
        "ticks": tick + 1,
        "ready_day0": ready,
        "star_connected": ok,
        "restore": {
            "total": restore_results["total"],
            "restored_ok": restore_results["restored_ok"],
            "hash_mismatch": restore_results["hash_mismatch"],
            "not_found": restore_results["not_found"],
        },
        "dr": {
            "victims": [v["label"] for v in dr_results.get("dr_victims", [])],
            "total": dr_results["total"],
            "restored_ok": dr_results["restored_ok"],
            "hash_mismatch": dr_results["hash_mismatch"],
            "not_found": dr_results["not_found"],
        },
        "teardown": {k: td[k] for k in ("terminated", "killed") if k in td},
    }


def _wait_for_discovery(fleet, labels, target, timeout_s, log):
    """Block until every node authenticates >= target peers (enough holder candidates to
    place), or timeout. A star-connect authenticates only the seed; the daemon learns +
    dials the rest via Kademlia, which needs time. Polls peer_count_authenticated."""
    target = max(1, int(target))
    start = time.time()
    while True:
        counts = {}
        for lab in labels:
            st = fleet.status_json(lab) or {}
            counts[lab] = int(st.get("peer_count_authenticated",
                                    st.get("peer_count", 0)) or 0)
        worst = min(counts.values()) if counts else 0
        n_ok = sum(1 for v in counts.values() if v >= target)
        elapsed = time.time() - start
        if worst >= target:
            log(f"[discovery] all {len(labels)} nodes >= {target} authenticated peers "
                f"(worst={worst}) in {elapsed:.0f}s")
            return
        if elapsed >= timeout_s:
            laggards = {k: v for k, v in sorted(counts.items()) if v < target}
            log(f"[discovery] WARN timeout {timeout_s:.0f}s: {n_ok}/{len(labels)} nodes "
                f"reached {target} authenticated peers; laggards={laggards}")
            return
        log(f"[discovery] {n_ok}/{len(labels)} nodes >= {target} peers "
            f"(worst={worst}); waiting... ({elapsed:.0f}s)")
        time.sleep(8.0)


def _apply_churn_event(fleet, ev, late_plans, seed_label, content_rng,
                       restore_ledger, rdir, log) -> None:
    """Apply one due ChurnEvent to the live fleet.

    'kill'/'mass_depart' -> SIGTERM the targets (kept restartable on the same data-dir).
    'restart' -> relaunch a previously-killed node on its SAME data-dir + reconnect.
    'join' -> if the target is a known late-joiner not yet launched, full fresh
        onboarding (init distinct master, config, launch, star-connect) and seed +
        ledger its files; if it was a previously-down always-node, treat as a restart.
    """
    for label in ev.targets:
        if ev.event_type in ("kill", "mass_depart"):
            if fleet.is_up(label):
                fleet.kill_node(label)
                log(f"[churn] killed {label} (event {ev.event_type} @ vday {ev.virtual_day:.2f})")
        elif ev.event_type == "restart":
            fleet.restart_node(label, [str(fleet.files_dir(label))])
            log(f"[churn] restarted {label} (@ vday {ev.virtual_day:.2f})")
        elif ev.event_type == "join":
            plan = late_plans.get(label)
            if plan is not None and not _has_launched(fleet, label):
                pid = fleet.join_node(label, plan, seed_label)
                if pid:
                    # Seed the late joiner's owned data + extend the restore ledger.
                    files_dir = fleet.files_dir(label)
                    for path, digest in config_gen.seed_watch_dir(
                        files_dir, plan, content_rng
                    ):
                        restore_ledger.append(
                            {
                                "label": label,
                                "path": str(path),
                                "hash": digest,
                                "name": Path(path).name,
                            }
                        )
                    save_json(rdir / "restore_ledger.json", restore_ledger)
                    log(f"[churn] onboarded newcomer {label} "
                        f"(@ vday {ev.virtual_day:.2f}, pid {pid})")
                else:
                    log(f"[churn] WARN newcomer {label} failed to onboard")
            else:
                # A non-late-join target told to come up = a restart of a down node.
                fleet.restart_node(label, [str(fleet.files_dir(label))])
                log(f"[churn] (re)started {label} via join event (@ vday {ev.virtual_day:.2f})")


def _has_launched(fleet, label) -> bool:
    """True if the fleet has ever launched this label (proc map has an entry)."""
    return label in getattr(fleet, "_procs", {})


# ----------------------------------------------------------------------------
# Entrypoint.
# ----------------------------------------------------------------------------


def _parse_args(argv) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="run.py",
        description="Viaticum polygon orchestrator: run one scenario end to end.",
    )
    ap.add_argument("scenario", help="path to the scenario JSON")
    ap.add_argument(
        "--results-base",
        default="experiments/polygon/results",
        help="base dir for the timestamped results dir (default: experiments/polygon/results)",
    )
    ap.add_argument(
        "--binary",
        default=None,
        help="path to the viaticum binary (else BINARY env, else ./target/release/viaticum)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the scenario and print the node plan; launch NO fleet",
    )
    return ap.parse_args(argv)


def main() -> int:
    """Orchestrate L1-L4 for one scenario. Returns exit code = 0 IFF bug-free PASS."""
    args = _parse_args(sys.argv[1:])
    log = _Log()

    # --- validate scenario (loud failure beats a silent misconfiguration) ---
    try:
        scenario = load_scenario(args.scenario)
    except (ValueError, OSError) as exc:
        log(f"[run] scenario invalid: {exc}")
        return 2

    scenario_id = str(scenario["id"])

    # --- dry-run: validate + print the plan, launch nothing ---
    if args.dry_run:
        log(f"[run] DRY RUN scenario '{scenario_id}' — no fleet will be launched")
        rng = random.Random(int(scenario["seed"]) & 0xFFFFFFFF)
        # In a dry run we cannot RSS-probe; show the plan at the REQUESTED N so the
        # operator sees the full intended population (the real run caps it to fit).
        plans = _build_node_plans(scenario, int(scenario["requested_nodes"]), rng)
        _print_node_plan(plans, log)
        log("[run] dry run complete (no daemons launched, no oracles run).")
        return 0

    # --- real run: timestamped results dir + provenance copy of the scenario ---
    rdir = results_dir(args.results_base, scenario_id)
    log.attach_file(rdir / "run.log")
    log(f"[run] scenario '{scenario_id}' -> results dir {rdir}")
    try:
        shutil.copy2(args.scenario, rdir / "scenario.json")
    except OSError as exc:
        log(f"[run] WARN could not copy scenario for provenance: {exc}")
        # Fall back to writing the parsed scenario so provenance is never lost.
        save_json(rdir / "scenario.json", scenario)

    summary = None
    run_error = None
    try:
        summary = _run_scenario(scenario, rdir, args.binary, log)
        save_json(rdir / "run_summary.json", summary)
    except Exception as exc:  # any orchestration failure must still try the oracles
        run_error = str(exc)
        log(f"[run] ERROR during run: {exc}")
        log(traceback.format_exc())
        save_json(rdir / "run_error.json", {"error": run_error,
                                            "traceback": traceback.format_exc()})

    # --- oracles: bug-freeness (HARD gate) + fairness (SOFT characterizer) ---
    bugfree = False
    try:
        bugfree = bool(oracle_bug.run(rdir))
    except Exception:
        log("[run] ERROR oracle_bug raised:\n" + traceback.format_exc())
        bugfree = False
    try:
        oracle_fair.run(rdir)
    except Exception:
        # Fairness NEVER fails the run; a fairness oracle crash is logged, not fatal.
        log("[run] WARN oracle_fair raised (non-fatal):\n" + traceback.format_exc())

    # --- operator summary line ---
    verdict_path = rdir / "verdict.json"
    fairness_path = rdir / "fairness_report.json"
    log("")
    log("============================================================")
    if run_error is not None:
        log(f"  RUN ERROR: {run_error}")
    _summarize_verdict(verdict_path, fairness_path, bugfree, log)
    _summarize_dr(rdir / "dr_results.json", log)
    log(f"  results dir: {rdir}")
    log("============================================================")
    log.close()

    # Exit code is 0 IFF bug-freeness passed (fairness is characterized, never gating).
    # An orchestration error that prevented the run also yields a non-zero exit.
    if run_error is not None:
        return 1
    return 0 if bugfree else 1


def _summarize_verdict(verdict_path: Path, fairness_path: Path, bugfree: bool, log) -> None:
    """Print the BUG-FREENESS and FAIRNESS one-liners the operator reads on stdout."""
    checks_line = ""
    try:
        from common import load_json

        if verdict_path.is_file():
            v = load_json(verdict_path)
            checks = (v.get("bugfree") or {}).get("checks") or []
            passed = sum(1 for c in checks if c.get("passed"))
            checks_line = f" ({passed}/{len(checks)} hard checks)" if checks else ""
    except Exception:
        checks_line = ""
    log(f"  BUG-FREENESS: {'PASS' if bugfree else 'FAIL'}{checks_line}")
    # Surface any check that PASSED its boolean but could not actually prove its property
    # (e.g. no-data-loss with no DR ground truth → tier-1 fallback). A "PASS but
    # inconclusive" run must not read as a clean green to whoever scans this summary.
    try:
        from common import load_json

        if verdict_path.is_file():
            incon = (load_json(verdict_path).get("bugfree") or {}).get("inconclusive") or []
            if incon:
                log(f"  ⚠ INCONCLUSIVE (passed but unproven): {', '.join(incon)}")
    except Exception:
        pass

    findings_line = "report not written"
    try:
        from common import load_json

        if fairness_path.is_file():
            fr = load_json(fairness_path)
            findings = fr.get("findings")
            if isinstance(findings, list):
                findings_line = f"{len(findings)} finding(s)"
            elif isinstance(fr, dict) and "findings_count" in fr:
                findings_line = f"{fr['findings_count']} finding(s)"
            else:
                findings_line = "report written"
    except Exception:
        findings_line = "report unreadable"
    log(f"  FAIRNESS: {findings_line} (see {fairness_path.name})")


def _summarize_dr(dr_path: Path, log) -> None:
    """Print the DR-subset (true network recoverability) one-liner for the operator.

    This is the load-bearing no-data-loss signal: a SAMPLE of k nodes that lost their
    whole data-dir and recovered every file FROM HOLDERS. Tier-1 local restore
    (restore_results.json) is the separate, weaker signal.
    """
    try:
        from common import load_json

        if not dr_path.is_file():
            log("  DR-RECOVERY: not run (no dr_results.json)")
            return
        dr = load_json(dr_path)
        victims = [v.get("label") for v in (dr.get("dr_victims") or [])]
        total = int(dr.get("total", 0) or 0)
        ok = int(dr.get("restored_ok", 0) or 0)
        mism = int(dr.get("hash_mismatch", 0) or 0)
        nf = int(dr.get("not_found", 0) or 0)
        if total == 0:
            log(f"  DR-RECOVERY: INCONCLUSIVE (no eligible victim; victims={victims})")
            return
        status = "PASS" if (mism == 0 and nf == 0) else "FAIL"
        log(f"  DR-RECOVERY: {status} — {ok}/{total} files recovered from holders "
            f"({mism} mismatch, {nf} not found); victims={victims}")
    except Exception:
        log("  DR-RECOVERY: report unreadable")


if __name__ == "__main__":
    sys.exit(main())
