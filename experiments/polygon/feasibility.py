"""Viaticum Polygon — L1 warm-up RSS probe + N-cap computation.

WHY THIS MODULE EXISTS (intent / acceptance criteria — fixed before the code):
  The polygon spins up a fleet of REAL viaticum daemons on a 64 GB box. North-star
  property (1) is BUG-FREENESS, and the single most common way to manufacture a FALSE
  "crash" is to launch more concurrent daemons than RAM can hold — the box OOM-kills a
  daemon mid-run and the bug oracle reports a spurious failure. So before the real
  fleet launches we MUST measure how heavy ONE daemon actually is under load and cap N
  to fit the box.

  AC1 (mandatory probe): we never guess RSS. We launch a tiny representative fleet of
       the HEAVIEST archetype, actually drive it (star-connect, push one file each, let
       PoS rounds fire so encode/holding/mailbox work is in flight), and sample real
       resident memory at the peak — MAX over repeated samples, not a single reading.
  AC2 (fit the box): N_cap is derived from /proc/meminfo MemTotal minus a fixed OS/IO
       reserve, divided by peak per-node RSS times a safety headroom factor. It reads
       the REAL machine, not a hard-coded 64 GB.
  AC3 (never silently truncate): if the scenario requested more nodes than fit, we
       reduce to N_cap and LOG the reduction explicitly (requested / peak_rss / usable /
       reserve / N_cap / using). A run that quietly shrank the fleet without a log line
       is a bug — the operator must see the cap.
  AC4 (leave the box clean): the warm-up fleet is always torn down, even on error, so
       the probe does not leak daemons into the real run.

This module is OBSERVE-ONLY: it launches the unmodified daemon via fleet.py primitives
and reads ps RSS. It introduces no new daemon code.

stdlib only. Depends on fleet.py (launch/connect/measure/teardown), config_gen.py
(render_config_toml/seed_watch_dir), and archetypes.py (ARCHETYPES/build_node_plan).
"""

import dataclasses
import math
import random
import time
import traceback
from pathlib import Path

from archetypes import ARCHETYPES, build_node_plan
import config_gen
from fleet import Fleet


# Default OS / page-cache / IO reserve held back from MemTotal, in MB.
DEFAULT_RESERVE_MB = 8000
# Safety headroom multiplier applied to measured peak RSS. A daemon's RSS grows as it
# accrues holdings/peers over a long run, and encodes spike transiently, so we budget
# 1.3x the warm-up peak per node.
DEFAULT_HEADROOM = 1.3
# How many representative daemons the warm-up launches (capped by requested N).
WARMUP_NODES = 6
# Hard floor so a tiny box / tiny scenario never computes N_cap = 0.
MIN_N_CAP = 2


def _single_file_plan(plan):
    """A copy of `plan` reduced to its first watch file (probe seeds only one file).

    Uses dataclasses.replace so it works on the NodePlan dataclass regardless of which
    module defines it — no coupling to common.NodePlan's constructor signature.
    """
    one = plan.watch_files[:1] or list(plan.watch_files)
    return dataclasses.replace(plan, watch_files=one, churn_schedule=[])


def _heaviest_archetype(scenario):
    """Pick the archetype expected to use the most RAM for the warm-up probe.

    The polygon caps N to the WORST case, so we probe the heaviest mix member. Heaviness
    is dominated by how much data a node encodes/holds, approximated by total seeded
    watch-dir bytes (watch_file_count * watch_file_size_bytes). The free-rider (tiny
    soft_quota) holds ~nothing for others but still encodes its own data, so own data
    size is the right proxy. Ties broken by file count (more files = more source blocks).
    """
    mix = scenario.get("archetype_mix", {})
    # Restrict to archetypes actually present in the scenario; fall back to all known.
    names = [n for n in mix if n in ARCHETYPES] or list(ARCHETYPES.keys())

    def weight(name):
        spec = ARCHETYPES[name]
        own_bytes = spec.watch_file_count * spec.watch_file_size_bytes
        return (own_bytes, spec.watch_file_count)

    return max(names, key=weight)


def probe_peak_rss(binary, scenario, work_dir, log):
    """Launch a tiny representative fleet, drive it, return peak per-node RSS in MB.

    Steps (mirrors the real fleet launch so the measurement is representative):
      1. pick the heaviest archetype; build that many node plans (min(WARMUP_NODES, N)).
      2. init + config + launch each daemon in `work_dir` via Fleet primitives.
      3. star-connect members to the seed.
      4. seed each watch dir with one representative file (drives backup -> encode ->
         placement -> holding -> PoS).
      5. wait for PoS to actually fire (pos_total_challenges climbs on some node), so
         the sample captures encode/mailbox/holding work, not just an idle daemon.
      6. sample `ps -o rss=` 3x at 5 s spacing across all live nodes; take the MAX.
      7. tear down the warm-up fleet (always, even on error).

    Returns peak_rss_mb (float). If the warm-up cannot produce a live daemon at all,
    raises RuntimeError — the caller must not proceed to a real launch on a box where a
    single daemon will not even start.
    """
    requested_n = int(scenario.get("requested_nodes", WARMUP_NODES))
    n_warm = max(1, min(WARMUP_NODES, requested_n))
    arch = _heaviest_archetype(scenario)
    log(f"[probe] warm-up: {n_warm} nodes of heaviest archetype '{arch}'")

    warm_dir = Path(work_dir) / "warmup"
    warm_dir.mkdir(parents=True, exist_ok=True)
    fleet = Fleet(warm_dir, scenario.get("time_scale", 1), log)

    # A fresh seeded RNG so warm-up file SIZES repeat run-to-run (stdlib only). XORed
    # off the scenario seed so it does not collide with the real fleet's RNG stream.
    rng = random.Random((int(scenario.get("seed", 0)) ^ 0x5EED) & 0xFFFFFFFF)

    labels = [f"warm-{i:02d}" for i in range(n_warm)]
    # Each warm-up node's data-dir mirrors the standard fleet layout (<root>/<label>),
    # so the daemon's watch dir is <root>/<label>/files — the path we seed + the daemon
    # watches are the same path.
    peak_rss_mb = 0.0
    try:
        # ── launch each warm-up daemon ──────────────────────────────────────
        # entries: (label, plan, files_dir, pid)
        ready = []
        for label in labels:
            plan = build_node_plan(label, arch, join_virtual_day=0, rng=rng,
                                   scenario=scenario)
            fleet.init_node(label)
            fleet.write_config(label, config_gen.render_config_toml(plan))
            files_dir = warm_dir / label / "files"
            files_dir.mkdir(parents=True, exist_ok=True)
            pid = fleet.launch_node(
                label, [str(files_dir)],
                importance_via_watchblock=(plan.importance_multiplier != 1.0))
            if fleet.wait_ready(label, timeout_s=60):
                ready.append((label, plan, files_dir, pid))
            else:
                log(f"[probe] WARN {label} did not become ready")

        if not ready:
            raise RuntimeError("warm-up: no daemon became ready — cannot probe RSS")

        # ── star-connect members to the first ready node ────────────────────
        seed_label = ready[0][0]
        members = [r[0] for r in ready[1:]]
        if members:
            ok = fleet.star_connect(seed_label, members)
            log(f"[probe] star-connect: {ok}/{len(members)} members reached seed")

        # ── seed one representative file per node (drives the pipeline) ──────
        for (label, plan, files_dir, _pid) in ready:
            # Only the first planned file so the probe is quick but still exercises
            # encode/placement; the full file set is for the real run.
            one = _single_file_plan(plan)
            file_rng = random.Random(
                (int(scenario.get("seed", 0)) ^ (hash(label) & 0xFFFFFFFF)) & 0xFFFFFFFF)
            config_gen.seed_watch_dir(files_dir, one, file_rng)

        # ── wait for PoS to fire so the sample captures real work ───────────
        _wait_for_pos(fleet, [r[0] for r in ready], log, timeout_s=90)

        # ── sample RSS: 3 passes @ 5 s, take the MAX over all nodes/passes ──
        for pass_i in range(3):
            for (label, _plan, _fd, pid) in ready:
                if pid is None:
                    continue
                m = fleet.measure(label, pid)
                rss_kb = (m or {}).get("rss_kb", 0) or 0
                rss_mb = rss_kb / 1024.0
                if rss_mb > peak_rss_mb:
                    peak_rss_mb = rss_mb
            log(f"[probe] sample pass {pass_i + 1}/3: running peak_rss={peak_rss_mb:.1f} MB")
            if pass_i < 2:
                time.sleep(5)

        if peak_rss_mb <= 0.0:
            raise RuntimeError("warm-up: ps reported no RSS for any daemon")

        log(f"[probe] peak per-node RSS = {peak_rss_mb:.1f} MB "
            f"(heaviest archetype '{arch}', {len(ready)} live samples)")
        return peak_rss_mb
    finally:
        # Always tear down the warm-up fleet so it never leaks into the real run.
        try:
            fleet.teardown(scan_first=False)
        except Exception:
            log("[probe] WARN teardown raised:\n" + traceback.format_exc())


def _wait_for_pos(fleet, labels, log, timeout_s=90):
    """Block until any warm-up node reports pos_total_challenges > 0, or timeout.

    A daemon that has only just started is near-idle; its RSS underestimates the real
    run. PoS challenges firing means encode re-runs + mailbox round-trips are in flight,
    which is the memory regime the real fleet will live in. We do not REQUIRE PoS to
    fire (a short scenario or slow discovery may not reach it in 90 s) — we just give it
    a chance so the peak sample is honest.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for label in labels:
            st = fleet.status_json(label)
            if st and int(st.get("pos_total_challenges", 0) or 0) > 0:
                log(f"[probe] PoS firing on {label} "
                    f"(challenges={st.get('pos_total_challenges')})")
                return True
        time.sleep(3)
    log("[probe] PoS did not fire within warm-up window — sampling current RSS anyway")
    return False


def _mem_total_mb():
    """Read MemTotal from /proc/meminfo, in MB. Falls back to 0 if unavailable."""
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    # Format: "MemTotal:       65805868 kB"
                    parts = line.split()
                    kb = int(parts[1])
                    return kb / 1024.0
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def compute_n_cap(peak_rss_mb, reserve_mb=DEFAULT_RESERVE_MB, headroom=DEFAULT_HEADROOM):
    """Max concurrent daemons that fit the box.

      usable_mb = MemTotal - reserve_mb
      N_cap     = floor(usable_mb / (peak_rss_mb * headroom))

    Reads the REAL machine (MemTotal from /proc/meminfo), never a hard-coded 64 GB.
    Floored at MIN_N_CAP so a degenerate measurement never yields 0.
    """
    if peak_rss_mb <= 0.0:
        return MIN_N_CAP
    mem_total_mb = _mem_total_mb()
    usable_mb = mem_total_mb - reserve_mb
    if usable_mb <= 0.0:
        return MIN_N_CAP
    per_node = peak_rss_mb * max(headroom, 1.0)
    if per_node <= 0.0:
        return MIN_N_CAP
    return max(MIN_N_CAP, int(math.floor(usable_mb / per_node)))


def cap_and_log(requested_n, n_cap, log, *, peak_rss_mb=None,
                reserve_mb=DEFAULT_RESERVE_MB):
    """Return min(requested_n, n_cap) and LOG the decision in full.

    Always logs a single provenance line carrying requested / peak_rss / usable /
    reserve / N_cap / using, so the operator can see what the fleet was capped to. If
    the fleet was reduced, an explicit reduction line is logged in addition — the cap is
    NEVER applied silently.
    """
    mem_total_mb = _mem_total_mb()
    usable_mb = max(0.0, mem_total_mb - reserve_mb)
    using = min(requested_n, n_cap)
    peak_str = f"{peak_rss_mb:.1f}MB" if peak_rss_mb is not None else "n/a"
    log(
        f"[n-cap] requested N={requested_n}, peak_rss={peak_str}, "
        f"usable={usable_mb:.0f}MB, reserve={reserve_mb}MB, "
        f"N_cap={n_cap} -> using N={using}"
    )
    if using < requested_n:
        log(
            f"[n-cap] REDUCED fleet from requested {requested_n} to {using} "
            f"to fit the box (N_cap={n_cap}). NOT silently truncated."
        )
    return using
