"""L2: archetype model for the Viaticum polygon.

WHY THIS MODULE EXISTS (intent / acceptance criteria — fixed before the code):
  The polygon's two north-star properties (bug-freeness + fairness) are only
  meaningful against a POPULATION that looks like the real world. Experiment 13
  established six behavioural archetypes that the trust economy must be able to
  rank by genuine usefulness (Reliable > Weekend > Seasonal > Nomad > Hoarder ~
  Freeloader). This module is the SINGLE SOURCE OF TRUTH that turns each of those
  archetypes — plus the v1-only "passive free-rider" (config-only, no Rust) and a
  "newcomer" onboarding case — into concrete daemon config knobs and a churn
  schedule.

  AC1 (config fidelity): each archetype maps to plausible daemon knobs. Storage
       capacity is expressed as `soft_quota_gb` because the daemon computes
       effective_quota = min(soft_quota, disk_free - disk_reserve); the free-rider
       / hoarder GET-for-others ceiling MUST be capped via soft_quota, never via
       hard_quota (see spec assumption: hard_quota does not cap GET-for-others).
  AC2 (uptime fidelity): each archetype's `uptime_pattern` expands into a concrete
       list of (kill/restart, virtual_day) churn events that REPRODUCE the Exp-13
       availability profile (Weekend offline on weekdays, Seasonal offline in
       summer, Nomad random ON/OFF blocks, etc.), bounded by the scenario duration.
  AC3 (determinism): two runs with the same scenario['seed'] and the same label
       produce the SAME file sizes and the SAME churn schedule. All randomness is
       drawn from the caller-supplied `rng` (a seeded random.Random), never from
       the global random module or wall-clock.
  AC4 (no I/O): this module is pure data + functions. It launches no process,
       reads no daemon, touches no disk. config_gen.py renders the TOML and seeds
       the watch dir; churn.py timestamps the events; this module only DESCRIBES.

  NB: the "always"-uptime archetypes still emit ZERO churn events here — real
  process churn for them (if any) comes from scenario['churn'] mass_depart/join
  specs, expanded by churn.py, not from the per-archetype pattern.

This module conforms to the interface declared in the polygon architecture spec.
Python 3 stdlib only.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

# Imported for the NodePlan / churn-event shape only. common.py is the single
# source of truth for those dataclasses; we never redefine them here.
from common import NodePlan


# ─────────────────────────────────────────────────────────────────────────────
# Archetype specification
# ─────────────────────────────────────────────────────────────────────────────

# A virtual "week" is 7 days; a virtual "year" is 365 days. The churn-event
# expansion below works in these whole-day units. churn.py maps virtual_day ->
# wall-clock seconds via the scenario time_scale.
DAYS_PER_WEEK = 7
DAYS_PER_YEAR = 365

# Summer window for the Seasonal (student) archetype, in day-of-year terms:
# roughly June through August. The student is offline across this window each
# virtual year and online the rest of the time.
SEASONAL_SUMMER_START_DOY = 152  # ~Jun 1
SEASONAL_SUMMER_END_DOY = 243  # ~Aug 31

# Capacities. Storage capacity from Exp-13 is a PERCENTAGE of "full"; we anchor
# "full" at a generous soft_quota so that Reliable/Weekend/Seasonal/Nomad can act
# as real holders, while Hoarder (20%) and Freeloader (10%) are proportionally
# starved. The passive free-rider is starved to a near-zero quota (config-only
# adversary): it backs up its own data but holds almost nothing for others.
FULL_SOFT_QUOTA_GB = 2.0
FREE_RIDER_SOFT_QUOTA_GB = 0.001  # spec: free-rider == tiny soft_quota_gb

# Default per-node owned-data footprint. Kept small (tens of MB) so a ~100-node
# fleet fits the box and backups/PoS complete quickly under acceleration.
DEFAULT_WATCH_FILE_COUNT = 4
DEFAULT_WATCH_FILE_SIZE_BYTES = 4 * 1024 * 1024  # 4 MiB


@dataclass
class ArchetypeSpec:
    """Static description of one archetype's config + availability profile.

    soft_quota_gb / hard_quota_gb / disk_reserve_gb: daemon [storage] knobs.
        soft_quota_gb is the load-bearing GET-for-others ceiling.
    importance_multiplier: [[watch]] importance for this node's own data.
    watch_file_count / watch_file_size_bytes: shape of the node's owned data
        (config_gen seeds the actual bytes from the rng using these as targets).
    uptime_pattern: one of the six recognised patterns; expanded by
        build_node_plan into concrete churn events.
    """

    soft_quota_gb: float
    hard_quota_gb: float
    disk_reserve_gb: float
    importance_multiplier: float
    watch_file_count: int
    watch_file_size_bytes: int
    uptime_pattern: str


# The recognised uptime patterns. build_node_plan dispatches on these.
UPTIME_PATTERNS = frozenset(
    {"always", "periodic", "seasonal", "nomad", "vacationer", "late_join"}
)


# The archetype table. Keys are the canonical archetype names used everywhere in
# the polygon (scenario['archetype_mix'] uses these keys verbatim).
#
#   reliable     — Exp-13 Reliable: 99% uptime, full capacity. uptime 'always'.
#   weekend      — Exp-13 Weekend Warrior: online weekends, mostly offline
#                  weekdays, full capacity. uptime 'periodic' (weekly cycle).
#   seasonal     — Exp-13 Seasonal student: online semester, offline summer,
#                  full capacity. uptime 'seasonal' (yearly cycle).
#   nomad        — Exp-13 Nomad: ~50% random ON/OFF blocks, full capacity.
#                  uptime 'nomad' (random blocks).
#   hoarder      — Exp-13 Hoarder: 90% uptime, only 20% storage capacity.
#                  uptime 'always' (it answers checks), starved soft_quota.
#   freeloader   — Exp-13 Freeloader: 80% uptime, only 10% storage capacity.
#                  uptime 'always', further-starved soft_quota.
#   free_rider   — v1 passive adversary (config-only): backs up its own data,
#                  holds ~nothing for others. Tiny soft_quota. uptime 'always'.
#   newcomer     — honest late joiner used to characterise onboarding fairness.
#                  Full capacity, joins mid-run. uptime 'late_join'.
ARCHETYPES: dict[str, ArchetypeSpec] = {
    "reliable": ArchetypeSpec(
        soft_quota_gb=FULL_SOFT_QUOTA_GB,
        hard_quota_gb=0.0,
        disk_reserve_gb=0.0,
        importance_multiplier=1.0,
        watch_file_count=DEFAULT_WATCH_FILE_COUNT,
        watch_file_size_bytes=DEFAULT_WATCH_FILE_SIZE_BYTES,
        uptime_pattern="always",
    ),
    "weekend": ArchetypeSpec(
        soft_quota_gb=FULL_SOFT_QUOTA_GB,
        hard_quota_gb=0.0,
        disk_reserve_gb=0.0,
        importance_multiplier=1.0,
        watch_file_count=DEFAULT_WATCH_FILE_COUNT,
        watch_file_size_bytes=DEFAULT_WATCH_FILE_SIZE_BYTES,
        uptime_pattern="periodic",
    ),
    "seasonal": ArchetypeSpec(
        soft_quota_gb=FULL_SOFT_QUOTA_GB,
        hard_quota_gb=0.0,
        disk_reserve_gb=0.0,
        importance_multiplier=1.0,
        watch_file_count=DEFAULT_WATCH_FILE_COUNT,
        watch_file_size_bytes=DEFAULT_WATCH_FILE_SIZE_BYTES,
        uptime_pattern="seasonal",
    ),
    "nomad": ArchetypeSpec(
        soft_quota_gb=FULL_SOFT_QUOTA_GB,
        hard_quota_gb=0.0,
        disk_reserve_gb=0.0,
        importance_multiplier=1.0,
        watch_file_count=DEFAULT_WATCH_FILE_COUNT,
        watch_file_size_bytes=DEFAULT_WATCH_FILE_SIZE_BYTES,
        uptime_pattern="nomad",
    ),
    "hoarder": ArchetypeSpec(
        # 20% of full storage capacity (Exp-13).
        soft_quota_gb=round(FULL_SOFT_QUOTA_GB * 0.20, 6),
        hard_quota_gb=0.0,
        disk_reserve_gb=0.0,
        importance_multiplier=1.0,
        watch_file_count=DEFAULT_WATCH_FILE_COUNT,
        watch_file_size_bytes=DEFAULT_WATCH_FILE_SIZE_BYTES,
        uptime_pattern="always",
    ),
    "freeloader": ArchetypeSpec(
        # 10% of full storage capacity (Exp-13).
        soft_quota_gb=round(FULL_SOFT_QUOTA_GB * 0.10, 6),
        hard_quota_gb=0.0,
        disk_reserve_gb=0.0,
        importance_multiplier=1.0,
        watch_file_count=DEFAULT_WATCH_FILE_COUNT,
        watch_file_size_bytes=DEFAULT_WATCH_FILE_SIZE_BYTES,
        uptime_pattern="always",
    ),
    "free_rider": ArchetypeSpec(
        # v1 passive adversary: tiny soft_quota caps GET-for-others to ~nothing.
        soft_quota_gb=FREE_RIDER_SOFT_QUOTA_GB,
        hard_quota_gb=0.0,
        disk_reserve_gb=0.0,
        importance_multiplier=1.0,
        watch_file_count=DEFAULT_WATCH_FILE_COUNT,
        watch_file_size_bytes=DEFAULT_WATCH_FILE_SIZE_BYTES,
        uptime_pattern="always",
    ),
    "newcomer": ArchetypeSpec(
        soft_quota_gb=FULL_SOFT_QUOTA_GB,
        hard_quota_gb=0.0,
        disk_reserve_gb=0.0,
        importance_multiplier=1.0,
        watch_file_count=DEFAULT_WATCH_FILE_COUNT,
        watch_file_size_bytes=DEFAULT_WATCH_FILE_SIZE_BYTES,
        uptime_pattern="late_join",
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Churn-event expansion
# ─────────────────────────────────────────────────────────────────────────────
#
# A churn event from this module is a (event_type, virtual_day) tuple where
# event_type is "kill" or "restart". churn.py turns these into ChurnEvent objects
# (assigning wall_secs from the scenario time_scale and targeting this node's
# label). We intentionally emit only the per-NODE availability pattern here;
# fleet-wide mass_depart/join lives in scenario['churn'] and is expanded by
# churn.py, NOT here.
#
# Invariant: events are emitted in strictly increasing virtual_day order and the
# down/up state alternates correctly (a "kill" is only emitted while up; a
# "restart" only while down). The node is assumed UP at its join_virtual_day.


def _clip_day(day: int, duration: int) -> int:
    """Clamp a virtual day into [0, duration)."""
    if day < 0:
        return 0
    if day >= duration:
        return duration - 1
    return day


def _expand_periodic(
    join_day: int, duration: int, rng: random.Random
) -> list[tuple[str, int]]:
    """Weekend Warrior: up on weekends, down on weekdays.

    Exp-13: ~95% uptime on weekends, ~30% on weekdays. We model the dominant
    signal — offline across the working week, online on the weekend — as a clean
    weekly kill/restart cycle. Concretely: each virtual week the node goes DOWN at
    the start of the work week (Mon) and comes back UP at the start of the weekend
    (Sat). The small stochastic weekday/weekend exceptions from Exp-13 are not
    modelled (they do not change the trust signal direction; the rng is still
    consumed once per week to keep determinism contracts identical across runs).
    """
    events: list[tuple[str, int]] = []
    # Iterate week by week. day-of-week 0 = the join day's notion of "Monday".
    week_start = join_day
    while week_start < duration:
        # Consume one rng draw per week to keep the stream stable even though we
        # do not currently jitter the boundaries.
        _ = rng.random()
        mon = week_start
        sat = week_start + 5
        if mon < duration and mon > join_day:
            events.append(("kill", _clip_day(mon, duration)))
        if sat < duration and sat > join_day:
            events.append(("restart", _clip_day(sat, duration)))
        week_start += DAYS_PER_WEEK
    return _normalise(events, duration)


def _expand_seasonal(
    join_day: int, duration: int, rng: random.Random
) -> list[tuple[str, int]]:
    """Seasonal student: online semester, offline summer (yearly cycle).

    Each virtual year the node goes DOWN at summer start and comes back UP at
    summer end. day-of-year is taken relative to virtual_day 0.
    """
    events: list[tuple[str, int]] = []
    year_start = 0
    while year_start < duration:
        _ = rng.random()  # determinism stream parity
        summer_in = year_start + SEASONAL_SUMMER_START_DOY
        summer_out = year_start + SEASONAL_SUMMER_END_DOY
        if join_day < summer_in < duration:
            events.append(("kill", _clip_day(summer_in, duration)))
        if join_day < summer_out < duration:
            events.append(("restart", _clip_day(summer_out, duration)))
        year_start += DAYS_PER_YEAR
    return _normalise(events, duration)


def _expand_nomad(
    join_day: int, duration: int, rng: random.Random
) -> list[tuple[str, int]]:
    """Nomad: ~50% availability in random ON/OFF blocks.

    We walk the timeline in random-length blocks (mean ~10 virtual days), flipping
    up/down at each block boundary, starting UP. Block lengths and the starting
    phase are drawn from the seeded rng so the schedule is reproducible.
    """
    events: list[tuple[str, int]] = []
    mean_block = 10
    cursor = join_day
    up = True
    while cursor < duration:
        # Geometric-ish block length in [2, ~2*mean] virtual days.
        block = 2 + int(rng.expovariate(1.0 / mean_block))
        boundary = cursor + block
        if boundary >= duration:
            break
        if up:
            events.append(("kill", _clip_day(boundary, duration)))
        else:
            events.append(("restart", _clip_day(boundary, duration)))
        up = not up
        cursor = boundary
    return _normalise(events, duration)


def _expand_late_join(
    join_day: int, duration: int, rng: random.Random
) -> list[tuple[str, int]]:
    """Newcomer: joins mid-run, then stays up.

    The join itself is handled by the orchestrator (it launches the node at
    join_virtual_day via fleet.join_node), so a late_join node emits NO kill/
    restart events of its own. Its availability after joining is 'always'.
    """
    _ = rng.random()  # determinism stream parity
    return []


def _normalise(events: list[tuple[str, int]], duration: int) -> list[tuple[str, int]]:
    """Sort by day and drop any events that would not alternate up/down.

    Guarantees a clean alternating kill/restart sequence assuming the node starts
    UP. Removes a kill-while-down or restart-while-up (which can arise from
    clipping near the duration boundary), and merges events that collide on the
    same virtual_day (keeps the first, which preserves alternation).
    """
    events_sorted = sorted(events, key=lambda e: e[1])
    out: list[tuple[str, int]] = []
    up = True
    last_day = -1
    for ev_type, day in events_sorted:
        if day == last_day:
            continue  # collapse same-day collisions
        if ev_type == "kill" and up:
            out.append((ev_type, day))
            up = False
            last_day = day
        elif ev_type == "restart" and not up:
            out.append((ev_type, day))
            up = True
            last_day = day
        # else: skip the non-alternating event
    return out


_PATTERN_DISPATCH = {
    "periodic": _expand_periodic,
    "seasonal": _expand_seasonal,
    "nomad": _expand_nomad,
    "vacationer": _expand_seasonal,  # vacationer == one long seasonal-style break
    "late_join": _expand_late_join,
}


def _expand_uptime_pattern(
    pattern: str, join_day: int, duration: int, rng: random.Random
) -> list[tuple[str, int]]:
    """Turn an uptime_pattern into a sorted, alternating churn-event list.

    'always' emits nothing (its only churn comes from scenario-level specs).
    Unknown patterns are treated as 'always' (no per-node churn) — config_gen and
    the scenario validator are responsible for rejecting unknown archetypes; here
    we degrade safely rather than raise mid-fleet.
    """
    if pattern == "always":
        return []
    handler = _PATTERN_DISPATCH.get(pattern)
    if handler is None:
        return []
    return handler(join_day, duration, rng)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def build_node_plan(
    label: str,
    archetype: str,
    join_virtual_day: int,
    rng: random.Random,
    scenario: dict,
) -> NodePlan:
    """Build the concrete NodePlan for one node.

    Fills watch_files sizes from `rng` (sizes are reproducible run-to-run for a
    fixed seed+label; config_gen writes fresh random CONTENT of those sizes and
    hashes it for the restore ledger). Expands the archetype's uptime_pattern into
    a churn_schedule of (event_type, virtual_day) tuples bounded by the scenario
    duration.

    Raises KeyError if `archetype` is unknown (the scenario validator should have
    caught this earlier; failing loud here is correct — an unknown archetype must
    not be silently coerced into a default population).
    """
    spec = ARCHETYPES[archetype]
    duration = int(scenario["duration_virtual_days"])

    # Owned-data file sizes. Drawn from the rng so they repeat run-to-run for a
    # fixed seed; we jitter each file +/-25% around the archetype's nominal size
    # so the fleet is not perfectly uniform (more realistic block accounting).
    watch_files: list[tuple[str, int]] = []
    nominal = spec.watch_file_size_bytes
    for fi in range(spec.watch_file_count):
        jitter = rng.uniform(0.75, 1.25)
        size = max(1, int(round(nominal * jitter)))
        watch_files.append((f"{label}_data_{fi:02d}.bin", size))

    churn_schedule = _expand_uptime_pattern(
        spec.uptime_pattern, int(join_virtual_day), duration, rng
    )

    return NodePlan(
        label=label,
        archetype=archetype,
        soft_quota_gb=spec.soft_quota_gb,
        hard_quota_gb=spec.hard_quota_gb,
        disk_reserve_gb=spec.disk_reserve_gb,
        watch_files=watch_files,
        importance_multiplier=spec.importance_multiplier,
        join_virtual_day=int(join_virtual_day),
        churn_schedule=churn_schedule,
    )


def cohort_of(label: str, node_index: dict) -> str:
    """Return the archetype (cohort) of a node given the node_index map.

    `node_index` is the fleet.py-produced map keyed by label, each entry a dict
    containing at least 'archetype' (see Fleet.node_index.json). Returns the
    archetype string, or 'unknown' if the label is absent — the oracles tag any
    'unknown' edges separately rather than crash.
    """
    entry = node_index.get(label)
    if entry is None:
        return "unknown"
    if isinstance(entry, dict):
        return str(entry.get("archetype", "unknown"))
    # Tolerate a bare-string mapping label->archetype.
    return str(entry)


def archetype_mix_to_labels(
    mix: dict, total_nodes: int, rng: random.Random
) -> list[tuple[str, str]]:
    """Expand a fractional archetype_mix into concrete (label, archetype) pairs.

    Helper for the orchestrator: `mix` maps archetype -> fraction (need not sum to
    exactly 1.0; it is normalised). Returns `total_nodes` (label, archetype) pairs
    with labels node-00..node-NN, deterministically shuffled by `rng` so cohorts
    are interleaved rather than clustered by launch index. Any rounding remainder
    is assigned to the largest-share archetype.
    """
    names = sorted(mix.keys())
    if not names:
        raise ValueError("archetype_mix is empty")
    weight_total = float(sum(mix[n] for n in names))
    if weight_total <= 0:
        raise ValueError("archetype_mix weights must be positive")

    counts: dict[str, int] = {}
    assigned = 0
    for n in names:
        c = int(math.floor(total_nodes * (mix[n] / weight_total)))
        counts[n] = c
        assigned += c
    # Hand the remainder to the largest-share archetype.
    remainder = total_nodes - assigned
    if remainder > 0:
        biggest = max(names, key=lambda n: mix[n])
        counts[biggest] += remainder

    archetypes: list[str] = []
    for n in names:
        archetypes.extend([n] * counts[n])
    rng.shuffle(archetypes)

    return [(f"node-{i:02d}", arch) for i, arch in enumerate(archetypes)]
