"""Viaticum Polygon — L3 churn engine: virtual->wall event queue + up-state oracle.

WHY THIS MODULE EXISTS (intent / acceptance criteria — fixed before the code):
  The polygon must subject REAL daemons to REAL process churn, because the two
  north-star properties (bug-freeness, fairness) only hold up if they survive
  nodes actually dying and coming back. Faults in v1 are NOT injected as
  Byzantine code — they are honest processes killed/restarted on a wall-clock
  schedule that maps an accelerated VIRTUAL timeline (months in minutes) onto
  real seconds. This module is the single source of truth for "what happens when",
  so the orchestrator and the observability collector agree on every node's
  up/down state at every tick.

  It does three things and nothing else:
    1. build_event_queue: flatten every per-archetype uptime pattern (already
       expanded into NodePlan.churn_schedule by archetypes.py) PLUS the
       scenario-level mass_depart / join specs into ONE time-ordered list of
       ChurnEvents stamped with absolute wall-clock seconds.
    2. due_events: at run time, given the orchestrator's wall clock, return the
       events whose firing time fell in the half-open window (last_wall, now_wall]
       — so each event fires exactly once, no double-fire on a slow tick.
    3. up_state_at: for the collector, reconstruct whether a given node is 'up' or
       'down' at an arbitrary wall time by replaying its kill/restart events. A
       node sampled while DOWN must be recorded status_ok=0, NOT a false crash.

  INTENT INVARIANTS (what "correct" means here, independent of the code):
    - A 'join' / 'restart' brings a node UP; a 'kill' / 'mass_depart' takes it DOWN.
    - A node that never appears in any kill/join event is 'up' for the whole run
      (always-on archetype) — UNLESS it has join_virtual_day > 0, in which case it
      is 'down' until its join fires (a late-joiner / onboarding node).
    - Events are deterministic given scenario['seed']: a gradual mass_depart spreads
      its kills uniformly across the virtual window using a seeded RNG, so two runs
      of the same scenario churn identically.
    - virtual->wall conversion is delegated to common.virtual_to_wall (single source
      of truth shared with the orchestrator); we only add fleet_start_wall offset.

  This module spawns NO processes and reads NO daemon state. It is pure schedule
  math. The orchestrator (run.py) is what actually calls fleet.kill_node /
  restart_node / join_node for each due event.
"""

import random
from pathlib import Path

from common import ChurnEvent, virtual_to_wall, load_json, save_json

# Event-type vocabulary. kill/mass_depart take a node DOWN; restart/join bring it UP.
DOWN_EVENTS = frozenset({"kill", "mass_depart"})
UP_EVENTS = frozenset({"restart", "join"})


def _event_virtual_day(entry):
    """Extract the virtual_day from a NodePlan.churn_schedule entry.

    archetypes.py expands an uptime_pattern into a list of (event, virtual_day, ...)
    tuples. We accept either a tuple/list (event, virtual_day, *rest) or a ChurnEvent
    already carrying .virtual_day, and normalize to (event_type:str, virtual_day:float).
    """
    if isinstance(entry, ChurnEvent):
        return entry.event_type, float(entry.virtual_day)
    # tuple / list form: (event_type, virtual_day, *rest)
    event_type = str(entry[0])
    virtual_day = float(entry[1])
    return event_type, virtual_day


def _make_event(event_type, virtual_day, targets, time_scale, fleet_start_wall):
    """Build one ChurnEvent with its absolute wall-clock firing time."""
    wall_secs = fleet_start_wall + virtual_to_wall(virtual_day, time_scale)
    return ChurnEvent(
        virtual_day=float(virtual_day),
        wall_secs=float(wall_secs),
        event_type=str(event_type),
        targets=list(targets),
    )


def build_event_queue(node_plans, scenario, fleet_start_wall):
    """Expand all churn sources into one time-ordered list[ChurnEvent].

    Sources, in this order of expansion (final list is sorted by wall_secs):
      A) per-node late-join: any NodePlan with join_virtual_day > 0 emits a 'join'
         event at that virtual day (the node starts DOWN, comes UP when it joins).
      B) per-archetype uptime pattern: each entry in NodePlan.churn_schedule
         (already expanded by archetypes.py into (event, virtual_day, ...)) becomes
         a single-target ChurnEvent for that node.
      C) scenario['churn'] specs: a list of dicts. Supported kinds:
           {"kind":"mass_depart", "virtual_day":D, "fraction":F or "count":C,
            "gradual":bool, "window_virtual_days":W, "targets":[labels]?}
              -> selects F*N (or C) target nodes and emits 'mass_depart' (DOWN)
                 events. If gradual, the kills are spread UNIFORMLY across
                 [D, D+W] using a seeded RNG (deterministic per scenario['seed']);
                 otherwise all fire at virtual_day D.
           {"kind":"join", "virtual_day":D, "targets":[labels], "gradual":bool,
            "window_virtual_days":W}
              -> emits 'join' (UP) events for the named labels (a planned
                 onboarding wave that is NOT already covered by join_virtual_day).
    """
    time_scale = float(scenario["time_scale"])
    seed = int(scenario.get("seed", 0))
    duration = float(scenario.get("duration_virtual_days", 0))

    queue = []
    labels = [p.label for p in node_plans]

    # ---- A) per-node late-join ------------------------------------------------
    for plan in node_plans:
        join_day = float(getattr(plan, "join_virtual_day", 0) or 0)
        if join_day > 0:
            queue.append(
                _make_event("join", join_day, [plan.label], time_scale, fleet_start_wall)
            )

    # ---- B) per-archetype uptime pattern -------------------------------------
    for plan in node_plans:
        schedule = getattr(plan, "churn_schedule", None) or []
        for entry in schedule:
            event_type, virtual_day = _event_virtual_day(entry)
            # Respect the run horizon: never schedule past the end of the run.
            if duration and virtual_day > duration:
                continue
            queue.append(
                _make_event(
                    event_type, virtual_day, [plan.label], time_scale, fleet_start_wall
                )
            )

    # ---- C) scenario-level churn specs ---------------------------------------
    churn_specs = scenario.get("churn") or []
    if isinstance(churn_specs, dict):
        churn_specs = [churn_specs]
    for idx, spec in enumerate(churn_specs):
        # Deterministic per-spec RNG: same scenario seed + spec index => same draw.
        # NB: we derive the RNG seed from INTEGERS only (seed, idx) — never from a
        # hashed string — because Python randomizes str hashing per-process
        # (PYTHONHASHSEED), which would silently break run-to-run determinism.
        rng = random.Random(seed * 1_000_003 + idx)
        queue.extend(
            _expand_churn_spec(spec, labels, duration, time_scale, fleet_start_wall, rng)
        )

    # Stable, time-ordered queue. Ties broken by (event_type, first target) so the
    # ordering is deterministic across runs of the same scenario.
    queue.sort(key=lambda e: (e.wall_secs, e.event_type, e.targets[0] if e.targets else ""))
    return queue


def _expand_churn_spec(spec, labels, duration, time_scale, fleet_start_wall, rng):
    """Expand one scenario['churn'] dict into a list of ChurnEvents."""
    kind = spec.get("kind")
    if kind not in ("mass_depart", "join"):
        # Unknown spec kind: ignore rather than crash the whole run.
        return []

    base_day = float(spec.get("virtual_day", 0))
    gradual = bool(spec.get("gradual", False))
    window = float(spec.get("window_virtual_days", 0))

    # Resolve the target set.
    targets = spec.get("targets")
    if targets:
        chosen = [t for t in targets if t in labels]
    else:
        n = len(labels)
        if "count" in spec:
            count = int(spec["count"])
        else:
            fraction = float(spec.get("fraction", 0.0))
            count = int(round(fraction * n))
        count = max(0, min(count, n))
        # Seeded uniform sample so the same scenario picks the same victims.
        chosen = sorted(rng.sample(labels, count)) if count else []

    if not chosen:
        return []

    events = []
    if gradual and window > 0 and len(chosen) > 1:
        # Spread firing times UNIFORMLY across [base_day, base_day + window].
        # Deterministic: each chosen node gets an evenly-spaced slot (shuffled by rng
        # so which node leaves first is seeded, not label-order-biased).
        order = list(chosen)
        rng.shuffle(order)
        step = window / float(len(order) - 1)
        for i, label in enumerate(order):
            day = base_day + step * i
            if duration and day > duration:
                continue
            events.append(
                _make_event(kind, day, [label], time_scale, fleet_start_wall)
            )
    else:
        # All at once at base_day — one event carrying every target. The
        # orchestrator iterates ChurnEvent.targets and applies each.
        if not (duration and base_day > duration):
            events.append(
                _make_event(kind, base_day, chosen, time_scale, fleet_start_wall)
            )
    return events


def due_events(queue, now_wall, last_wall):
    """Return events whose wall_secs fell in the half-open window (last_wall, now_wall].

    Half-open on the low side so an event fired at the boundary of one tick is NOT
    re-fired at the next tick's boundary (idempotent dispatch). queue must be the
    list returned by build_event_queue (sorted by wall_secs).
    """
    return [e for e in queue if last_wall < e.wall_secs <= now_wall]


def up_state_at(label, queue, at_virtual_day):
    """Return 'up' or 'down' for `label` at scenario virtual_day by replaying its events.

    Keyed on virtual_day, NOT wall_secs: event wall_secs are ABSOLUTE epoch while a
    caller's clock may be relative-to-fleet-start, so a wall_secs comparison mixed bases
    and silently returned the initial state forever (every node read 'up'). virtual_day is
    base-independent and present on every event. Walk this node's kill/restart/join/
    mass_depart events in virtual-time order up to at_virtual_day; the LAST one wins. No
    events -> 'up' (always-on). First-ever event a 'join' -> 'down' until that join fires.
    """
    relevant = sorted(
        (e for e in queue if label in e.targets),
        key=lambda e: e.virtual_day,
    )
    if not relevant:
        return "up"

    # Determine the initial state BEFORE any event. A node whose first event is a
    # 'join' starts life DOWN (it onboards later); otherwise it starts UP.
    state = "down" if relevant[0].event_type in UP_EVENTS else "up"

    for e in relevant:
        if e.virtual_day > at_virtual_day:
            break
        if e.event_type in DOWN_EVENTS:
            state = "down"
        elif e.event_type in UP_EVENTS:
            state = "up"
    return state


def write_churn_log(path, queue):
    """Persist the resolved event queue to churn_log.json for provenance / debugging.

    The log is a flat, sorted list of every event with its virtual day, absolute wall
    time, type, and targets — enough to replay or audit the run after the fact.
    """
    record = {
        "event_count": len(queue),
        "events": [
            {
                "virtual_day": e.virtual_day,
                "wall_secs": e.wall_secs,
                "event_type": e.event_type,
                "targets": list(e.targets),
            }
            for e in queue
        ],
    }
    save_json(Path(path), record)


# load_json is imported so callers that want to re-read a churn_log have a single
# stdlib-only entry point alongside save_json; reference it to keep linters quiet.
_ = load_json
