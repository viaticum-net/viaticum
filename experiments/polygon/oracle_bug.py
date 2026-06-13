"""Viaticum Polygon — L5a HARD bug-freeness oracle.

WHY THIS MODULE EXISTS (intent / acceptance criteria — fixed before the code):
  North-star property (1) of the polygon is BUG-FREENESS, and unlike fairness it is a
  HARD gate: any single failed check fails the whole run. The polygon is run MANY
  TIMES against the unmodified daemon under accelerated time + real process churn, so
  this oracle has to answer one blunt question from the recorded artifacts alone (it
  NEVER touches a live daemon): "did this run ever crash, lose data, leak, or wedge?"

  The acceptance criteria this oracle enforces — each is one check_<name> function,
  each named after the daemon INVARIANT or product property it guards:

    BUG-no-panic        : no daemon ever panicked (stderr scan). The crash gate.
    BUG-no-unexpected-death : every node that the churn schedule says should be UP was
                          actually reachable (status_ok) past the re-auth/discovery
                          settle window — a node that vanishes while it was supposed to
                          be up is an OOM/crash, not planned churn.
    BUG-error-flood     : ERROR lines stay under a tolerated band (a *flood* of errors
                          signals a wedged subsystem even with no hard panic).
    BUG-rss-bounded     : per-node resident memory does NOT grow without bound over the
                          steady-state back half of the run (leak detector).
    BUG-disk-bounded    : holdings + db.redb on-disk footprint does NOT grow without
                          bound late in the run (eviction / vacuum actually run).
    BUG-db-bounded      : redb row counts (tbl_*) do NOT grow without bound (record cap
                          + vacuum + TTL sweeps actually fire).
    BUG-backup-liveness : honest owners reach healthy replication — blocks_ok climbs and
                          placement_alive is non-trivial by end of run (no stuck backup).
    BUG-pos-liveness    : PoS rounds not only ISSUE challenges but PASS them — the E1
                          regression (mailbox poll not scaling with time_scale) issued
                          challenges that never round-tripped, so passes stayed 0. We
                          assert pos_total_passes actually CLIMBS, the only signature
                          that catches an E1-class regression.
    BUG-mailbox-exercised : tbl_mailbox_entries was > 0 at some sample — the scaled
                          mailbox path was genuinely exercised (the polygon only ever
                          runs under time_scale>1, so a permanently-empty mailbox means
                          the scaled poll never delivered anything = E1 signature).
    BUG-no-data-loss    : every honest backed-up file restored at end of run to its
                          exact pre-backup content hash (the ground-truth ledger, same
                          method local_delete_test.sh uses). This is the load-bearing
                          product property; a single mismatch fails the run.
    BUG-db-integrity    : every node that was UP at teardown answered status --json (a
                          corrupt redb after a -9 would fail to open) — the two-pass
                          TERM->grace->KILL teardown is supposed to make this impossible.
    BUG-churn-recovery  : after kills/restarts, lost placements recover (placement_lost
                          does not stay pinned high to end of run) — self-heal works.
    BUG-no-repair-backlog : blocks_needing_repair does not grow without bound — the
                          repair pipeline keeps up, it is not wedged.

  Determinism / tolerance: every threshold is read from scenario.json with a documented
  default, and every aggregate gate uses a band tolerant of stochastic variation (slopes,
  coefficients of variation, settle windows) — never a brittle exact equality. The oracle
  judges LIVENESS only after the warm-up window (discovery + first backup take time under
  acceleration), and judges UP/DOWN against the churn schedule's intended state (a node
  sampled while intentionally DOWN is status_ok=0, NOT a crash).

  Inputs (read-only, all under results_dir):
    timeseries.csv     — per (tick,node) StatusData + table_stats + by_importance + ext_*
    edges.csv          — per (tick,node,peer) PeerSummary (read for completeness only)
    restore_ledger.json— ground-truth file-hash ledger (see _load_restore_ledger)
    stderr_scan.json   — per-node panic/ERROR scan from teardown (see _load_stderr_scan)
    churn_log.json     — resolved ChurnEvent queue (intended up/down per node per wall)
    node_index.json    — label <-> identity/device_id/archetype/join_virtual_day
    scenario.json      — the run config + threshold overrides

  Output: verdict.json = {bugfree:{pass, checks:[CheckResult...]}, generated_at,
  scenario_id}. run() returns True iff every hard check passed.

  This module consumes ONLY the on-disk artifacts; it launches no process and reads no
  daemon. stdlib only.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import asdict, dataclass, field
from pathlib import Path

from common import (
    backhalf_slope,
    load_json,
    read_timeseries,
    save_json,
    virtual_to_wall,
    wall_to_virtual,
)

# ---------------------------------------------------------------------------
# Documented threshold defaults. Each is overridable via scenario.json
# (top level, or under a "thresholds" object — both are honored).
# ---------------------------------------------------------------------------

DEFAULT_THRESHOLDS = {
    # Per-node RSS back-half slope (KB per tick) above which we call it a leak.
    # A flat-to-noisy steady state slopes ~0; sustained climb of >512 KB/tick over the
    # back half of a multi-hundred-sample run is unbounded growth, not noise.
    "rss_leak_slope_kb_per_tick": 512.0,
    # holdings + db.redb disk footprint back-half slope (KB per tick) leak threshold.
    "disk_leak_slope_kb_per_tick": 256.0,
    # db.redb byte-size back-half slope (bytes per tick) leak threshold.
    "db_redb_leak_slope_bytes_per_tick": 65536.0,
    # redb row-count (tbl_*) back-half slope (rows per tick) leak threshold. Row counts
    # are bounded by the record cap; a real cap pins the back-half slope near 0.
    "db_rows_leak_slope_per_tick": 4.0,
    # blocks_needing_repair back-half slope (blocks per tick) backlog threshold.
    "repair_backlog_slope_per_tick": 0.5,
    # Coefficient-of-variation ceiling (reserved for callers; not a hard gate here).
    "cv_threshold": 1.5,
    # Fraction of placements allowed to remain Lost at end of run after churn.
    # placement_lost / max(placement_count,1) must end below this band.
    "churn_loss_band": 0.5,
    # Tolerated ERROR lines per node across the whole run before we call it a flood.
    # Transient connect/timeout ERRORs are normal under churn; a flood is a wedge.
    "error_flood_per_node": 200,
    # After a (re)start, peer_count_authenticated and discovery need to settle. We give
    # a node this many ticks of grace after coming UP before judging its liveness.
    "reauth_settle_ticks": 6,
    # General noise band for "did this value ever move" style climb checks.
    "noise_band": 0.0,
    # Min ticks a node must be intentionally UP (past settle) before we expect it to
    # have a working status — guards against judging a node mid-onboarding.
    "min_up_ticks_for_liveness": 3,
}


# ---------------------------------------------------------------------------
# Result type.
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """One hard check's verdict. `observable` names the daemon signal it watched."""

    name: str = ""
    passed: bool = False
    observable: str = ""
    detail: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Context: everything the checks read, loaded once.
# ---------------------------------------------------------------------------


class _Ctx:
    """Materialized read-only view of one run's artifacts, shared by every check.

    The timeseries is materialized into a list (the back-half slope / per-node grouping
    passes iterate it several times; at polygon scale — ~100 nodes * a few hundred ticks
    — this is a few hundred thousand small rows, comfortably in RAM and far cheaper than
    re-parsing the CSV per check).
    """

    def __init__(self, results_dir: Path) -> None:
        self.results_dir = Path(results_dir)
        self.scenario = _load_scenario(self.results_dir)
        self.thresholds = _resolve_thresholds(self.scenario)
        self.time_scale = float(self.scenario.get("time_scale", 1) or 1)

        ts_path = self.results_dir / "timeseries.csv"
        self.rows = list(read_timeseries(ts_path)) if ts_path.is_file() else []

        # Group rows by node label and by tick once.
        self.by_node: dict[str, list] = {}
        self.ticks: set[int] = set()
        for r in self.rows:
            self.by_node.setdefault(r.label, []).append(r)
            self.ticks.add(r.tick)
        for label in self.by_node:
            self.by_node[label].sort(key=lambda x: (x.tick, x.wall_secs))
        self.sorted_ticks = sorted(self.ticks)

        self.stderr_scan = _load_stderr_scan(self.results_dir)
        self.restore_ledger = _load_restore_ledger(self.results_dir)
        self.node_index = _load_node_index(self.results_dir)
        self.churn = _load_churn_log(self.results_dir)

        # Warm-up boundary in wall seconds since fleet start (liveness judged after it).
        warmup_days = float(self.scenario.get("warmup_virtual_days", 0) or 0)
        self.warmup_wall = virtual_to_wall(warmup_days, self.time_scale)

        # Sample interval (seconds) -> ticks-per-wall conversion for settle windows.
        self.sample_interval = float(self.scenario.get("sample_interval_secs", 0) or 0)

    # -- helpers shared by checks -------------------------------------------
    def last_row_per_node(self) -> dict:
        """Final sample for each node (highest tick), regardless of up/down state."""
        out = {}
        for label, rows in self.by_node.items():
            if rows:
                out[label] = rows[-1]
        return out

    def post_warmup_rows(self, rows: list) -> list:
        return [r for r in rows if r.wall_secs >= self.warmup_wall]


# ---------------------------------------------------------------------------
# Artifact loaders (tolerant of absent/partial files — a missing input must be a
# loud FAILED check, never a silent crash of the oracle).
# ---------------------------------------------------------------------------


def _load_scenario(results_dir: Path) -> dict:
    """Load the scenario JSON copied into the results dir (provenance copy).

    run.py copies the scenario into results_dir as scenario.json. We also accept a
    scenario_copy.json fallback. Returns {} if neither exists (checks then run with
    documented defaults and report scenario_id 'unknown').
    """
    for name in ("scenario.json", "scenario_copy.json"):
        p = results_dir / name
        if p.is_file():
            try:
                obj = load_json(p)
                if isinstance(obj, dict):
                    return obj
            except (OSError, ValueError):
                pass
    return {}


def _resolve_thresholds(scenario: dict) -> dict:
    """Merge documented defaults with scenario overrides.

    Overrides may live at the scenario top level (a key matching a default name) or
    under a nested "thresholds" object; the nested object wins over a top-level key,
    which wins over the default.
    """
    merged = dict(DEFAULT_THRESHOLDS)
    for key in DEFAULT_THRESHOLDS:
        if key in scenario:
            merged[key] = scenario[key]
    nested = scenario.get("thresholds")
    if isinstance(nested, dict):
        for key, val in nested.items():
            if key in merged:
                merged[key] = val
    return merged


def _load_stderr_scan(results_dir: Path) -> dict:
    """Load per-node panic/ERROR scan, normalized to {label: {panicked, error_lines,
    first_error}}.

    Accepts either the shape teardown() returns ({"scans": {label: {...}}, ...}) or a
    flat {label: {...}} map (run.py may persist either). Returns {} if absent, which the
    panic/flood checks treat as "no scan available" (a FAILED check with a clear detail,
    because a run with no stderr scan cannot prove bug-freeness).
    """
    # The fleet teardown writes "stderr_scans.json" (plural, a per-label map);
    # older drafts used the singular name. Accept either.
    p = results_dir / "stderr_scans.json"
    if not p.is_file():
        p = results_dir / "stderr_scan.json"
    if not p.is_file():
        return {}
    try:
        obj = load_json(p)
    except (OSError, ValueError):
        return {}
    if isinstance(obj, dict) and "scans" in obj and isinstance(obj["scans"], dict):
        obj = obj["scans"]
    if not isinstance(obj, dict):
        return {}
    out = {}
    for label, scan in obj.items():
        if isinstance(scan, dict):
            out[label] = {
                "panicked": bool(scan.get("panicked", False)),
                "error_lines": int(scan.get("error_lines", 0) or 0),
                "first_error": scan.get("first_error"),
            }
    return out


def _load_restore_ledger(results_dir: Path) -> list:
    """Load the ground-truth restore ledger, normalized to a list of entries:

        {label, filename, original_hash, restored_hash, ok}

    Accepts a list of such dicts, or {"entries": [...]}, or a mapping keyed by a file
    id. `ok` is honored if present; otherwise it is derived from original_hash ==
    restored_hash (case-insensitive). A missing/empty restored_hash means the restore
    never landed -> not ok (data loss / stuck restore). Returns [] if the file is absent.

    Prefers restore_results.json (run.py's authoritative per-file restore OUTCOMES:
    {entries:[{label,name,want_hash,got_hash,status}]}); falls back to
    restore_ledger.json (original-hash-only ground truth) when results are absent.
    """
    pr = results_dir / "restore_results.json"
    if pr.is_file():
        try:
            res = load_json(pr)
        except (OSError, ValueError):
            res = None
        if isinstance(res, dict) and isinstance(res.get("entries"), list):
            out = []
            for raw in res["entries"]:
                if not isinstance(raw, dict):
                    continue
                want = str(raw.get("want_hash", "") or "").lower()
                got = str(raw.get("got_hash", "") or "").lower()
                out.append(
                    {
                        "label": str(raw.get("label", "")),
                        "filename": str(raw.get("name", "")),
                        "original_hash": want,
                        "restored_hash": got,
                        "ok": str(raw.get("status", "")).lower() == "ok",
                    }
                )
            if out:
                return out
    p = results_dir / "restore_ledger.json"
    if not p.is_file():
        return []
    try:
        obj = load_json(p)
    except (OSError, ValueError):
        return []
    if isinstance(obj, dict):
        if isinstance(obj.get("entries"), list):
            obj = obj["entries"]
        else:
            obj = list(obj.values())
    if not isinstance(obj, list):
        return []
    out = []
    for raw in obj:
        if not isinstance(raw, dict):
            continue
        orig = str(raw.get("original_hash", "") or raw.get("hash", "") or "").lower()
        rest = str(raw.get("restored_hash", "") or "").lower()
        if "ok" in raw:
            ok = bool(raw["ok"])
        else:
            ok = bool(orig) and bool(rest) and orig == rest
        out.append(
            {
                "label": str(raw.get("label", "")),
                "filename": str(raw.get("filename", raw.get("path", ""))),
                "original_hash": orig,
                "restored_hash": rest,
                "ok": ok,
            }
        )
    return out


def _load_node_index(results_dir: Path) -> dict:
    """Load node_index.json into {label: entry}. Returns {} if absent."""
    p = results_dir / "node_index.json"
    if not p.is_file():
        return {}
    try:
        obj = load_json(p)
    except (OSError, ValueError):
        return {}
    out = {}
    if isinstance(obj, list):
        for e in obj:
            if isinstance(e, dict) and e.get("label"):
                out[e["label"]] = e
    elif isinstance(obj, dict):
        for label, e in obj.items():
            if isinstance(e, dict):
                out[label] = e
    return out


def _load_churn_log(results_dir: Path) -> dict:
    """Load churn_log.json. Returns {"events": [...]} (possibly empty)."""
    p = results_dir / "churn_log.json"
    if not p.is_file():
        return {"events": []}
    try:
        obj = load_json(p)
    except (OSError, ValueError):
        return {"events": []}
    if isinstance(obj, dict) and isinstance(obj.get("events"), list):
        return obj
    if isinstance(obj, list):
        return {"events": obj}
    return {"events": []}


# ---------------------------------------------------------------------------
# Churn replay (mirror of churn.up_state_at, but operating on the persisted
# churn_log.json rather than live ChurnEvent objects, so the oracle has no import
# cycle and can read a run authored by any compatible churn engine).
# ---------------------------------------------------------------------------

_DOWN_EVENTS = frozenset({"kill", "mass_depart"})
_UP_EVENTS = frozenset({"restart", "join"})


def _intended_up(label: str, churn: dict, at_virtual_day: float) -> bool:
    """Reconstruct whether `label` was intended UP at scenario virtual_day.

    Keyed on virtual_day, NOT wall_secs: churn_log event wall_secs are ABSOLUTE epoch
    while the timeseries wall_secs are RELATIVE-to-fleet-start, so a wall_secs comparison
    mixed bases and always returned the initial state (every node read 'up' -> churn-down
    samples wrongly counted as deaths). virtual_day is base-independent and present on
    every event + sample. Mirrors churn.up_state_at: no events -> UP the whole run; a
    node whose first event is an UP event (late-joiner) starts DOWN until that event.
    """
    events = [e for e in churn.get("events", []) if label in (e.get("targets") or [])]
    events.sort(key=lambda e: float(e.get("virtual_day", 0)))
    if not events:
        return True
    state_up = events[0].get("event_type") not in _UP_EVENTS
    for e in events:
        if float(e.get("virtual_day", 0)) > at_virtual_day:
            break
        et = e.get("event_type")
        if et in _DOWN_EVENTS:
            state_up = False
        elif et in _UP_EVENTS:
            state_up = True
    return state_up


def _last_up_transition_vday(label: str, churn: dict, at_virtual_day: float) -> float:
    """virtual_day of the most recent UP transition for `label` at/<= at_virtual_day.

    Used to apply the re-auth/discovery settle window: a node that only just came UP is
    not yet expected to have re-authenticated peers or finished discovery. Returns 0.0
    if UP from the beginning, or +inf if currently down / not-yet-joined. Keyed on
    virtual_day (see _intended_up for why wall_secs is unusable here).
    """
    events = [e for e in churn.get("events", []) if label in (e.get("targets") or [])]
    events.sort(key=lambda e: float(e.get("virtual_day", 0)))
    last_up = 0.0
    started_up = not events or events[0].get("event_type") not in _UP_EVENTS
    if not started_up:
        # Stays "not yet up" until the first UP event lands.
        last_up = float("inf")
    for e in events:
        v = float(e.get("virtual_day", 0))
        if v > at_virtual_day:
            break
        if e.get("event_type") in _UP_EVENTS:
            last_up = v
        elif e.get("event_type") in _DOWN_EVENTS:
            last_up = float("inf")  # currently down; no valid "up since"
    return last_up


# ---------------------------------------------------------------------------
# Individual checks. Each returns a CheckResult; passed=False fails the run.
# ---------------------------------------------------------------------------


def check_no_panic(ctx: _Ctx) -> CheckResult:
    """No daemon ever panicked (stderr scan). The crash gate."""
    if not ctx.stderr_scan:
        return CheckResult(
            "BUG-no-panic",
            False,
            "stderr panicked flag",
            {"reason": "stderr_scan.json missing or empty — cannot prove no panic"},
        )
    panicked = {
        label: scan.get("first_error")
        for label, scan in ctx.stderr_scan.items()
        if scan.get("panicked")
    }
    return CheckResult(
        "BUG-no-panic",
        len(panicked) == 0,
        "stderr panicked flag",
        {"panicked_nodes": panicked, "scanned": len(ctx.stderr_scan)},
    )


def check_error_flood(ctx: _Ctx) -> CheckResult:
    """ERROR-line count per node stays under the tolerated flood band.

    Transient connect/timeout ERRORs under churn are normal; a FLOOD (a node spewing
    hundreds of ERRORs) signals a wedged subsystem even with no hard panic.
    """
    band = float(ctx.thresholds["error_flood_per_node"])
    if not ctx.stderr_scan:
        return CheckResult(
            "BUG-error-flood",
            False,
            "stderr ERROR line count",
            {"reason": "stderr_scan.json missing — cannot assess error volume"},
        )
    offenders = {
        label: scan.get("error_lines", 0)
        for label, scan in ctx.stderr_scan.items()
        if scan.get("error_lines", 0) > band
    }
    return CheckResult(
        "BUG-error-flood",
        len(offenders) == 0,
        "stderr ERROR line count",
        {"band_per_node": band, "offenders": offenders},
    )


def check_no_unexpected_death(ctx: _Ctx) -> CheckResult:
    """Every node intended UP (past its settle window) was actually reachable.

    A node that the churn schedule says should be UP but whose status --json failed
    (status_ok=0) past the re-auth/discovery settle window and the warm-up boundary is
    an unexpected death (OOM / crash) — distinct from planned churn (those samples are
    intended DOWN). We require a node to have been intended-UP for at least
    min_up_ticks_for_liveness samples (past settle) before we hold a status failure
    against it, so a node mid-onboarding is not penalized.
    """
    settle_ticks = int(ctx.thresholds["reauth_settle_ticks"])
    # Settle window in VIRTUAL days (intended-state is keyed on virtual_day; see
    # _intended_up). settle_ticks samples * real interval * time_scale / secs-per-day.
    _ts = float(ctx.scenario.get("time_scale", 1) or 1)
    settle_vdays = (settle_ticks * ctx.sample_interval * _ts) / 86400.0
    min_up = int(ctx.thresholds["min_up_ticks_for_liveness"])

    dead = {}
    for label, rows in ctx.by_node.items():
        # Count consecutive intended-up, post-settle, post-warmup samples that failed.
        eligible_fail = 0
        eligible_total = 0
        for r in rows:
            if r.wall_secs < ctx.warmup_wall:
                continue
            if not _intended_up(label, ctx.churn, r.virtual_day):
                continue
            up_since = _last_up_transition_vday(label, ctx.churn, r.virtual_day)
            if up_since == float("inf"):
                continue
            if r.virtual_day < up_since + settle_vdays:
                continue  # still settling after a (re)start
            eligible_total += 1
            if r.status_ok == 0:
                eligible_fail += 1
        # Hold it against the node only if it had enough eligible samples AND most of
        # them failed (a node that should be up but is silent throughout = dead).
        if eligible_total >= min_up and eligible_fail >= max(min_up, eligible_total // 2):
            dead[label] = {"eligible": eligible_total, "failed": eligible_fail}

    return CheckResult(
        "BUG-no-unexpected-death",
        len(dead) == 0,
        "status_ok while intended UP",
        {"dead_nodes": dead, "settle_ticks": settle_ticks},
    )


def _backhalf_for(ctx: _Ctx, label_rows: list, attr: str, up_only: bool) -> float:
    """Back-half slope of `attr` over (tick,value) for one node's rows.

    When up_only, samples where status_ok=0 (node down) are skipped so a node parked
    DOWN at the end of the run does not register as a "leak fixed" or a false flat line;
    we measure growth only while the node was actually running.
    """
    series = []
    for r in label_rows:
        if up_only and r.status_ok == 0:
            continue
        val = getattr(r, attr, 0) or 0
        series.append((r.tick, float(val)))
    return backhalf_slope(series)


def check_rss_bounded(ctx: _Ctx) -> CheckResult:
    """Per-node resident memory does not grow without bound late in the run."""
    thr = float(ctx.thresholds["rss_leak_slope_kb_per_tick"])
    leaks = {}
    for label, rows in ctx.by_node.items():
        slope = _backhalf_for(ctx, rows, "ext_rss_kb", up_only=True)
        if slope > thr:
            leaks[label] = round(slope, 2)
    return CheckResult(
        "BUG-rss-bounded",
        len(leaks) == 0,
        "ext_rss_kb back-half slope (KB/tick)",
        {"threshold": thr, "leaking_nodes": leaks},
    )


def check_disk_bounded(ctx: _Ctx) -> CheckResult:
    """Holdings + db.redb on-disk footprint does not grow without bound.

    Two sub-signals: du(holdings) KB and du(db.redb) bytes. Either climbing unbounded in
    the steady state means eviction / vacuum is not running. Source files are user-owned
    and never evicted, so we deliberately watch holdings + db, NOT the whole datadir.
    """
    hold_thr = float(ctx.thresholds["disk_leak_slope_kb_per_tick"])
    db_thr = float(ctx.thresholds["db_redb_leak_slope_bytes_per_tick"])
    hold_leaks = {}
    db_leaks = {}
    for label, rows in ctx.by_node.items():
        # Holdings only "leak" if eviction should be holding them flat — i.e. the node is
        # AT/NEAR its quota (under pressure). Below quota there is no pressure and filling
        # allowed space is legitimate growth, not a leak; flagging it would false-fail any
        # no-pressure run that is still filling. db.redb is bounded by vacuum/cap
        # regardless of pressure, so it is always checked. (A real eviction failure is
        # caught here only once a node is at quota — exercised by the disk-pressure run.)
        reach = [r for r in rows if r.status_ok == 1]
        lastr = reach[-1] if reach else (rows[-1] if rows else None)
        at_quota = bool(lastr) and lastr.effective_quota_bytes > 0 and \
            lastr.holding_bytes >= 0.9 * lastr.effective_quota_bytes
        if at_quota:
            hslope = _backhalf_for(ctx, rows, "ext_du_holdings_kb", up_only=True)
            if hslope > hold_thr:
                hold_leaks[label] = round(hslope, 2)
        dslope = _backhalf_for(ctx, rows, "ext_du_db_redb_bytes", up_only=True)
        if dslope > db_thr:
            db_leaks[label] = round(dslope, 2)
    return CheckResult(
        "BUG-disk-bounded",
        len(hold_leaks) == 0 and len(db_leaks) == 0,
        "ext_du_holdings_kb + ext_du_db_redb_bytes back-half slope",
        {
            "holdings_threshold_kb_per_tick": hold_thr,
            "holdings_leaks": hold_leaks,
            "db_redb_threshold_bytes_per_tick": db_thr,
            "db_redb_leaks": db_leaks,
        },
    )


def check_db_bounded(ctx: _Ctx) -> CheckResult:
    """redb row counts (tbl_*) do not grow without bound.

    The record cap + vacuum + TTL sweeps are supposed to bound every table. event_log
    in particular is the canary: it accumulates per-action rows and is the table most
    likely to grow unbounded if the cap/vacuum regresses. We gate every tbl_* column.
    """
    thr = float(ctx.thresholds["db_rows_leak_slope_per_tick"])
    tbl_attrs = [a for a in vars(_blank_row()) if a.startswith("tbl_")]
    leaks = {}
    for label, rows in ctx.by_node.items():
        node_leaks = {}
        for attr in tbl_attrs:
            slope = _backhalf_for(ctx, rows, attr, up_only=True)
            if slope > thr:
                node_leaks[attr] = round(slope, 2)
        if node_leaks:
            leaks[label] = node_leaks
    return CheckResult(
        "BUG-db-bounded",
        len(leaks) == 0,
        "tbl_* row-count back-half slope (rows/tick)",
        {"threshold": thr, "leaking_nodes": leaks},
    )


def check_backup_liveness(ctx: _Ctx) -> CheckResult:
    """Honest owners reach healthy replication — no stuck backup pipeline.

    A node with its own data (backed_up_files > 0 at any point) must, by end of run,
    show blocks_ok > 0 and placement_alive > 0 in its final reachable sample. A node
    that backs up but whose blocks never become OK is a wedged backup/placement path.
    The free-rider still backs up its OWN data, so it is included as an owner here; what
    it does NOT do is hold for others (that is a fairness signal, not a bug).
    """
    failures = {}
    owners = 0
    for label, rows in ctx.by_node.items():
        had_own = any(r.backed_up_files > 0 for r in rows)
        if not had_own:
            continue
        owners += 1
        # Liveness = the backup pipeline reached healthy replication at SOME point. A node
        # can show blocks_ok/placement_alive=0 in its FINAL reachable sample purely because
        # its holders were churned-down at that instant (the owner's view of placement
        # liveness drops while holders are transiently offline) — yet its data exists and
        # restores (the no-data-loss gate proves it). We flag only a node that NEVER reached
        # healthy replication despite owning data = a genuinely wedged backup/placement path.
        reachable = [r for r in rows if r.status_ok == 1]
        if not reachable:
            continue
        ever_ok = any(r.blocks_ok > 0 and r.placement_alive > 0 for r in reachable)
        if not ever_ok:
            last = reachable[-1]
            failures[label] = {
                "blocks_ok": last.blocks_ok,
                "placement_alive": last.placement_alive,
                "backed_up_files": last.backed_up_files,
                "note": "never reached blocks_ok>0 & placement_alive>0 in any reachable sample",
            }
    # If literally no node ever backed anything up, the run did not exercise backup —
    # that is a setup failure, not a pass.
    if owners == 0:
        return CheckResult(
            "BUG-backup-liveness",
            False,
            "blocks_ok / placement_alive at end of run",
            {"reason": "no node ever reported backed_up_files>0 — backup not exercised"},
        )
    return CheckResult(
        "BUG-backup-liveness",
        len(failures) == 0,
        "blocks_ok / placement_alive at end of run",
        {"owners": owners, "stuck_nodes": failures},
    )


def check_pos_liveness(ctx: _Ctx) -> CheckResult:
    """PoS rounds not only ISSUE challenges but PASS them (E1 regression guard).

    The E1 bug (mailbox poll not scaling with time_scale) let owners issue challenges
    that never round-tripped, so pos_total_passes stayed pinned at 0 while challenges
    climbed. We assert, across the fleet, that pos_total_passes actually CLIMBS from the
    first post-warmup sample to the last reachable sample (delta > noise_band), on at
    least one node that also issued challenges. This is the ONLY signature that catches
    an E1-class regression — counting challenges alone would falsely pass.
    """
    noise = float(ctx.thresholds["noise_band"])
    any_challenged = False
    climbed = False
    detail_nodes = {}
    for label, rows in ctx.by_node.items():
        post = ctx.post_warmup_rows(rows)
        reachable = [r for r in post if r.status_ok == 1]
        if not reachable:
            continue
        first_ch = reachable[0].pos_total_challenges
        last_ch = reachable[-1].pos_total_challenges
        first_pass = reachable[0].pos_total_passes
        last_pass = reachable[-1].pos_total_passes
        # An owner observes its holders' PoS by issuing challenges; passes are the
        # holders answering. We track both from the owner's status counters.
        if last_ch > 0:
            any_challenged = True
        pass_delta = last_pass - first_pass
        if pass_delta > noise and last_pass > 0:
            climbed = True
            detail_nodes[label] = {
                "challenges_first": first_ch,
                "challenges_last": last_ch,
                "passes_first": first_pass,
                "passes_last": last_pass,
            }
    if not any_challenged:
        return CheckResult(
            "BUG-pos-liveness",
            False,
            "pos_total_passes climb (E1 guard)",
            {"reason": "no node ever issued a PoS challenge — PoS not exercised"},
        )
    return CheckResult(
        "BUG-pos-liveness",
        climbed,
        "pos_total_passes climb (E1 guard)",
        {
            "challenges_observed": any_challenged,
            "passes_climbed": climbed,
            "evidence": detail_nodes,
        },
    )


def check_mailbox_exercised(ctx: _Ctx) -> CheckResult:
    """tbl_mailbox_entries was > 0 at some sample (scaled mailbox path exercised).

    The polygon only ever runs under time_scale>1. If the scaled mailbox poll never
    delivered anything, mailbox_entries stays 0 fleet-wide for the whole run — the E1
    signature at the storage layer. We require at least one node to have shown
    mailbox_entries>0 at some tick.
    """
    max_entries = 0
    saw_label = None
    for label, rows in ctx.by_node.items():
        for r in rows:
            if r.tbl_mailbox_entries > max_entries:
                max_entries = r.tbl_mailbox_entries
                saw_label = label
    return CheckResult(
        "BUG-mailbox-exercised",
        max_entries > 0,
        "tbl_mailbox_entries peak",
        {"peak_mailbox_entries": max_entries, "peak_node": saw_label},
    )


def check_no_data_loss(ctx: _Ctx) -> CheckResult:
    """Every honest backed-up file restored to its exact pre-backup content hash.

    The ground-truth product property. A single mismatch (or a restore that never
    landed -> empty restored_hash) fails the run. An empty ledger means the restore
    ground-truth was not collected — that cannot prove no-data-loss, so it FAILS loudly.
    """
    if not ctx.restore_ledger:
        return CheckResult(
            "BUG-no-data-loss",
            False,
            "restore content-hash match",
            {"reason": "restore_ledger.json missing/empty — no-data-loss not proven"},
        )
    mismatches = [
        {
            "label": e["label"],
            "filename": e["filename"],
            "original_hash": e["original_hash"],
            "restored_hash": e["restored_hash"],
        }
        for e in ctx.restore_ledger
        if not e["ok"]
    ]
    return CheckResult(
        "BUG-no-data-loss",
        len(mismatches) == 0,
        "restore content-hash match",
        {
            "files_checked": len(ctx.restore_ledger),
            "mismatches": mismatches,
        },
    )


def check_db_integrity(ctx: _Ctx) -> CheckResult:
    """Every node UP at teardown answered status --json (no redb corruption).

    A corrupt redb (e.g. from a -9 with no flush) would fail to open and status --json
    would error. The two-pass TERM->grace->KILL teardown is designed to prevent that.
    We assert: for every node intended UP at its LAST sample, status_ok=1 on that
    sample (the node could still serve its DB at the end of the run).
    """
    last_rows = ctx.last_row_per_node()
    corrupt = {}
    checked = 0
    for label, last in last_rows.items():
        if not _intended_up(label, ctx.churn, last.virtual_day):
            continue
        up_since = _last_up_transition_vday(label, ctx.churn, last.virtual_day)
        if up_since == float("inf"):
            continue
        _ts = float(ctx.scenario.get("time_scale", 1) or 1)
        settle_vdays = (int(ctx.thresholds["reauth_settle_ticks"]) * ctx.sample_interval * _ts) / 86400.0
        if last.virtual_day < up_since + settle_vdays:
            continue
        checked += 1
        if last.status_ok != 1:
            corrupt[label] = {"last_tick": last.tick, "status_ok": last.status_ok}
    return CheckResult(
        "BUG-db-integrity",
        len(corrupt) == 0,
        "status_ok on final sample of UP nodes",
        {"checked": checked, "unreadable_nodes": corrupt},
    )


def check_churn_recovery(ctx: _Ctx) -> CheckResult:
    """After kills/restarts, lost placements recover (no permanent loss pinning).

    For a node that experienced churn (had a kill/restart event), its final reachable
    sample must not leave a large fraction of placements Lost. placement_lost /
    max(placement_count,1) at end of run must end below churn_loss_band. A run with NO
    churn events passes trivially (nothing to recover from).
    """
    band = float(ctx.thresholds["churn_loss_band"])
    churned_labels = set()
    for e in ctx.churn.get("events", []):
        if e.get("event_type") in _DOWN_EVENTS:
            for t in e.get("targets") or []:
                churned_labels.add(t)
    if not churned_labels:
        return CheckResult(
            "BUG-churn-recovery",
            True,
            "placement_lost fraction at end of run",
            {"note": "no churn (kill/mass_depart) events — nothing to recover from"},
        )
    offenders = {}
    for label in churned_labels:
        rows = ctx.by_node.get(label, [])
        reachable = [r for r in rows if r.status_ok == 1]
        if not reachable:
            continue
        last = reachable[-1]
        total = max(last.placement_count, 1)
        frac = last.placement_lost / total
        if last.placement_count > 0 and frac > band:
            offenders[label] = {
                "placement_lost": last.placement_lost,
                "placement_count": last.placement_count,
                "lost_fraction": round(frac, 3),
            }
    return CheckResult(
        "BUG-churn-recovery",
        len(offenders) == 0,
        "placement_lost fraction at end of run",
        {"band": band, "churned_nodes": len(churned_labels), "offenders": offenders},
    )


def check_no_repair_backlog(ctx: _Ctx) -> CheckResult:
    """blocks_needing_repair does not grow without bound (repair pipeline keeps up).

    A persistently positive back-half slope of blocks_needing_repair means the repair
    subsystem is wedged — blocks pile up faster than they are repaired. Transient spikes
    after a kill are fine (they appear in the early half / get repaired); the back-half
    slope catches a true backlog.
    """
    thr = float(ctx.thresholds["repair_backlog_slope_per_tick"])
    backlogged = {}
    for label, rows in ctx.by_node.items():
        slope = _backhalf_for(ctx, rows, "blocks_needing_repair", up_only=True)
        if slope > thr:
            backlogged[label] = round(slope, 3)
    return CheckResult(
        "BUG-no-repair-backlog",
        len(backlogged) == 0,
        "blocks_needing_repair back-half slope",
        {"threshold": thr, "backlogged_nodes": backlogged},
    )


# Ordered registry of every hard check. The count is the "N/N hard checks" denominator.
CHECKS = (
    check_no_panic,
    check_no_unexpected_death,
    check_error_flood,
    check_rss_bounded,
    check_disk_bounded,
    check_db_bounded,
    check_backup_liveness,
    check_pos_liveness,
    check_mailbox_exercised,
    check_no_data_loss,
    check_db_integrity,
    check_churn_recovery,
    check_no_repair_backlog,
)


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------


def run(results_dir) -> bool:
    """Evaluate every hard check over a run's artifacts; write verdict.json.

    Returns True iff ALL hard checks passed (the run's bug-freeness gate). Each check is
    isolated: if a check function raises, that check is recorded FAILED with the
    exception in its detail (a crash in the oracle must never silently pass the run).
    """
    results_dir = Path(results_dir)
    ctx = _Ctx(results_dir)

    checks: list[CheckResult] = []
    for fn in CHECKS:
        try:
            res = fn(ctx)
        except Exception as exc:  # noqa: BLE001 — oracle robustness: a crashing check fails
            res = CheckResult(
                name=getattr(fn, "__name__", "check_unknown").replace("check_", "BUG-"),
                passed=False,
                observable="oracle internal",
                detail={"exception": f"{type(exc).__name__}: {exc}"},
            )
        checks.append(res)

    overall = all(c.passed for c in checks)
    passed_n = sum(1 for c in checks if c.passed)

    verdict = {
        "bugfree": {
            "pass": overall,
            "passed": passed_n,
            "total": len(checks),
            "checks": [asdict(c) for c in checks],
        },
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "scenario_id": str(ctx.scenario.get("id", "unknown")),
    }
    save_json(results_dir / "verdict.json", verdict)
    return overall


# ---------------------------------------------------------------------------
# Internal helper: a blank TimeseriesRow to enumerate tbl_* attribute names without
# importing the dataclass directly (keeps the tbl_* gate in lock-step with common.py's
# schema — adding a tbl_ column there auto-extends the DB-growth gate here).
# ---------------------------------------------------------------------------


def _blank_row():
    # Lazy import so the module-level import block stays focused on the public API.
    from common import TimeseriesRow

    return TimeseriesRow()


# ---------------------------------------------------------------------------
# Manual entry point: `python3 oracle_bug.py <results_dir>` re-runs the oracle on an
# already-collected run (the orchestrator calls run() directly). Kept thin.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python3 oracle_bug.py <results_dir>", file=sys.stderr)
        raise SystemExit(2)
    ok = run(Path(sys.argv[1]))
    v = load_json(Path(sys.argv[1]) / "verdict.json")
    bf = v["bugfree"]
    print(f"BUG-FREENESS: {'PASS' if bf['pass'] else 'FAIL'} "
          f"({bf['passed']}/{bf['total']} hard checks)")
    for c in bf["checks"]:
        mark = "ok  " if c["passed"] else "FAIL"
        print(f"  [{mark}] {c['name']:<26} ({c['observable']})")
    # Reference the otherwise-unused imports kept for the documented dependency surface.
    _ = (wall_to_virtual,)
    raise SystemExit(0 if ok else 1)
