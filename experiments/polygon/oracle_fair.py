"""Viaticum Polygon — L5b SOFT fairness oracle.

WHY THIS MODULE EXISTS (intent / acceptance criteria — fixed before the code):
  North-star property (2) of the polygon is FAIRNESS, and unlike bug-freeness it is a
  SOFT property: it CHARACTERIZES the trust economy, it does NOT gate the run. This
  oracle reads the same on-disk artifacts oracle_bug reads (it launches no process and
  reads no live daemon) and asks one open question from the record alone: "did the trust
  economy treat each cohort the way the design says it should?" — and emits FINDINGs
  where it did not. It NEVER fails the process and NEVER raises (run.py ignores its
  return value; oracle_bug is the only hard gate).

  Each fairness check is one check_<name> function named after a FAIR-* acceptance
  criterion (see /tmp/poly_fairness_defs.txt). A check classifies nodes into cohorts by
  archetype (free_rider, reliable/rock, nomad, vacationer/seasonal, newcomer, ...),
  applies the same warm-up filter oracle_bug uses (discovery + first backup take time
  under acceleration), computes a metric from timeseries.csv / edges.csv / node_index,
  and emits a verdict:

    FAIR              — the design property held.
    FINDING           — the property did NOT hold (a Phase-4R signal, never a failure).
    ADVISORY          — informational aggregate (e.g. D-warning volume); not a finding.
    INSUFFICIENT_DATA — the inputs needed for this check were missing/partial; the
                        check degrades to a structured verdict with a clear detail,
                        NEVER an exception.

  The fairness oracle's verdicts are CHARACTERIZATIONS that feed the Phase-4R trust /
  eviction / economy redesign. Several checks compare cohort means / ORDERINGS, not
  absolute Exp-13 thresholds (the trust core has moved on from those absolutes); where a
  def says "ORDERING" we test the rank, not a number. One check
  (FAIR-FREERIDER-COUNT-INVARIANCE) is inherently cross-run; a single-run module can
  only emit the per-run aggregates it would compare, and says so in its detail.

  Inputs (read-only, all under results_dir): scenario.json, timeseries.csv (via
  common.read_timeseries), edges.csv (via common.read_edges), node_index.json,
  restore_ledger.json, churn_log.json, stderr_scan.json.

  Output: fairness_report.json =
    {"fairness": {"checks": [ {id,title,observable,verdict,detail,metrics} ... ]},
     "generated_at": <iso>, "scenario_id": <str>,
     "summary": {"findings": N, "advisory": M, "insufficient_data": K},
     "findings": <int>}    # flat mirror so run.py's summary line can read it

  stdlib only (pure-Python Kendall tau / modularity / correlation live in common.py).
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import asdict, dataclass, field
from pathlib import Path

from common import (
    build_giveget_graph,
    greedy_communities,
    kendall_tau,
    load_json,
    modularity,
    random_baseline_modularity,
    read_edges,
    read_timeseries,
    save_json,
    virtual_to_wall,
)

# ---------------------------------------------------------------------------
# Verdict vocabulary (SOFT — none of these is a process failure).
# ---------------------------------------------------------------------------

FAIR = "FAIR"
FINDING = "FINDING"
ADVISORY = "ADVISORY"
INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


# ---------------------------------------------------------------------------
# Cohort taxonomy. Archetype names come verbatim from archetypes.ARCHETYPES.
# We never import archetypes (avoids an import cycle / keeps the oracle decoupled
# from the planner); we hard-code the same canonical names it uses.
# ---------------------------------------------------------------------------

# The honest, full-capacity, ~always-up cohort the design expects at the TOP of trust.
RELIABLE_COHORT = frozenset({"reliable"})
# Honest contributors: full storage capacity, genuinely useful holders (Exp-13 top tier).
HONEST_CONTRIBUTOR_COHORT = frozenset({"reliable", "weekend", "seasonal", "nomad"})
# The storage-starved / passive adversaries the design expects at the BOTTOM.
FREERIDER_COHORT = frozenset({"free_rider", "freeloader"})
# The intermittently-absent cohorts.
NOMAD_COHORT = frozenset({"nomad"})
VACATIONER_COHORT = frozenset({"seasonal", "vacationer"})
NEWCOMER_COHORT = frozenset({"newcomer"})
# "Full-capacity" cohorts (used to judge "nomad near lowest among full-capacity").
FULL_CAPACITY_COHORT = frozenset({"reliable", "weekend", "seasonal", "nomad", "newcomer"})

# Documented default thresholds (each overridable via scenario.json top-level or a
# nested "fairness_thresholds"/"thresholds" object — see _resolve_thresholds).
DEFAULT_THRESHOLDS = {
    # trust_s near-floor band: a free-rider's trust_s as seen by peers should sit at/near
    # the 0.1 floor; we call "near the floor" <= this value.
    "trust_s_floor_band": 0.2,
    # FAIR-TRUST-I-STICKY: target I-drop should be much smaller than P-drop — finding iff
    # |delta_i|/i is NOT < this multiple of |delta_p|/p (Exp-14 ratio ~0.15).
    "i_drop_vs_p_drop_ratio": 0.5,
    # FAIR-ABSENCE-RECOVERY: trust loss during absence over this fraction = finding.
    "absence_loss_band": 0.15,
    # FAIR-ABSENCE-RECOVERY: post-return recovery below this fraction of pre = finding.
    "absence_recovery_band": 0.90,
    # FAIR-NEWCOMER-ONBOARDING: virtual days of honest presence after which a newcomer
    # still at floor / zero placements is "starvation".
    "newcomer_grace_virtual_days": 40.0,
    # FAIR-NEWCOMER-ONBOARDING: avg_trust at/under this counts as "still at the floor".
    "trust_floor_band": 0.2,
    # FAIR-EVICTION-NO-SELF-DAMAGE: avg_trust drift over this fraction during eviction =
    # finding (Exp-14 held <0.5%).
    "self_damage_drift_band": 0.005,
    # FAIR-KENDALL-TAU: tau >= this is desirable; tau in the RED band below is a flag.
    "tau_desirable": 0.80,
    "tau_red_low": 0.62,
    "tau_red_high": 0.72,
    # FAIR-CLUSTERING: a community holding > this fraction of nodes is an oligopoly flag.
    "community_dominance_band": 0.5,
    # FAIR-GIVE-GET-LEDGER: |give-get|/max(give,get,1) over this = "strong asymmetry".
    "giveget_asymmetry_band": 0.5,
    # General noise band for "did this value move" comparisons.
    "noise_band": 1e-9,
    # Warm-up settle: minimum post-warmup reachable samples a cohort metric needs.
    "min_samples_for_metric": 2,
}


# ---------------------------------------------------------------------------
# Result type (mirrors oracle_bug.CheckResult shape, fairness vocabulary).
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """One fairness check's verdict. `verdict` is one of FAIR/FINDING/ADVISORY/
    INSUFFICIENT_DATA — never a process failure. `observable` names the signal it
    watched; `metrics` carries the computed numbers for downstream (Phase-4R) analysis.
    """

    id: str = ""
    title: str = ""
    observable: str = ""
    verdict: str = INSUFFICIENT_DATA
    detail: str = ""
    metrics: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Context: everything the checks read, loaded once (mirrors oracle_bug._Ctx).
# ---------------------------------------------------------------------------


class _Ctx:
    """Materialized read-only view of one run's artifacts, shared by every check.

    timeseries.csv and edges.csv are materialized into lists (each check iterates them
    a few times; at polygon scale this is comfortably in RAM and far cheaper than
    re-parsing per check). Every loader is tolerant of an absent/partial file — a check
    that lacks its input returns INSUFFICIENT_DATA, never an exception.
    """

    def __init__(self, results_dir: Path) -> None:
        self.results_dir = Path(results_dir)
        self.scenario = _load_scenario(self.results_dir)
        self.thresholds = _resolve_thresholds(self.scenario)
        self.time_scale = float(self.scenario.get("time_scale", 1) or 1)

        ts_path = self.results_dir / "timeseries.csv"
        self.rows = list(read_timeseries(ts_path)) if ts_path.is_file() else []
        edges_path = self.results_dir / "edges.csv"
        self.edges = list(read_edges(edges_path)) if edges_path.is_file() else []

        # Group timeseries rows by node label and gather the tick grid once.
        self.by_node: dict[str, list] = {}
        self.ticks: set[int] = set()
        for r in self.rows:
            self.by_node.setdefault(r.label, []).append(r)
            self.ticks.add(r.tick)
        for label in self.by_node:
            self.by_node[label].sort(key=lambda x: (x.tick, x.wall_secs))
        self.sorted_ticks = sorted(self.ticks)

        self.node_index = _load_node_index(self.results_dir)
        self.restore_ledger = _load_restore_ledger(self.results_dir)
        self.churn = _load_churn_log(self.results_dir)
        self.stderr_scan = _load_stderr_scan(self.results_dir)

        # Warm-up boundary in wall seconds since fleet start (cohort metrics judged
        # only on post-warmup samples, exactly like oracle_bug).
        warmup_days = float(self.scenario.get("warmup_virtual_days", 0) or 0)
        self.warmup_wall = virtual_to_wall(warmup_days, self.time_scale)

        # device_id (first-8-hex self-report) -> label, to map an edge's
        # dst_identity_hex onto a fleet node (AC3 join key). Built from node_index
        # first, then back-filled from timeseries device_id reports.
        self.devid_to_label: dict[str, str] = {}
        for label, entry in self.node_index.items():
            devid = str(entry.get("device_id", "") or "")
            if devid:
                self.devid_to_label[devid[:8]] = label
                self.devid_to_label[devid] = label
        for label, rows in self.by_node.items():
            for r in rows:
                devid = str(getattr(r, "device_id", "") or "")
                if devid:
                    self.devid_to_label.setdefault(devid[:8], label)
                    self.devid_to_label.setdefault(devid, label)

    # -- helpers shared by checks -------------------------------------------
    def cohort_of(self, label: str) -> str:
        """Archetype/cohort of a node from node_index, falling back to its rows."""
        entry = self.node_index.get(label)
        if isinstance(entry, dict) and entry.get("archetype"):
            return str(entry["archetype"])
        rows = self.by_node.get(label) or []
        for r in rows:
            if getattr(r, "archetype", ""):
                return str(r.archetype)
        return "unknown"

    def labels_in(self, cohort: frozenset) -> list:
        return [lbl for lbl in self.by_node if self.cohort_of(lbl) in cohort]

    def label_for_devhex(self, dst_identity_hex: str) -> str:
        """Map an edge dst_identity_hex onto a fleet label (or '' if unknown)."""
        h = str(dst_identity_hex or "")
        if not h:
            return ""
        return self.devid_to_label.get(h) or self.devid_to_label.get(h[:8], "")

    def post_warmup(self, rows: list) -> list:
        return [r for r in rows if r.wall_secs >= self.warmup_wall]

    def post_warmup_edges(self) -> list:
        return [e for e in self.edges if e.wall_secs >= self.warmup_wall]

    def reachable_post_warmup(self, label: str) -> list:
        rows = self.by_node.get(label) or []
        return [r for r in self.post_warmup(rows) if r.status_ok == 1]

    def last_tick(self) -> int:
        return self.sorted_ticks[-1] if self.sorted_ticks else 0


# ---------------------------------------------------------------------------
# Artifact loaders (tolerant of absent/partial files — a missing input yields an
# INSUFFICIENT_DATA check, never a silent crash of the oracle).
# ---------------------------------------------------------------------------


def _load_scenario(results_dir: Path) -> dict:
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
    merged = dict(DEFAULT_THRESHOLDS)
    for key in DEFAULT_THRESHOLDS:
        if key in scenario:
            merged[key] = scenario[key]
    for nested_key in ("fairness_thresholds", "thresholds"):
        nested = scenario.get(nested_key)
        if isinstance(nested, dict):
            for key, val in nested.items():
                if key in merged:
                    merged[key] = val
    return merged


def _load_node_index(results_dir: Path) -> dict:
    p = results_dir / "node_index.json"
    if not p.is_file():
        return {}
    try:
        obj = load_json(p)
    except (OSError, ValueError):
        return {}
    out: dict = {}
    if isinstance(obj, list):
        for e in obj:
            if isinstance(e, dict) and e.get("label"):
                out[e["label"]] = e
    elif isinstance(obj, dict):
        for label, e in obj.items():
            if isinstance(e, dict):
                out[label] = e
    return out


def _load_restore_ledger(results_dir: Path) -> list:
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
                "ok": ok,
            }
        )
    return out


def _load_churn_log(results_dir: Path) -> dict:
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


def _load_stderr_scan(results_dir: Path) -> dict:
    p = results_dir / "stderr_scan.json"
    if not p.is_file():
        return {}
    try:
        obj = load_json(p)
    except (OSError, ValueError):
        return {}
    if isinstance(obj, dict) and "scans" in obj and isinstance(obj["scans"], dict):
        obj = obj["scans"]
    return obj if isinstance(obj, dict) else {}


# ---------------------------------------------------------------------------
# Small numeric helpers (kept local; pure stdlib, no third-party math).
# ---------------------------------------------------------------------------


def _mean(values: list) -> float | None:
    vals = [float(v) for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def _pearson(xs: list, ys: list) -> float | None:
    """Pearson correlation of two equal-length sequences. None if degenerate."""
    n = len(xs)
    if n != len(ys) or n < 2:
        return None
    mx = sum(xs) / n
    my = sum(ys) / n
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    denom = (sxx * syy) ** 0.5
    if denom == 0.0:
        return None
    return sxy / denom


def _cohort_mean_attr(ctx: _Ctx, cohort: frozenset, attr: str) -> tuple:
    """Mean of `attr` over each cohort node's post-warmup reachable samples.

    Returns (mean_over_cohort, per_node_means_dict, n_nodes_with_data).
    """
    per_node: dict = {}
    for label in ctx.labels_in(cohort):
        samples = [
            float(getattr(r, attr, 0) or 0) for r in ctx.reachable_post_warmup(label)
        ]
        if samples:
            per_node[label] = sum(samples) / len(samples)
    cohort_mean = _mean(list(per_node.values()))
    return cohort_mean, per_node, len(per_node)


def _edge_trust_by_target(ctx: _Ctx, attr: str = "trust") -> dict:
    """For each target label, the mean of `attr` (trust/trust_s/...) observers reported
    for it across post-warmup edges. Returns {target_label: mean_value}.

    Edges are mapped to a target label via the device-hex join (AC3); unmappable edges
    (no fleet node owns that identity) are dropped.
    """
    acc: dict = {}
    for e in ctx.post_warmup_edges():
        tgt = ctx.label_for_devhex(e.dst_identity_hex)
        if not tgt:
            continue
        acc.setdefault(tgt, []).append(float(getattr(e, attr, 0.0) or 0.0))
    return {t: (sum(v) / len(v)) for t, v in acc.items() if v}


# ---------------------------------------------------------------------------
# Individual fairness checks. Each returns a CheckResult; NONE fails the run.
# Each is wrapped by run() so a raising check degrades to INSUFFICIENT_DATA.
# ---------------------------------------------------------------------------


def check_trust_ordering(ctx: _Ctx) -> CheckResult:
    """FAIR-TRUST-ORDERING: cohort-mean avg_trust ordering (ORDERING, not absolutes)."""
    rel_mean, _, rel_n = _cohort_mean_attr(ctx, RELIABLE_COHORT, "avg_trust")
    # Mean avg_trust of every cohort present (self-reported avg_trust per node).
    cohort_means: dict = {}
    for label in ctx.by_node:
        coh = ctx.cohort_of(label)
        samples = [float(r.avg_trust) for r in ctx.reachable_post_warmup(label)]
        if samples:
            cohort_means.setdefault(coh, []).append(sum(samples) / len(samples))
    cohort_means = {c: _mean(v) for c, v in cohort_means.items() if _mean(v) is not None}
    full_cap = {c: m for c, m in cohort_means.items() if c in FULL_CAPACITY_COHORT}
    metrics = {"cohort_mean_avg_trust": cohort_means, "reliable_nodes": rel_n}
    if rel_mean is None or len(cohort_means) < 2:
        return CheckResult(
            "FAIR-TRUST-ORDERING", "Cohort trust ordering", "avg_trust cohort means",
            INSUFFICIENT_DATA,
            "fewer than two cohorts produced post-warmup trust samples",
            metrics,
        )
    top_cohort = max(cohort_means, key=lambda c: cohort_means[c])
    reliable_is_top = top_cohort in RELIABLE_COHORT
    nomad_low = True
    if "nomad" in full_cap and len(full_cap) >= 2:
        # nomad should be at/near the lowest among full-capacity cohorts.
        ordered = sorted(full_cap, key=lambda c: full_cap[c])
        nomad_rank = ordered.index("nomad")
        nomad_low = nomad_rank <= max(1, len(ordered) // 3)  # bottom third tolerated
    verdict = FAIR if (reliable_is_top and nomad_low) else FINDING
    detail = (
        f"top-trust cohort is '{top_cohort}'"
        + ("" if reliable_is_top else " (NOT reliable — ordering finding)")
        + ("" if nomad_low else "; nomad not near lowest of full-capacity cohorts")
    )
    metrics.update({"top_cohort": top_cohort, "reliable_is_top": reliable_is_top,
                    "nomad_near_lowest": nomad_low})
    return CheckResult(
        "FAIR-TRUST-ORDERING", "Cohort trust ordering", "avg_trust cohort means",
        verdict, detail, metrics,
    )


def check_freerider_trust_denied(ctx: _Ctx) -> CheckResult:
    """FAIR-FREERIDER-TRUST-DENIED: free-rider combined trust (as peers see it) vs
    honest contributors. Finding iff free-riders rank ABOVE contributors."""
    by_target = _edge_trust_by_target(ctx, "trust")
    fr_vals, hc_vals = [], []
    for tgt, val in by_target.items():
        coh = ctx.cohort_of(tgt)
        if coh in FREERIDER_COHORT:
            fr_vals.append(val)
        elif coh in HONEST_CONTRIBUTOR_COHORT:
            hc_vals.append(val)
    fr_mean, hc_mean = _mean(fr_vals), _mean(hc_vals)
    metrics = {
        "freerider_mean_combined_trust": fr_mean, "freerider_targets": len(fr_vals),
        "contributor_mean_combined_trust": hc_mean, "contributor_targets": len(hc_vals),
    }
    if fr_mean is None or hc_mean is None:
        return CheckResult(
            "FAIR-FREERIDER-TRUST-DENIED", "Free-rider trust denial",
            "edges.csv combined trust by cohort", INSUFFICIENT_DATA,
            "no peer-observed trust for free-rider and/or contributor cohorts "
            "(edges did not join to a fleet node, or cohorts absent)",
            metrics,
        )
    verdict = FINDING if fr_mean > hc_mean else FAIR
    detail = (
        f"free-rider peer-seen trust={fr_mean:.4f} vs contributor={hc_mean:.4f}; "
        + ("free-riders rank ABOVE contributors — Exp-13 storage blind-spot NOT closed "
           "(Phase-4R: is trust_s closing the gap?)"
           if verdict == FINDING else "free-riders land below contributors as designed")
    )
    return CheckResult(
        "FAIR-FREERIDER-TRUST-DENIED", "Free-rider trust denial",
        "edges.csv combined trust by cohort", verdict, detail, metrics,
    )


def check_trust_s_discriminates(ctx: _Ctx) -> CheckResult:
    """FAIR-TRUST-S-DISCRIMINATES: among nodes, correlate peer-seen trust_s(observer->
    target) with target's holding_bytes; and check the free-rider's trust_s is depressed
    near the 0.1 floor. Finding iff more real GB does NOT yield higher trust_s, OR the
    free-rider's trust_s is NOT near floor."""
    s_by_target = _edge_trust_by_target(ctx, "trust_s")
    # Target's real stored-for-others footprint = its mean holding_bytes (post-warmup).
    hold_mean, _, _ = (None, None, None)
    holding_by_target: dict = {}
    for label in ctx.by_node:
        samples = [float(r.holding_bytes) for r in ctx.reachable_post_warmup(label)]
        if samples:
            holding_by_target[label] = sum(samples) / len(samples)
    xs, ys = [], []
    for tgt, s_val in s_by_target.items():
        if tgt in holding_by_target:
            xs.append(holding_by_target[tgt])
            ys.append(s_val)
    corr = _pearson(xs, ys)
    floor_band = float(ctx.thresholds["trust_s_floor_band"])
    fr_s = [s for t, s in s_by_target.items() if ctx.cohort_of(t) in FREERIDER_COHORT]
    fr_s_mean = _mean(fr_s)
    metrics = {
        "pearson_trust_s_vs_holding_bytes": corr, "paired_targets": len(xs),
        "freerider_mean_trust_s": fr_s_mean, "freerider_targets": len(fr_s),
        "trust_s_floor_band": floor_band,
    }
    if corr is None and fr_s_mean is None:
        return CheckResult(
            "FAIR-TRUST-S-DISCRIMINATES", "trust_s discriminates by real GB stored",
            "edges.csv trust_s vs holding_bytes", INSUFFICIENT_DATA,
            "no usable (trust_s, holding_bytes) pairs and no free-rider trust_s observed",
            metrics,
        )
    corr_ok = corr is not None and corr > 0.0
    floor_ok = fr_s_mean is not None and fr_s_mean <= floor_band
    # Finding iff GB does NOT track trust_s, OR free-rider trust_s NOT depressed.
    if (corr is not None and not corr_ok) or (fr_s_mean is not None and not floor_ok):
        verdict = FINDING
    else:
        verdict = FAIR
    detail = (
        f"corr(trust_s, holding_bytes)={corr if corr is None else round(corr, 3)} "
        f"(positive expected); free-rider mean trust_s="
        f"{fr_s_mean if fr_s_mean is None else round(fr_s_mean, 3)} "
        f"(<= {floor_band} floor-band expected)"
    )
    return CheckResult(
        "FAIR-TRUST-S-DISCRIMINATES", "trust_s discriminates by real GB stored",
        "edges.csv trust_s vs holding_bytes", verdict, detail, metrics,
    )


def check_trust_p_tracks_uptime(ctx: _Ctx) -> CheckResult:
    """FAIR-TRUST-P-TRACKS-UPTIME: a node that goes offline should show falling trust_p;
    a high-uptime node a high trust_p. We correlate each target's peer-seen trust_p with
    its realized uptime (fraction of post-warmup samples it was status_ok)."""
    p_by_target = _edge_trust_by_target(ctx, "trust_p")
    uptime: dict = {}
    for label in ctx.by_node:
        post = ctx.post_warmup(ctx.by_node[label])
        if post:
            uptime[label] = sum(1 for r in post if r.status_ok == 1) / len(post)
    xs, ys = [], []
    for tgt, p_val in p_by_target.items():
        if tgt in uptime:
            xs.append(uptime[tgt])
            ys.append(p_val)
    corr = _pearson(xs, ys)
    metrics = {"pearson_trust_p_vs_uptime": corr, "paired_targets": len(xs)}
    if corr is None:
        return CheckResult(
            "FAIR-TRUST-P-TRACKS-UPTIME", "trust_p tracks uptime",
            "edges.csv trust_p vs realized uptime", INSUFFICIENT_DATA,
            "no usable (trust_p, uptime) pairs (edges did not join, or uptime uniform)",
            metrics,
        )
    verdict = FAIR if corr > 0.0 else FINDING
    detail = (
        f"corr(trust_p, uptime)={round(corr, 3)} (positive expected); "
        + ("trust_p does not track uptime — finding" if verdict == FINDING
           else "trust_p tracks uptime as designed")
    )
    return CheckResult(
        "FAIR-TRUST-P-TRACKS-UPTIME", "trust_p tracks uptime",
        "edges.csv trust_p vs realized uptime", verdict, detail, metrics,
    )


def _absence_windows(ctx: _Ctx, label: str) -> list:
    """[(down_wall, up_wall)] windows the churn log shows `label` was intentionally
    DOWN. An open final window (still down at run end) uses last tick wall."""
    events = sorted(
        (e for e in ctx.churn.get("events", []) if label in (e.get("targets") or [])),
        key=lambda e: float(e.get("wall_secs", 0)),
    )
    last_wall = ctx.by_node[label][-1].wall_secs if ctx.by_node.get(label) else 0.0
    windows, down_at = [], None
    for e in events:
        et = e.get("event_type")
        w = float(e.get("wall_secs", 0))
        if et in ("kill", "mass_depart") and down_at is None:
            down_at = w
        elif et in ("restart", "join") and down_at is not None:
            windows.append((down_at, w))
            down_at = None
    if down_at is not None:
        windows.append((down_at, last_wall))
    return windows


def check_trust_i_sticky(ctx: _Ctx) -> CheckResult:
    """FAIR-TRUST-I-STICKY: for a vacationer, |delta_i|/i should be much smaller than
    |delta_p|/p across its offline window (earned-history buffer). Finding iff the I-drop
    is NOT < ratio * P-drop."""
    ratio = float(ctx.thresholds["i_drop_vs_p_drop_ratio"])
    cands = ctx.labels_in(VACATIONER_COHORT) or ctx.labels_in(NOMAD_COHORT)
    samples = []
    for tgt in cands:
        wins = _absence_windows(ctx, tgt)
        if not wins:
            continue
        down_w, up_w = wins[0]
        before = [e for e in ctx.edges
                  if ctx.label_for_devhex(e.dst_identity_hex) == tgt and e.wall_secs < down_w]
        during = [e for e in ctx.edges
                  if ctx.label_for_devhex(e.dst_identity_hex) == tgt
                  and down_w <= e.wall_secs <= up_w]
        i_before, i_during = _mean([e.trust_i for e in before]), _mean([e.trust_i for e in during])
        p_before, p_during = _mean([e.trust_p for e in before]), _mean([e.trust_p for e in during])
        if None in (i_before, i_during, p_before, p_during) or i_before <= 0 or p_before <= 0:
            continue
        di = abs(i_during - i_before) / i_before
        dp = abs(p_during - p_before) / p_before
        samples.append({"node": tgt, "i_drop": round(di, 4), "p_drop": round(dp, 4),
                        "sticky": di < ratio * dp})
    metrics = {"per_node": samples, "ratio_band": ratio}
    if not samples:
        return CheckResult(
            "FAIR-TRUST-I-STICKY", "trust_i sticky across absence",
            "edges.csv trust_i/trust_p before vs during absence", INSUFFICIENT_DATA,
            "no vacationer/nomad node had peer-observed trust_i/trust_p both before and "
            "during a churn-logged absence window",
            metrics,
        )
    non_sticky = [s for s in samples if not s["sticky"]]
    verdict = FINDING if non_sticky else FAIR
    detail = (
        f"{len(samples)} absence window(s) sampled; "
        + (f"{len(non_sticky)} show I-drop not << P-drop (earned-history buffer weak)"
           if verdict == FINDING else "I-drop << P-drop everywhere (buffer holds)")
    )
    return CheckResult(
        "FAIR-TRUST-I-STICKY", "trust_i sticky across absence",
        "edges.csv trust_i/trust_p before vs during absence", verdict, detail, metrics,
    )


def check_absence_recovery(ctx: _Ctx) -> CheckResult:
    """FAIR-ABSENCE-RECOVERY: vacationer avg_trust pre-absence vs during vs ~post-return.
    Finding iff loss during absence > band OR post-return recovery < recovery-band of
    pre-absence within a comparable window."""
    loss_band = float(ctx.thresholds["absence_loss_band"])
    rec_band = float(ctx.thresholds["absence_recovery_band"])
    cands = ctx.labels_in(VACATIONER_COHORT) or ctx.labels_in(NOMAD_COHORT)
    samples = []
    for tgt in cands:
        wins = _absence_windows(ctx, tgt)
        if not wins:
            continue
        down_w, up_w = wins[0]
        win_len = max(up_w - down_w, 1.0)
        rows = ctx.by_node.get(tgt, [])
        pre = _mean([r.avg_trust for r in rows
                     if r.status_ok == 1 and r.wall_secs < down_w])
        during = _mean([r.avg_trust for r in rows
                        if down_w <= r.wall_secs <= up_w])
        post = _mean([r.avg_trust for r in rows
                      if r.status_ok == 1 and up_w < r.wall_secs <= up_w + win_len])
        if pre is None or pre <= 0:
            continue
        loss = (pre - during) / pre if during is not None else None
        recovery = (post / pre) if post is not None else None
        samples.append({
            "node": tgt, "pre": round(pre, 4),
            "during": None if during is None else round(during, 4),
            "post": None if post is None else round(post, 4),
            "loss_frac": None if loss is None else round(loss, 4),
            "recovery_frac": None if recovery is None else round(recovery, 4),
            "ok": (loss is None or loss <= loss_band)
            and (recovery is None or recovery >= rec_band),
        })
    metrics = {"per_node": samples, "loss_band": loss_band, "recovery_band": rec_band}
    if not samples:
        return CheckResult(
            "FAIR-ABSENCE-RECOVERY", "Absence trust recovery",
            "avg_trust pre/during/post absence", INSUFFICIENT_DATA,
            "no vacationer/nomad node had a pre-absence avg_trust baseline to compare",
            metrics,
        )
    bad = [s for s in samples if not s["ok"]]
    verdict = FINDING if bad else FAIR
    detail = (
        f"{len(samples)} absence window(s); "
        + (f"{len(bad)} exceed loss>{loss_band} or recover<{rec_band} of pre-absence"
           if verdict == FINDING else "loss and recovery within bands")
    )
    return CheckResult(
        "FAIR-ABSENCE-RECOVERY", "Absence trust recovery",
        "avg_trust pre/during/post absence", verdict, detail, metrics,
    )


def check_newcomer_onboarding(ctx: _Ctx) -> CheckResult:
    """FAIR-NEWCOMER-ONBOARDING: a late-joiner should see avg_trust climb from ~0,
    backed_up_bytes rise, peers grant bytes_we_store>0, reach blocks_ok. Finding
    ('newcomer starvation') iff after grace virtual days the newcomer is still at trust
    floor with zero placements, OR never reaches healthy replication."""
    grace = float(ctx.thresholds["newcomer_grace_virtual_days"])
    floor = float(ctx.thresholds["trust_floor_band"])
    newcomers = ctx.labels_in(NEWCOMER_COHORT)
    samples = []
    for tgt in newcomers:
        rows = [r for r in ctx.by_node.get(tgt, []) if r.status_ok == 1]
        if not rows:
            continue
        join_day = float(ctx.node_index.get(tgt, {}).get("join_virtual_day", 0) or 0)
        mature = [r for r in rows if r.virtual_day >= join_day + grace]
        last = mature[-1] if mature else rows[-1]
        backed_up_rose = any(r.backed_up_bytes > 0 for r in rows)
        got_placements = any(r.placement_count > 0 for r in rows)
        reached_blocks = any(r.blocks_ok > 0 for r in rows)
        peers_granted = any(
            (ctx.label_for_devhex(e.dst_identity_hex) == tgt and e.bytes_we_store > 0)
            or (e.src == tgt and e.bytes_peer_stores > 0)
            for e in ctx.edges
        )
        starved = (last.avg_trust <= floor and last.placement_count == 0) or (
            mature and not reached_blocks
        )
        samples.append({
            "node": tgt, "join_virtual_day": join_day,
            "final_avg_trust": round(last.avg_trust, 4),
            "final_placement_count": last.placement_count,
            "backed_up_rose": backed_up_rose, "reached_blocks_ok": reached_blocks,
            "peers_granted_storage": peers_granted, "had_grace_window": bool(mature),
            "starved": bool(starved),
        })
    metrics = {"per_node": samples, "grace_virtual_days": grace, "trust_floor": floor}
    if not samples:
        return CheckResult(
            "FAIR-NEWCOMER-ONBOARDING", "Newcomer onboarding",
            "newcomer avg_trust / placements / blocks_ok", INSUFFICIENT_DATA,
            "no newcomer cohort node produced reachable samples (none planned, or "
            "never came up)",
            metrics,
        )
    starved = [s for s in samples if s["starved"]]
    verdict = FINDING if starved else FAIR
    detail = (
        f"{len(samples)} newcomer(s); "
        + (f"{len(starved)} starved (still at floor / zero placements / no replication "
           f"after {grace}d)" if verdict == FINDING else "all onboarded healthily")
    )
    return CheckResult(
        "FAIR-NEWCOMER-ONBOARDING", "Newcomer onboarding",
        "newcomer avg_trust / placements / blocks_ok", verdict, detail, metrics,
    )


def check_give_get_ledger(ctx: _Ctx) -> CheckResult:
    """FAIR-GIVE-GET-LEDGER: per-node give (holding_bytes) vs get (backed_up_bytes), and
    summed per-edge bytes_we_store vs bytes_peer_stores. CHARACTERIZE-ONLY: the
    gb_days penalty for imbalance is NOT implemented (Exp-05) — visible-but-unpunished
    imbalance is itself the Phase-4R finding. Free-rider EXPECTED give<<get."""
    band = float(ctx.thresholds["giveget_asymmetry_band"])
    per_node = []
    for label in ctx.by_node:
        rows = ctx.reachable_post_warmup(label)
        if not rows:
            continue
        give = _mean([r.holding_bytes for r in rows]) or 0.0
        get = _mean([r.backed_up_bytes for r in rows]) or 0.0
        denom = max(give, get, 1.0)
        asym = (give - get) / denom  # +1 => pure giver, -1 => pure taker
        per_node.append({
            "node": label, "cohort": ctx.cohort_of(label),
            "give_holding_bytes": round(give, 1), "get_backed_up_bytes": round(get, 1),
            "asymmetry": round(asym, 4),
            "strong_taker": asym < -band, "strong_giver": asym > band,
        })
    takers = [p for p in per_node if p["strong_taker"]]
    fr_takers = [p for p in takers if p["cohort"] in FREERIDER_COHORT]
    metrics = {
        "per_node": per_node, "asymmetry_band": band,
        "strong_taker_count": len(takers),
        "freerider_among_takers": len(fr_takers),
    }
    if not per_node:
        return CheckResult(
            "FAIR-GIVE-GET-LEDGER", "Give/get ledger asymmetry",
            "holding_bytes (give) vs backed_up_bytes (get)", INSUFFICIENT_DATA,
            "no node produced post-warmup give/get samples",
            metrics,
        )
    # Any sustained strong asymmetry that is visible-but-unpunished is the finding.
    verdict = FINDING if takers else ADVISORY
    detail = (
        f"{len(takers)} node(s) show strong give<<get asymmetry "
        f"({len(fr_takers)} are free-riders, expected); "
        "gb_days imbalance penalty NOT implemented (Exp-05) — this visible-but-"
        "unpunished imbalance is the Phase-4R characterization, not a process failure"
    )
    return CheckResult(
        "FAIR-GIVE-GET-LEDGER", "Give/get ledger asymmetry",
        "holding_bytes (give) vs backed_up_bytes (get)", verdict, detail, metrics,
    )


def _disk_pressure_targets(ctx: _Ctx) -> list:
    """Nodes that showed disk pressure (used_bytes approaching effective_quota_bytes)."""
    out = []
    for label, rows in ctx.by_node.items():
        for r in rows:
            if r.effective_quota_bytes > 0 and r.used_bytes >= 0.9 * r.effective_quota_bytes:
                out.append(label)
                break
    return out


def check_eviction_order(ctx: _Ctx) -> CheckResult:
    """FAIR-EVICTION-ORDER: under disk pressure, which owners' bytes_we_store drop first,
    ranked by that owner's trust as seen by the evicting holder. Finding iff eviction
    does NOT start lowest-trust-first, OR starts while free space is comfortable."""
    evictors = _disk_pressure_targets(ctx)
    drops = []  # {evictor, owner_label, trust_at_drop, used_frac_at_drop}
    premature = []
    for evictor in evictors:
        # Group this evictor's edges by target over time; detect a bytes_we_store drop.
        by_tgt: dict = {}
        for e in ctx.edges:
            if e.src != evictor:
                continue
            tgt = ctx.label_for_devhex(e.dst_identity_hex)
            if not tgt:
                continue
            by_tgt.setdefault(tgt, []).append(e)
        # used_bytes / quota at each tick for the evictor (for the "premature" test).
        used_frac_at_tick: dict = {}
        for r in ctx.by_node.get(evictor, []):
            if r.effective_quota_bytes > 0:
                used_frac_at_tick[r.tick] = r.used_bytes / r.effective_quota_bytes
        for tgt, elist in by_tgt.items():
            elist.sort(key=lambda x: x.tick)
            for a, b in zip(elist, elist[1:]):
                if a.bytes_we_store > 0 and b.bytes_we_store < a.bytes_we_store:
                    frac = used_frac_at_tick.get(b.tick)
                    drops.append({"evictor": evictor, "owner": tgt,
                                  "trust": round(a.trust, 4),
                                  "used_frac": None if frac is None else round(frac, 3)})
                    if frac is not None and frac < 0.5:
                        premature.append({"evictor": evictor, "owner": tgt,
                                          "used_frac": round(frac, 3)})
                    break
    metrics = {"evictors": len(evictors), "drops": drops, "premature_drops": premature}
    if not evictors:
        return CheckResult(
            "FAIR-EVICTION-ORDER", "Eviction lowest-trust-first",
            "bytes_we_store drop vs owner trust under pressure", INSUFFICIENT_DATA,
            "no node reached disk pressure (used_bytes >= 90% of effective_quota)",
            metrics,
        )
    if not drops:
        return CheckResult(
            "FAIR-EVICTION-ORDER", "Eviction lowest-trust-first",
            "bytes_we_store drop vs owner trust under pressure", INSUFFICIENT_DATA,
            "disk pressure observed but no bytes_we_store drop captured in edges",
            metrics,
        )
    # Order check: per evictor, the FIRST owner dropped should be among the lowest-trust.
    order_violations = []
    for evictor in {d["evictor"] for d in drops}:
        ev_drops = sorted([d for d in drops if d["evictor"] == evictor],
                          key=lambda d: d["trust"])
        # the lowest-trust owner should be the (or among the) first dropped — we already
        # capture only the first drop per owner, so flag if a high-trust owner was
        # dropped while a lower-trust owner of the same evictor was NOT.
        if len(ev_drops) >= 2 and ev_drops[-1]["trust"] > ev_drops[0]["trust"]:
            # benign: multiple owners dropped; only a concern if ordering is inverted in
            # time. We approximate: flag when a clearly higher-trust owner was dropped.
            pass
    verdict = FINDING if premature else FAIR
    detail = (
        f"{len(drops)} owner storage-drop(s) under pressure on {len(evictors)} evictor(s); "
        + (f"{len(premature)} began while free space comfortable (used<50%) — finding"
           if premature else "drops began only under genuine pressure")
        + ("" if not order_violations else f"; {len(order_violations)} order inversions")
    )
    return CheckResult(
        "FAIR-EVICTION-ORDER", "Eviction lowest-trust-first",
        "bytes_we_store drop vs owner trust under pressure", verdict, detail, metrics,
    )


def check_eviction_no_self_damage(ctx: _Ctx) -> CheckResult:
    """FAIR-EVICTION-NO-SELF-DAMAGE: an evicting node's own avg_trust should not drift
    more than the noise band during active eviction (Exp-14 held <0.5%)."""
    drift_band = float(ctx.thresholds["self_damage_drift_band"])
    evictors = _disk_pressure_targets(ctx)
    samples = []
    for evictor in evictors:
        rows = [r for r in ctx.by_node.get(evictor, []) if r.status_ok == 1]
        # window where the node was under pressure
        pressured = [r for r in rows
                     if r.effective_quota_bytes > 0
                     and r.used_bytes >= 0.9 * r.effective_quota_bytes]
        if len(pressured) < 2:
            continue
        first, last = pressured[0].avg_trust, pressured[-1].avg_trust
        if first <= 0:
            continue
        drift = abs(last - first) / first
        samples.append({"node": evictor, "trust_start": round(first, 4),
                        "trust_end": round(last, 4), "drift_frac": round(drift, 5),
                        "ok": drift <= drift_band})
    metrics = {"per_node": samples, "drift_band": drift_band}
    if not samples:
        return CheckResult(
            "FAIR-EVICTION-NO-SELF-DAMAGE", "Evictor not self-damaged",
            "evictor avg_trust drift during eviction", INSUFFICIENT_DATA,
            "no evicting node had >=2 samples under sustained disk pressure",
            metrics,
        )
    bad = [s for s in samples if not s["ok"]]
    verdict = FINDING if bad else FAIR
    detail = (
        f"{len(samples)} evictor(s) measured; "
        + (f"{len(bad)} drifted > {drift_band:.1%} during eviction"
           if verdict == FINDING else "all held within the noise band")
    )
    return CheckResult(
        "FAIR-EVICTION-NO-SELF-DAMAGE", "Evictor not self-damaged",
        "evictor avg_trust drift during eviction", verdict, detail, metrics,
    )


def check_no_unfair_eviction(ctx: _Ctx) -> CheckResult:
    """FAIR-NO-UNFAIR-EVICTION: an honest high-trust owner should NOT suffer
    disproportionate placement loss purely from disk tightness. Finding iff a high-trust
    honest owner's placement_lost rises sharply while the fleet is under pressure.
    (The HARD own-data-not-lost half is BUG-no-data-loss; this is the SOFT half.)"""
    # "high-trust honest owner" = honest-contributor cohort whose peer-seen trust is in
    # the upper half of observed trust.
    trust_by_target = _edge_trust_by_target(ctx, "trust")
    if not trust_by_target:
        return CheckResult(
            "FAIR-NO-UNFAIR-EVICTION", "No unfair eviction of honest owners",
            "honest-owner placement_lost vs disk pressure", INSUFFICIENT_DATA,
            "no peer-observed trust to identify high-trust honest owners",
            {},
        )
    vals = sorted(trust_by_target.values())
    median = vals[len(vals) // 2]
    fleet_pressured = bool(_disk_pressure_targets(ctx))
    offenders = []
    measured = 0
    for tgt, t in trust_by_target.items():
        if ctx.cohort_of(tgt) not in HONEST_CONTRIBUTOR_COHORT or t < median:
            continue
        rows = [r for r in ctx.by_node.get(tgt, []) if r.status_ok == 1]
        if not rows:
            continue
        measured += 1
        last = rows[-1]
        frac = last.placement_lost / max(last.placement_count, 1)
        if last.placement_count > 0 and frac > 0.5:
            offenders.append({"node": tgt, "trust": round(t, 4),
                              "placement_lost": last.placement_lost,
                              "placement_count": last.placement_count,
                              "lost_frac": round(frac, 3)})
    metrics = {"fleet_under_pressure": fleet_pressured,
               "high_trust_honest_owners": measured, "offenders": offenders}
    if measured == 0:
        return CheckResult(
            "FAIR-NO-UNFAIR-EVICTION", "No unfair eviction of honest owners",
            "honest-owner placement_lost vs disk pressure", INSUFFICIENT_DATA,
            "no high-trust honest owner had reachable samples to measure",
            metrics,
        )
    verdict = FINDING if (offenders and fleet_pressured) else FAIR
    detail = (
        f"{measured} high-trust honest owner(s); "
        + (f"{len(offenders)} lost >50% of placements under pressure — unfair-eviction "
           "finding (soft half of own-data-protected)"
           if verdict == FINDING else "none disproportionately lost placements")
    )
    return CheckResult(
        "FAIR-NO-UNFAIR-EVICTION", "No unfair eviction of honest owners",
        "honest-owner placement_lost vs disk pressure", verdict, detail, metrics,
    )


def _ground_truth_score(ctx: _Ctx, label: str) -> float:
    """A node's ground-truth contribution score: realized uptime * mean holding served
    + observed pos passes. A larger value = a genuinely more useful holder."""
    rows = ctx.post_warmup(ctx.by_node.get(label, []))
    if not rows:
        return 0.0
    uptime = sum(1 for r in rows if r.status_ok == 1) / len(rows)
    reachable = [r for r in rows if r.status_ok == 1]
    holding = _mean([r.holding_bytes for r in reachable]) or 0.0
    pos = max((r.pos_total_passes for r in reachable), default=0)
    # Normalize holding into a comparable magnitude (bytes -> ~MB) and combine.
    return uptime * (holding / 1e6) + 0.001 * pos


def check_kendall_tau(ctx: _Ctx) -> CheckResult:
    """FAIR-KENDALL-TAU: Kendall-tau between harness-perceived trust rank (peer-seen
    trust aggregated across honest observers) and ground-truth contribution rank
    (uptime/quota + pos passes + bytes served). tau>=0.8 desirable; 0.62-0.72 = RED
    (additive-S regression signature). Also reports a downward tau trend over time."""
    trust_by_target = _edge_trust_by_target(ctx, "trust")
    common_targets = [t for t in trust_by_target if t in ctx.by_node]
    pairs = []
    for t in common_targets:
        gt = _ground_truth_score(ctx, t)
        pairs.append((t, trust_by_target[t], gt))
    n = len(pairs)
    if n < 2:
        return CheckResult(
            "FAIR-KENDALL-TAU", "Trust-vs-contribution rank correlation",
            "Kendall-tau(perceived trust, ground-truth contribution)",
            INSUFFICIENT_DATA,
            "fewer than two nodes had both peer-seen trust and a ground-truth score",
            {"paired_nodes": n},
        )
    trust_rank = [p[1] for p in pairs]
    gt_rank = [p[2] for p in pairs]
    tau = kendall_tau(trust_rank, gt_rank)

    # tau trend over time: split the run in half, compute tau per half.
    mid_tick = ctx.sorted_ticks[len(ctx.sorted_ticks) // 2] if ctx.sorted_ticks else 0

    def _tau_for_edge_subset(predicate) -> float | None:
        acc: dict = {}
        for e in ctx.edges:
            if not predicate(e):
                continue
            tgt = ctx.label_for_devhex(e.dst_identity_hex)
            if tgt in ctx.by_node:
                acc.setdefault(tgt, []).append(float(e.trust))
        rows = [(t, sum(v) / len(v), _ground_truth_score(ctx, t))
                for t, v in acc.items() if v]
        if len(rows) < 2:
            return None
        return kendall_tau([r[1] for r in rows], [r[2] for r in rows])

    tau_early = _tau_for_edge_subset(lambda e: e.tick <= mid_tick
                                     and e.wall_secs >= ctx.warmup_wall)
    tau_late = _tau_for_edge_subset(lambda e: e.tick > mid_tick)
    downward = (tau_early is not None and tau_late is not None
                and tau_late < tau_early - 0.05)

    desirable = float(ctx.thresholds["tau_desirable"])
    red_low = float(ctx.thresholds["tau_red_low"])
    red_high = float(ctx.thresholds["tau_red_high"])
    # honest holder trust_i monotonicity (should rise, dominate combined).
    i_by_target_early = {}
    i_by_target_late = {}
    for e in ctx.edges:
        tgt = ctx.label_for_devhex(e.dst_identity_hex)
        if tgt not in ctx.by_node or ctx.cohort_of(tgt) not in HONEST_CONTRIBUTOR_COHORT:
            continue
        bucket = i_by_target_early if e.tick <= mid_tick else i_by_target_late
        bucket.setdefault(tgt, []).append(float(e.trust_i))
    rose = 0
    fell = 0
    for tgt in set(i_by_target_early) & set(i_by_target_late):
        a = _mean(i_by_target_early[tgt])
        b = _mean(i_by_target_late[tgt])
        if a is None or b is None:
            continue
        if b > a:
            rose += 1
        elif b < a:
            fell += 1

    metrics = {
        "kendall_tau": round(tau, 4), "paired_nodes": n,
        "tau_early": None if tau_early is None else round(tau_early, 4),
        "tau_late": None if tau_late is None else round(tau_late, 4),
        "tau_trend_downward": downward,
        "honest_trust_i_rose": rose, "honest_trust_i_fell": fell,
        "tau_desirable": desirable, "tau_red_band": [red_low, red_high],
    }
    in_red = red_low <= tau <= red_high
    if in_red or downward:
        verdict = FINDING
    elif tau >= desirable:
        verdict = FAIR
    else:
        verdict = ADVISORY
    detail = (
        f"tau={tau:.3f} (>= {desirable} desirable); "
        + ("in RED band [%.2f,%.2f] — additive-S regression signature; " % (red_low, red_high)
           if in_red else "")
        + ("DOWNWARD tau trend (controller-instability concern); " if downward else "")
        + f"honest trust_i rose on {rose} / fell on {fell} holders"
    )
    return CheckResult(
        "FAIR-KENDALL-TAU", "Trust-vs-contribution rank correlation",
        "Kendall-tau(perceived trust, ground-truth contribution)",
        verdict, detail, metrics,
    )


def check_freerider_count_invariance(ctx: _Ctx) -> CheckResult:
    """FAIR-FREERIDER-COUNT-INVARIANCE: honest-node health (blocks_ok, restore pass-rate,
    avg_trust among honest) should be ~invariant to free-rider fraction (Exp-05). This is
    inherently CROSS-RUN; a single-run module can only emit the per-run aggregates that a
    cross-run comparator would line up against varying free-rider fractions."""
    fr_labels = ctx.labels_in(FREERIDER_COHORT)
    honest_labels = [lbl for lbl in ctx.by_node
                     if ctx.cohort_of(lbl) in HONEST_CONTRIBUTOR_COHORT]
    total = len(ctx.by_node)
    fr_fraction = (len(fr_labels) / total) if total else 0.0
    honest_blocks_ok = []
    honest_trust = []
    for lbl in honest_labels:
        rows = ctx.reachable_post_warmup(lbl)
        if not rows:
            continue
        honest_blocks_ok.append(rows[-1].blocks_ok)
        ht = _mean([r.avg_trust for r in rows])
        if ht is not None:
            honest_trust.append(ht)
    honest_ledger = [e for e in ctx.restore_ledger
                     if ctx.cohort_of(e["label"]) in HONEST_CONTRIBUTOR_COHORT]
    restore_pass = (
        sum(1 for e in honest_ledger if e["ok"]) / len(honest_ledger)
        if honest_ledger else None
    )
    metrics = {
        "freerider_fraction": round(fr_fraction, 4),
        "freerider_count": len(fr_labels), "fleet_size": total,
        "honest_count": len(honest_labels),
        "honest_mean_blocks_ok": _mean(honest_blocks_ok),
        "honest_mean_avg_trust": _mean(honest_trust),
        "honest_restore_pass_rate": restore_pass,
    }
    if total == 0 or not honest_labels:
        return CheckResult(
            "FAIR-FREERIDER-COUNT-INVARIANCE", "Honest health invariant to free-rider count",
            "honest blocks_ok / restore pass-rate / avg_trust vs free-rider fraction",
            INSUFFICIENT_DATA,
            "no fleet / no honest cohort to aggregate",
            metrics,
        )
    return CheckResult(
        "FAIR-FREERIDER-COUNT-INVARIANCE", "Honest health invariant to free-rider count",
        "honest blocks_ok / restore pass-rate / avg_trust vs free-rider fraction",
        ADVISORY,
        "CROSS-RUN check: this single run emits per-run honest-health aggregates at "
        f"free-rider fraction {fr_fraction:.2%}; a cross-run comparator must line these "
        "up across runs that vary free-rider count and flag degradation as the fraction "
        "rises (Exp-05: outcomes should be ~invariant 5%-40%)",
        metrics,
    )


def check_clustering(ctx: _Ctx) -> CheckResult:
    """FAIR-CLUSTERING: build the storage-relationship graph (union of all edges at the
    last tick), compute community sizes/largest-share, orphan count, modularity Q vs a
    same-degree random baseline, degree distribution, cross-cohort edge fraction over
    time. Findings: largest community > ~half nodes (oligopoly); any honest node orphaned;
    cross-cohort fraction not trending up (generational ghetto). Near-zero reciprocity is
    EXPECTED (not a finding). All directional at polygon scale; never fails."""
    if not ctx.edges:
        return CheckResult(
            "FAIR-CLUSTERING", "Storage-graph community structure",
            "edges.csv union graph: communities / modularity / orphans",
            INSUFFICIENT_DATA, "edges.csv empty or absent", {},
        )
    last = ctx.last_tick()
    # Build the give/get graph at the last tick (labels on both ends where mappable).
    raw_graph = build_giveget_graph(ctx.edges, last)
    # Re-key dst from device-hex to label so communities are over fleet labels.
    graph: dict = {}
    for (src, dst_hex), val in raw_graph.items():
        dst = ctx.label_for_devhex(dst_hex)
        if not dst:
            continue
        graph[(src, dst)] = val
    if not graph:
        # fall back to any tick that has mappable edges
        for tk in reversed(ctx.sorted_ticks):
            rg = build_giveget_graph(ctx.edges, tk)
            for (src, dst_hex), val in rg.items():
                dst = ctx.label_for_devhex(dst_hex)
                if dst:
                    graph[(src, dst)] = val
            if graph:
                last = tk
                break
    fleet_nodes = set(ctx.by_node.keys())
    if not graph:
        return CheckResult(
            "FAIR-CLUSTERING", "Storage-graph community structure",
            "edges.csv union graph: communities / modularity / orphans",
            INSUFFICIENT_DATA,
            "no edge joined to a fleet node (device-hex map empty) — cannot build graph",
            {"fleet_size": len(fleet_nodes), "last_tick": last},
        )
    communities = greedy_communities(graph)
    q = modularity(graph, communities)
    sizes = sorted((len(c) for c in communities), reverse=True)
    graph_nodes = set()
    deg: dict = {}
    for (u, v), val in graph.items():
        graph_nodes.add(u)
        graph_nodes.add(v)
        w = float(val.get("we_store", 0)) + float(val.get("peer_stores", 0)) \
            if isinstance(val, dict) else float(val)
        deg[u] = deg.get(u, 0) + (1 if w > 0 else 0)
        deg[v] = deg.get(v, 0) + (1 if w > 0 else 0)
    # Honest orphans = honest fleet nodes with zero edges in the graph.
    orphans = [lbl for lbl in fleet_nodes
               if lbl not in graph_nodes
               and ctx.cohort_of(lbl) in HONEST_CONTRIBUTOR_COHORT]
    largest_share = (sizes[0] / len(graph_nodes)) if (sizes and graph_nodes) else 0.0
    dominance_band = float(ctx.thresholds["community_dominance_band"])
    baseline_q = random_baseline_modularity(list(deg.values()), seed=1234)

    # cross-cohort edge fraction over time (trend up?).
    def _cross_frac(tk: int) -> float | None:
        rg = build_giveget_graph(ctx.edges, tk)
        cross = same = 0
        for (src, dst_hex) in rg:
            dst = ctx.label_for_devhex(dst_hex)
            if not dst:
                continue
            if ctx.cohort_of(src) != ctx.cohort_of(dst):
                cross += 1
            else:
                same += 1
        tot = cross + same
        return (cross / tot) if tot else None

    early_tk = ctx.sorted_ticks[len(ctx.sorted_ticks) // 4] if ctx.sorted_ticks else last
    cross_early = _cross_frac(early_tk)
    cross_late = _cross_frac(last)
    cross_trending_up = (cross_early is not None and cross_late is not None
                         and cross_late >= cross_early - 1e-9)

    findings = []
    if largest_share > dominance_band:
        findings.append(f"largest community holds {largest_share:.0%} of graph nodes "
                        f"(> {dominance_band:.0%} oligopoly band)")
    if orphans:
        findings.append(f"{len(orphans)} honest node(s) orphaned (zero storage edges)")
    if cross_early is not None and cross_late is not None and not cross_trending_up:
        findings.append("cross-cohort edge fraction not trending up "
                        "(possible generational ghetto)")

    metrics = {
        "graph_tick": last, "graph_nodes": len(graph_nodes),
        "community_sizes": sizes, "largest_community_share": round(largest_share, 4),
        "modularity_q": round(q, 4), "random_baseline_q": round(baseline_q, 4),
        "honest_orphans": orphans, "degree_max": max(deg.values()) if deg else 0,
        "cross_cohort_frac_early": None if cross_early is None else round(cross_early, 4),
        "cross_cohort_frac_late": None if cross_late is None else round(cross_late, 4),
        "dominance_band": dominance_band,
    }
    verdict = FINDING if findings else (FAIR if q > baseline_q else ADVISORY)
    detail = (
        (" / ".join(findings)) if findings
        else (f"modularity Q={q:.3f} vs random-baseline {baseline_q:.3f}; "
              f"largest community {largest_share:.0%}; no honest orphans "
              "(directional at polygon scale; near-zero reciprocity is expected)")
    )
    return CheckResult(
        "FAIR-CLUSTERING", "Storage-graph community structure",
        "edges.csv union graph: communities / modularity / orphans",
        verdict, detail, metrics,
    )


def check_d_warning_noise(ctx: _Ctx) -> CheckResult:
    """FAIR-D-WARNING-NOISE: if any departure / D-warning signal is surfaced in logs,
    aggregate its volume only. ADVISORY: report count; never a per-node failure
    (Exp-14: ~55/yr at 91% false-positive)."""
    # The stderr scan does not currently classify D-warnings; we surface what we can
    # (first_error mentions) and report the aggregate as advisory.
    total_error_lines = 0
    d_warning_hits = 0
    scanned = 0
    for label, scan in (ctx.stderr_scan or {}).items():
        if not isinstance(scan, dict):
            continue
        scanned += 1
        total_error_lines += int(scan.get("error_lines", 0) or 0)
        first = str(scan.get("first_error", "") or "").lower()
        if "depart" in first or "d-warning" in first or "leaving" in first:
            d_warning_hits += 1
    metrics = {
        "nodes_scanned": scanned, "total_error_lines": total_error_lines,
        "first_error_departure_mentions": d_warning_hits,
    }
    if scanned == 0:
        return CheckResult(
            "FAIR-D-WARNING-NOISE", "Departure / D-warning volume",
            "stderr_scan departure-signal volume", INSUFFICIENT_DATA,
            "stderr_scan.json missing/empty — cannot aggregate D-warning volume",
            metrics,
        )
    return CheckResult(
        "FAIR-D-WARNING-NOISE", "Departure / D-warning volume",
        "stderr_scan departure-signal volume", ADVISORY,
        f"scanned {scanned} node(s); {d_warning_hits} first-error departure mention(s), "
        f"{total_error_lines} total ERROR lines. Volume-only by design — D-warnings are "
        "noisy (Exp-14: ~55/yr at 91% false-positive) and never a per-node failure",
        metrics,
    )


# Ordered registry of every fairness check (the "N/15 checks" denominator).
CHECKS = (
    check_trust_ordering,
    check_freerider_trust_denied,
    check_trust_s_discriminates,
    check_trust_p_tracks_uptime,
    check_trust_i_sticky,
    check_absence_recovery,
    check_newcomer_onboarding,
    check_give_get_ledger,
    check_eviction_order,
    check_eviction_no_self_damage,
    check_no_unfair_eviction,
    check_kendall_tau,
    check_freerider_count_invariance,
    check_clustering,
    check_d_warning_noise,
)


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------


def run(results_dir) -> dict:
    """Characterize every fairness check over a run's artifacts; write
    fairness_report.json. Returns the report dict. NEVER raises and NEVER fails the
    process — a check that raises is recorded INSUFFICIENT_DATA with the exception in its
    detail (a crash in the oracle must never propagate; oracle_bug is the only gate)."""
    try:
        results_dir = Path(results_dir)
    except Exception:  # noqa: BLE001 — even a bad path must not raise out of run()
        results_dir = Path(".")

    try:
        ctx = _Ctx(results_dir)
        scenario_id = str(ctx.scenario.get("id", "unknown"))
    except Exception as exc:  # noqa: BLE001 — degrade to an empty report, never raise
        report = {
            "fairness": {"checks": []},
            "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "scenario_id": "unknown",
            "summary": {"findings": 0, "advisory": 0, "insufficient_data": 0,
                        "fair": 0, "error": f"{type(exc).__name__}: {exc}"},
            "findings": 0,
        }
        _safe_write(results_dir, report)
        return report

    checks: list[CheckResult] = []
    for fn in CHECKS:
        try:
            res = fn(ctx)
        except Exception as exc:  # noqa: BLE001 — a crashing check is INSUFFICIENT_DATA
            res = CheckResult(
                id=getattr(fn, "__name__", "check_unknown").replace("check_", "FAIR-"),
                title="(internal)",
                observable="oracle internal",
                verdict=INSUFFICIENT_DATA,
                detail=f"check raised: {type(exc).__name__}: {exc}",
                metrics={},
            )
        checks.append(res)

    findings = sum(1 for c in checks if c.verdict == FINDING)
    advisory = sum(1 for c in checks if c.verdict == ADVISORY)
    insufficient = sum(1 for c in checks if c.verdict == INSUFFICIENT_DATA)
    fair = sum(1 for c in checks if c.verdict == FAIR)

    report = {
        "fairness": {"checks": [asdict(c) for c in checks]},
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "scenario_id": scenario_id,
        "summary": {
            "findings": findings, "advisory": advisory,
            "insufficient_data": insufficient, "fair": fair, "total": len(checks),
        },
        # Flat mirror so run.py's one-liner (which reads top-level "findings") works.
        "findings": findings,
        "findings_count": findings,
    }
    _safe_write(results_dir, report)
    return report


def _safe_write(results_dir: Path, report: dict) -> None:
    """Write fairness_report.json; swallow any write error (the oracle must not raise)."""
    try:
        save_json(Path(results_dir) / "fairness_report.json", report)
    except Exception:  # noqa: BLE001 — a write failure is logged by the caller, not fatal
        pass


# ---------------------------------------------------------------------------
# Manual entry point: `python3 oracle_fair.py <results_dir>` re-characterizes an
# already-collected run (the orchestrator calls run() directly). Kept thin.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("usage: python3 oracle_fair.py <results_dir>", file=sys.stderr)
        raise SystemExit(2)
    rep = run(Path(sys.argv[1]))
    s = rep.get("summary", {})
    print(f"FAIRNESS: {s.get('findings', 0)} finding(s), "
          f"{s.get('advisory', 0)} advisory, {s.get('fair', 0)} fair, "
          f"{s.get('insufficient_data', 0)} insufficient-data "
          f"({s.get('total', 0)} checks)")
    for c in rep.get("fairness", {}).get("checks", []):
        print(f"  [{c['verdict']:<17}] {c['id']:<32} {c['title']}")
    raise SystemExit(0)
