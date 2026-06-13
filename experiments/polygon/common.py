"""Viaticum Polygon — shared library (typed schemas + pure-stdlib analysis math).

WHY THIS MODULE EXISTS (intent / acceptance criteria — fixed before the code):
  The polygon is a *reusable* instrumented E2E proving ground for the viaticum
  daemon, not a one-shot test. Many independent modules (collector, oracles,
  fleet, churn, config_gen) must agree byte-for-byte on the on-disk artifact
  format — otherwise an oracle silently misreads a column the collector wrote and
  emits a false verdict. This module is the SINGLE SOURCE OF TRUTH for:

    AC1: the exact CSV schema of timeseries.csv and edges.csv. Headers are DERIVED
         from the dataclass field order (one definition, never hand-duplicated), so
         the writer (collector) and the readers (oracle_bug / oracle_fair) can never
         drift. Adding a field in one place adds the column everywhere.
    AC2: the results-dir layout (timestamped, scenario-tagged, never overwriting a
         prior run — the polygon is run MANY TIMES and each run is provenance).
    AC3: the give/get graph reconstruction. Each node reports only its TOP-20 peers
         by trust (PeerSummary cap), so the full fleet graph is the UNION of every
         node's peers[] list. The join key is the first-8-hex device identity:
         StatusData.device_id (a node's self-report) == PeerSummary.identity_hex
         (what its peers report for it). This module joins on exactly that key.
    AC4: the fairness/clustering math (Kendall-tau rank correlation, pure-Python
         greedy-modularity community detection + a same-degree random baseline,
         back-half linear-fit slope for growth/leak gates, coefficient of variation
         for balance dispersion) — all stdlib only, no numpy/networkx.
    AC5: virtual<->wall time conversion. The daemon divides every internal cadence
         by time_scale; the orchestrator maps virtual days onto wall-clock seconds
         the same way. A single conversion pair keeps churn/onboarding/oracles
         consistent with what the daemon actually does.

  This module launches NO processes and knows NO daemon internals beyond the field
  NAMES it copies from cli/types.rs (StatusData / PeerSummary / TableStats /
  ImportanceBucketStats). It is pure data + math. stdlib only.
"""

from __future__ import annotations

import csv
import datetime as _dt
import json
import math
import random
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Constants mirrored from the daemon (field names only — see cli/types.rs).
# ---------------------------------------------------------------------------

# StatusData.by_importance always has exactly these 5 buckets, in this order.
IMPORTANCE_BUCKETS = ("critical", "high", "medium", "low", "trivial")

# TableStats fields (crates/viaticum-core/src/db/mod.rs). Order is load-bearing
# only for column naming — we prefix each with "tbl_" in the timeseries header.
TABLE_STAT_FIELDS = (
    "files",
    "source_blocks",
    "symbol_placements",
    "peers",
    "holdings",
    "event_log",
    "pos_weekly",
    "file_holders",
    "holder_files",
    "mailbox_entries",
)


# ---------------------------------------------------------------------------
# Row schemas — these dataclasses ARE the CSV schema.
# ---------------------------------------------------------------------------


@dataclass
class TimeseriesRow:
    """One sample of one node at one tick. Field order == CSV column order.

    Harness-side bookkeeping comes first, then the flattened StatusData scalars,
    then the flattened TableStats counts (tbl_*), then the per-importance-bucket
    aggregates (imp_<bucket>_count / imp_<bucket>_mean_p), then the externally
    measured resource footprints (ext_*). A node that is DOWN at this tick still
    emits a row: status_ok=0 and every daemon-sourced field stays at its default
    so the time series has no gaps (gaps would confuse the slope/leak oracles).
    """

    # --- harness bookkeeping ---
    tick: int = 0
    wall_secs: float = 0.0
    virtual_day: float = 0.0
    label: str = ""
    archetype: str = ""
    up_state: str = ""          # 'up' | 'down' (intended state from churn queue)
    status_ok: int = 0          # 1 if status --json succeeded this tick, else 0

    # --- StatusData identity (recorded but mostly constant) ---
    device_id: str = ""

    # --- StatusData scalars (names match cli/types.rs exactly) ---
    peer_count: int = 0
    peer_count_connected: int = 0
    peer_count_authenticated: int = 0
    avg_trust: float = 0.0
    holding_bytes: int = 0
    backed_up_files: int = 0
    backed_up_bytes: int = 0
    blocks_needing_repair: int = 0
    effective_quota_bytes: int = 0
    used_bytes: int = 0
    pos_total_challenges: int = 0
    pos_total_passes: int = 0
    placement_count: int = 0
    placement_alive: int = 0
    placement_lost: int = 0
    blocks_ok: int = 0
    blocks_at_risk: int = 0

    # --- TableStats (tbl_*) ---
    tbl_files: int = 0
    tbl_source_blocks: int = 0
    tbl_symbol_placements: int = 0
    tbl_peers: int = 0
    tbl_holdings: int = 0
    tbl_event_log: int = 0
    tbl_pos_weekly: int = 0
    tbl_file_holders: int = 0
    tbl_holder_files: int = 0
    tbl_mailbox_entries: int = 0

    # --- by_importance buckets ---
    imp_critical_count: int = 0
    imp_critical_mean_p: float = 0.0
    imp_high_count: int = 0
    imp_high_mean_p: float = 0.0
    imp_medium_count: int = 0
    imp_medium_mean_p: float = 0.0
    imp_low_count: int = 0
    imp_low_mean_p: float = 0.0
    imp_trivial_count: int = 0
    imp_trivial_mean_p: float = 0.0

    # --- externally measured resource footprint ---
    ext_rss_kb: int = 0
    ext_du_holdings_kb: int = 0
    ext_du_db_redb_bytes: int = 0
    ext_du_datadir_kb: int = 0


@dataclass
class EdgeRow:
    """One PeerSummary as seen by one node at one tick. Field order == CSV order.

    src is the OBSERVING node's launch label (e.g. 'node-03'); dst_identity_hex is
    the first-8-hex of the observed peer (PeerSummary.identity_hex), which the
    collector/oracle later joins against each node's StatusData.device_id to map
    the edge onto a launch label. bytes_we_store / bytes_peer_stores are from src's
    point of view: 'we' == src, 'peer' == the dst peer.
    """

    tick: int = 0
    wall_secs: float = 0.0
    virtual_day: float = 0.0
    src: str = ""                 # observing node launch label
    src_archetype: str = ""
    dst_identity_hex: str = ""    # PeerSummary.identity_hex (first-8-hex)
    trust: float = 0.0
    trust_p: float = 0.0
    trust_i: float = 0.0
    trust_s: float = 0.0
    bytes_we_store: int = 0       # src stores this many bytes FOR dst
    bytes_peer_stores: int = 0    # dst stores this many bytes FOR src
    pos_challenges_recent: int = 0
    pos_passes_recent: int = 0
    last_seen: str = ""
    link: str = ""                # 'auth' | 'conn' | 'known'


# ---------------------------------------------------------------------------
# Planning dataclasses (produced by archetypes/config_gen, consumed by churn).
# ---------------------------------------------------------------------------


@dataclass
class ChurnEvent:
    """A scheduled kill / restart / join, mapped to a wall-clock instant.

    event_type in {'kill', 'restart', 'join'}. targets is the list of node labels
    the event applies to (usually one; mass-departure events may list many).
    virtual_day is the scenario-relative virtual time; wall_secs is that instant in
    real seconds since fleet start (virtual_to_wall(virtual_day, time_scale)).
    """

    virtual_day: float = 0.0
    wall_secs: float = 0.0
    event_type: str = ""
    targets: list[str] = field(default_factory=list)


@dataclass
class NodePlan:
    """Everything the fleet needs to stand up and drive one node.

    watch_files is a list of (filename, size_bytes) the config_gen writes into the
    node's watch dir with seeded-random content. churn_schedule is the per-node
    uptime pattern already expanded into (event_type, virtual_day) tuples by
    archetypes.build_node_plan; churn.build_event_queue turns those into ChurnEvents.
    """

    label: str = ""
    archetype: str = ""
    soft_quota_gb: float = 0.0
    hard_quota_gb: float = 0.0
    disk_reserve_gb: float = 0.0
    watch_files: list[tuple[str, int]] = field(default_factory=list)
    importance_multiplier: float = 1.0
    join_virtual_day: int = 0
    churn_schedule: list[tuple[str, int]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CSV header derivation (single source of truth).
# ---------------------------------------------------------------------------


def timeseries_header() -> list[str]:
    """Exact column order of timeseries.csv, derived from TimeseriesRow."""
    return [f.name for f in fields(TimeseriesRow)]


def edges_header() -> list[str]:
    """Exact column order of edges.csv, derived from EdgeRow."""
    return [f.name for f in fields(EdgeRow)]


def _coerce(value: str, py_type) -> object:
    """Parse a CSV cell back into the dataclass field's declared type."""
    if py_type is int:
        # CSV may carry an empty cell for a down-node default; treat as 0.
        if value == "":
            return 0
        # tolerate floats written for an int column (e.g. "3.0")
        try:
            return int(value)
        except ValueError:
            return int(float(value))
    if py_type is float:
        if value == "":
            return 0.0
        return float(value)
    return value  # str


def _row_to_dict(row, header: list[str]) -> dict:
    return {name: getattr(row, name) for name in header}


def write_timeseries_row(fh, row: TimeseriesRow) -> None:
    """Append one TimeseriesRow to an already-open file handle.

    The caller is responsible for having written the header (use
    open_timeseries_writer, which returns a (file, writer) the collector keeps
    open for the whole run). This signature matches the interface contract; for
    convenience the writer is a csv.DictWriter bound to the canonical header.
    """
    writer = csv.DictWriter(fh, fieldnames=timeseries_header())
    writer.writerow(_row_to_dict(row, timeseries_header()))


def write_edge_row(fh, row: EdgeRow) -> None:
    """Append one EdgeRow to an already-open file handle (see write_timeseries_row)."""
    writer = csv.DictWriter(fh, fieldnames=edges_header())
    writer.writerow(_row_to_dict(row, edges_header()))


def open_timeseries_writer(path: Path):
    """Open timeseries.csv for writing and emit the header. Returns (fh, writer)."""
    fh = open(path, "w", newline="")
    writer = csv.DictWriter(fh, fieldnames=timeseries_header())
    writer.writeheader()
    return fh, writer


def open_edges_writer(path: Path):
    """Open edges.csv for writing and emit the header. Returns (fh, writer)."""
    fh = open(path, "w", newline="")
    writer = csv.DictWriter(fh, fieldnames=edges_header())
    writer.writeheader()
    return fh, writer


def read_timeseries(path: Path) -> Iterator[TimeseriesRow]:
    """Stream timeseries.csv back as typed TimeseriesRow objects."""
    type_by_name = {f.name: f.type for f in fields(TimeseriesRow)}
    # dataclass field .type may be a string under `from __future__ import annotations`;
    # resolve the three concrete types we use by their default value instead.
    default_by_name = {f.name: f.default for f in fields(TimeseriesRow)}
    with open(path, newline="") as fh:
        for raw in csv.DictReader(fh):
            kwargs = {}
            for name, default in default_by_name.items():
                cell = raw.get(name, "")
                kwargs[name] = _coerce(cell, type(default))
            yield TimeseriesRow(**kwargs)
    _ = type_by_name  # kept for clarity; coercion is driven by defaults


def read_edges(path: Path) -> Iterator[EdgeRow]:
    """Stream edges.csv back as typed EdgeRow objects."""
    default_by_name = {f.name: f.default for f in fields(EdgeRow)}
    with open(path, newline="") as fh:
        for raw in csv.DictReader(fh):
            kwargs = {}
            for name, default in default_by_name.items():
                cell = raw.get(name, "")
                kwargs[name] = _coerce(cell, type(default))
            yield EdgeRow(**kwargs)


# ---------------------------------------------------------------------------
# JSON helpers.
# ---------------------------------------------------------------------------


def load_json(path: Path | str) -> object:
    with open(path) as fh:
        return json.load(fh)


def save_json(path: Path | str, obj: object) -> None:
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True, default=_json_default)
        fh.write("\n")


def _json_default(obj):
    # Allow dataclasses / Paths to serialize transparently.
    if isinstance(obj, Path):
        return str(obj)
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    raise TypeError(f"not JSON-serializable: {type(obj)!r}")


# ---------------------------------------------------------------------------
# Results-dir layout.
# ---------------------------------------------------------------------------


def results_dir(base: Path | str, scenario_id: str) -> Path:
    """Create + return a fresh timestamped results dir under `base`.

    Format: <base>/<UTC ISO compact>_<scenario_id>/ — sortable, never overwriting a
    prior run. Colons in the timestamp are replaced with '-' so the path is portable.
    """
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    # sanitize scenario_id for filesystem safety
    safe_id = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in scenario_id)
    out = base / f"{stamp}_{safe_id}"
    # extremely unlikely collision (same second, same id) — disambiguate
    n = 1
    cand = out
    while cand.exists():
        cand = base / f"{stamp}_{safe_id}_{n}"
        n += 1
    cand.mkdir(parents=True)
    return cand


# ---------------------------------------------------------------------------
# Give/get graph reconstruction (union of every node's top-20 peers[]).
# ---------------------------------------------------------------------------


def build_giveget_graph(edges, at_tick: int) -> dict:
    """Build the directed give/get graph at one tick.

    Returns dict keyed (src_label, dst_identity_hex) ->
        {'we_store': int, 'peer_stores': int, 'trust': float}.

    `we_store` = bytes src stores FOR dst (a GIVE edge from src's view).
    `peer_stores` = bytes dst stores FOR src (a GET edge from src's view).
    Because each node reports only its own top-20-by-trust peers, the union over
    every src's edge list reconstructs (most of) the full fleet graph: each node
    reliably contributes its own outgoing observations. If the same (src,dst) pair
    appears more than once at a tick (shouldn't, but be robust), the last wins.

    `edges` may be an iterator OR a pre-materialized list of EdgeRow.
    """
    graph: dict = {}
    for e in edges:
        if e.tick != at_tick:
            continue
        if not e.dst_identity_hex:
            continue
        key = (e.src, e.dst_identity_hex)
        graph[key] = {
            "we_store": int(e.bytes_we_store),
            "peer_stores": int(e.bytes_peer_stores),
            "trust": float(e.trust),
        }
    return graph


def ticks_in(edges) -> list[int]:
    """Sorted unique tick values present in an EdgeRow collection."""
    return sorted({e.tick for e in edges})


# ---------------------------------------------------------------------------
# Kendall-tau rank correlation (tau-b, handles ties). Pure stdlib.
# ---------------------------------------------------------------------------


def kendall_tau(rank_a: list, rank_b: list) -> float:
    """Kendall's tau-b between two equal-length sequences of comparable values.

    Returns a value in [-1, 1]; +1 = identical ordering, -1 = reversed, 0 = no
    association. tau-b corrects for ties in either sequence. Returns 0.0 for
    degenerate input (n < 2 or all-tied on one side -> zero denominator).
    Used to test "does measured trust rank peers the way contribution does?".
    """
    n = len(rank_a)
    if n != len(rank_b):
        raise ValueError("kendall_tau: sequences must be equal length")
    if n < 2:
        return 0.0

    concordant = 0
    discordant = 0
    ties_a = 0
    ties_b = 0
    for i in range(n):
        for j in range(i + 1, n):
            da = rank_a[i] - rank_a[j]
            db = rank_b[i] - rank_b[j]
            prod = da * db
            if prod > 0:
                concordant += 1
            elif prod < 0:
                discordant += 1
            else:
                # at least one side tied
                if da == 0:
                    ties_a += 1
                if db == 0:
                    ties_b += 1
    n0 = n * (n - 1) / 2.0
    denom = math.sqrt((n0 - ties_a) * (n0 - ties_b))
    if denom == 0.0:
        return 0.0
    return (concordant - discordant) / denom


# ---------------------------------------------------------------------------
# Community detection: greedy modularity maximization on an undirected weighted
# graph. Pure stdlib (a small CNM-style agglomerative pass). No networkx.
# ---------------------------------------------------------------------------


def _to_undirected_weighted(graph: dict) -> dict:
    """Collapse a directed give/get graph into an undirected weighted adjacency.

    Input: either build_giveget_graph output (keyed (src,dst)->{we_store,...}) or a
    plain {(u,v): weight} dict. Weight = we_store + peer_stores (total bytes flowing
    on the relationship), summed across both directions. Returns
    {node: {neighbor: weight}} with weight >= 0; self-loops dropped.
    """
    adj: dict = {}

    def add(u, v, w):
        if u == v or w <= 0:
            return
        adj.setdefault(u, {})
        adj[u][v] = adj[u].get(v, 0.0) + w

    for key, val in graph.items():
        u, v = key
        if isinstance(val, dict):
            w = float(val.get("we_store", 0)) + float(val.get("peer_stores", 0))
        else:
            w = float(val)
        add(u, v, w)
        add(v, u, w)
    # ensure every referenced node is a key even if isolated
    for u in list(adj.keys()):
        for v in adj[u]:
            adj.setdefault(v, {})
    return adj


def modularity(graph: dict, communities: list) -> float:
    """Newman modularity Q of a partition over an undirected weighted graph.

    `graph` is a directed give/get graph (or {(u,v):w}); it is symmetrized
    internally. `communities` is a list of sets (or lists) of node labels. Returns
    Q in roughly [-0.5, 1]; higher = stronger community structure than chance.
    Returns 0.0 for an empty graph (no edges).
    """
    adj = _to_undirected_weighted(graph)
    # total weight m = 0.5 * sum of all edge weights (each undirected edge counted twice)
    m2 = sum(w for nbrs in adj.values() for w in nbrs.values())
    if m2 == 0.0:
        return 0.0
    deg = {u: sum(nbrs.values()) for u, nbrs in adj.items()}
    comm_of = {}
    for idx, comm in enumerate(communities):
        for node in comm:
            comm_of[node] = idx
    q = 0.0
    for u, nbrs in adj.items():
        cu = comm_of.get(u)
        if cu is None:
            continue
        for v, w in nbrs.items():
            if comm_of.get(v) == cu:
                q += w - (deg[u] * deg.get(v, 0.0)) / m2
    return q / m2


def greedy_communities(graph: dict) -> list:
    """Greedy agglomerative community detection (CNM-style), pure stdlib.

    Start with every node in its own community, then repeatedly merge the pair of
    communities whose merge most increases modularity, until no merge helps.
    Returns a list of sets of node labels. Deterministic given the input (ties
    broken by sorted node order). O(V^2 * iterations) — fine at polygon scale
    (~100 nodes).
    """
    adj = _to_undirected_weighted(graph)
    nodes = sorted(adj.keys())
    if not nodes:
        return []
    communities = [{n} for n in nodes]

    def q_of(parts):
        return modularity(graph, parts)

    improved = True
    while improved and len(communities) > 1:
        improved = False
        base_q = q_of(communities)
        best_gain = 1e-12
        best_pair = None
        ncom = len(communities)
        for i in range(ncom):
            for j in range(i + 1, ncom):
                if not _communities_adjacent(adj, communities[i], communities[j]):
                    continue
                merged = list(communities)
                merged[i] = communities[i] | communities[j]
                del merged[j]
                gain = q_of(merged) - base_q
                if gain > best_gain:
                    best_gain = gain
                    best_pair = (i, j)
        if best_pair is not None:
            i, j = best_pair
            communities[i] = communities[i] | communities[j]
            del communities[j]
            improved = True
    return communities


def _communities_adjacent(adj: dict, a: set, b: set) -> bool:
    """True if any edge connects community a to community b (prunes merge search)."""
    for u in a:
        for v in adj.get(u, {}):
            if v in b:
                return True
    return False


def random_baseline_modularity(degree_seq: list, seed: int) -> float:
    """Modularity a random graph with the same degree sequence would exhibit.

    Builds a configuration-model multigraph from `degree_seq` (a list of integer
    degrees), runs greedy_communities on it, and returns its modularity. This is
    the null baseline: an observed clustering Q is only "real structure" if it
    exceeds this random-baseline Q. Deterministic given (degree_seq, seed).

    degree_seq entries are rounded to non-negative ints; the total stub count is
    made even by dropping the last stub if odd. Returns 0.0 if no edges form.
    """
    rng = random.Random(seed)
    stubs = []
    for i, d in enumerate(degree_seq):
        d = max(0, int(round(d)))
        stubs.extend([i] * d)
    if len(stubs) < 2:
        return 0.0
    rng.shuffle(stubs)
    if len(stubs) % 2 == 1:
        stubs.pop()
    graph: dict = {}
    for k in range(0, len(stubs), 2):
        u, v = stubs[k], stubs[k + 1]
        if u == v:
            continue
        key = (u, v)
        # weight 1 per parallel edge (count multiplicities)
        cur = graph.get(key)
        if cur is None:
            graph[key] = {"we_store": 1, "peer_stores": 0}
        else:
            cur["we_store"] += 1
    if not graph:
        return 0.0
    comms = greedy_communities(graph)
    return modularity(graph, comms)


# ---------------------------------------------------------------------------
# Trend / dispersion helpers.
# ---------------------------------------------------------------------------


def backhalf_slope(series: list) -> float:
    """Least-squares slope (value per tick) over the BACK HALF of a series.

    `series` is a list of (tick, value) pairs (need not be pre-sorted). We sort by
    tick, take the second half (steady-state, past warm-up/transient), and fit a
    line value = slope*tick + b. Returns the slope. Used by the bug oracle for RAM/
    disk leak detection (a persistently positive slope late in the run = unbounded
    growth) and DB-row-count growth. Returns 0.0 for fewer than 2 back-half points.
    """
    if not series:
        return 0.0
    pts = sorted(series, key=lambda p: p[0])
    half = pts[len(pts) // 2:]
    n = len(half)
    if n < 2:
        return 0.0
    sx = sum(p[0] for p in half)
    sy = sum(p[1] for p in half)
    sxx = sum(p[0] * p[0] for p in half)
    sxy = sum(p[0] * p[1] for p in half)
    denom = n * sxx - sx * sx
    if denom == 0:
        return 0.0
    return (n * sxy - sx * sy) / denom


def coef_variation(values: list) -> float:
    """Coefficient of variation = stdev/mean (population stdev). 0.0 if mean==0.

    A scale-free dispersion measure for fairness (e.g. CV of per-node give/get
    balance across honest nodes — lower = more even-handed). Ignores None entries.
    Returns 0.0 for fewer than 2 usable values.
    """
    vals = [float(v) for v in values if v is not None]
    n = len(vals)
    if n < 2:
        return 0.0
    mean = sum(vals) / n
    if mean == 0.0:
        return 0.0
    var = sum((v - mean) ** 2 for v in vals) / n
    return math.sqrt(var) / abs(mean)


# ---------------------------------------------------------------------------
# Virtual <-> wall time conversion.
# ---------------------------------------------------------------------------

_SECONDS_PER_DAY = 86400.0


def virtual_to_wall(virtual_day: float, time_scale: float) -> float:
    """Wall-clock seconds (since fleet start) for a given virtual-day offset.

    The daemon divides internal cadences by time_scale, so one virtual day of
    daemon-internal evolution elapses in (86400 / time_scale) real seconds. time_scale
    must be >= 1 (the daemon floors each scaled cadence at .max(1), but the mapping
    itself is just division). Guards time_scale<=0 -> treats as 1.
    """
    if time_scale <= 0:
        time_scale = 1.0
    return (virtual_day * _SECONDS_PER_DAY) / time_scale


def wall_to_virtual(wall_secs: float, time_scale: float) -> float:
    """Virtual-day offset corresponding to a wall-clock seconds-since-start value.

    Inverse of virtual_to_wall. Used by the collector to stamp each sample's
    virtual_day and by the churn engine to report progress in virtual time.
    """
    if time_scale <= 0:
        time_scale = 1.0
    return (wall_secs * time_scale) / _SECONDS_PER_DAY
