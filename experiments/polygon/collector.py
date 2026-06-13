"""Viaticum Polygon — L4 observability collector: the dense time-series feed.

WHY THIS MODULE EXISTS (intent / acceptance criteria — fixed before the code):
  The two north-star properties (bug-freeness, fairness) are NOT decided by the
  daemon and NOT decided by the orchestrator — they are decided by the ORACLES,
  and the oracles only ever see what this collector wrote to disk. So this module
  is the eyes of the whole polygon: every sample_interval it captures each node's
  user's-eye view (`status --json`), its external resource footprint (RSS via ps,
  holdings + db.redb on-disk size via du/stat that the JSON does NOT expose), and
  its INTENDED up/down state (from the churn queue, so a node we deliberately
  killed is recorded status_ok=0, never mistaken for a crash). It flattens all of
  that into two append-only CSVs whose schema is owned by common.py (single source
  of truth), so the oracles can read back exactly what was written with zero drift.

  ACCEPTANCE CRITERIA this module is responsible for:
    AC1 (no gaps): EVERY node emits a TimeseriesRow at EVERY tick, even when it is
         down or unreachable. A down node's row is status_ok=0 with daemon-sourced
         fields at their defaults — gaps would break the slope/leak oracles, which
         fit a line over the back half of each per-node series and need a regular
         grid. The up_state column distinguishes "intentionally down" (churn) from
         "should be up but status failed" (the bug oracle's stuck-pipeline signal).
    AC2 (schema fidelity): rows are written with EXACTLY common.timeseries_header()
         / common.edges_header() column order, derived from the dataclasses. We map
         the daemon's JSON field names onto the row fields once, here, and never
         hand-duplicate a header.
    AC3 (give/get edges): every PeerSummary a node reports becomes one EdgeRow keyed
         (src=observer label, dst=PeerSummary.identity_hex). Because each node only
         reports its top-20-by-trust peers, the oracle reconstructs the full fleet
         graph by UNIONing every node's edges — so we must faithfully emit one edge
         per reported peer, with the join key (identity_hex) intact.
    AC4 (no daemon knowledge): the collector reads NOTHING it cannot get from
         Fleet.status_json / Fleet.measure and churn.up_state_at. It does not poke
         the daemon directly, parse logs, or know any redb internals.

  This module spawns NO processes (Fleet does). It is a pure flatten-and-append
  layer over the primitives. stdlib only.
"""

from __future__ import annotations

from common import (
    EdgeRow,
    IMPORTANCE_BUCKETS,
    TABLE_STAT_FIELDS,
    TimeseriesRow,
    open_edges_writer,
    open_timeseries_writer,
    wall_to_virtual,
)
from churn import up_state_at

# StatusData scalar fields that map 1:1 (same name) from the daemon JSON onto a
# TimeseriesRow field. Listed explicitly (not derived) so an accidental rename in
# either schema is a visible diff here rather than a silent dropped column.
_STATUS_SCALARS = (
    "peer_count",
    "peer_count_connected",
    "peer_count_authenticated",
    "avg_trust",
    "holding_bytes",
    "backed_up_files",
    "backed_up_bytes",
    "blocks_needing_repair",
    "effective_quota_bytes",
    "used_bytes",
    "pos_total_challenges",
    "pos_total_passes",
    "placement_count",
    "placement_alive",
    "placement_lost",
    "blocks_ok",
    "blocks_at_risk",
)

# PeerSummary fields that map 1:1 onto an EdgeRow field.
_PEER_SCALARS = (
    "trust",
    "trust_p",
    "trust_i",
    "trust_s",
    "bytes_we_store",
    "bytes_peer_stores",
    "pos_challenges_recent",
    "pos_passes_recent",
)


class Collector:
    """Samples the whole fleet into timeseries.csv + edges.csv (append-only).

    Construction opens both CSV files with their canonical headers and keeps the
    handles open for the life of the run; the orchestrator calls sample(tick, now)
    once per sample_interval and finalize() once at the end.
    """

    def __init__(self, fleet, churn_queue, scenario, results_dir) -> None:
        self.fleet = fleet
        self.churn_queue = churn_queue
        self.scenario = scenario
        self.results_dir = results_dir
        self.time_scale = float(scenario.get("time_scale", 1) or 1)

        from pathlib import Path

        self.results_dir = Path(results_dir)
        self._ts_fh, self._ts_writer = open_timeseries_writer(
            self.results_dir / "timeseries.csv"
        )
        self._edge_fh, self._edge_writer = open_edges_writer(
            self.results_dir / "edges.csv"
        )
        self._closed = False

    # ------------------------------------------------------------- sampling
    def sample(self, tick: int, now_wall: float) -> None:
        """Sample every node once. Appends one TimeseriesRow per node and one
        EdgeRow per reported PeerSummary. Never raises on a single node's failure
        (a dead node still gets a status_ok=0 row — AC1)."""
        if self._closed:
            return
        virtual_day = wall_to_virtual(now_wall, self.time_scale)

        for label in self._fleet_labels():
            archetype = self._archetype_of(label)
            up_state = self._up_state(label, now_wall)

            status = self._safe_status(label)
            measured = self._safe_measure(label)

            row = self._build_timeseries_row(
                tick=tick,
                now_wall=now_wall,
                virtual_day=virtual_day,
                label=label,
                archetype=archetype,
                up_state=up_state,
                status=status,
                measured=measured,
            )
            self._ts_writer.writerow(_row_dict(row))

            if status:
                self._emit_edges(
                    tick=tick,
                    now_wall=now_wall,
                    virtual_day=virtual_day,
                    src=label,
                    src_archetype=archetype,
                    status=status,
                )

        # Flush each tick so a crashed orchestrator still leaves a usable, oracle-
        # readable partial time series (the polygon run is provenance either way).
        self._ts_fh.flush()
        self._edge_fh.flush()

    # ------------------------------------------------------------- row builders
    def _build_timeseries_row(
        self,
        tick,
        now_wall,
        virtual_day,
        label,
        archetype,
        up_state,
        status,
        measured,
    ) -> TimeseriesRow:
        row = TimeseriesRow(
            tick=tick,
            wall_secs=float(now_wall),
            virtual_day=float(virtual_day),
            label=label,
            archetype=archetype,
            up_state=up_state,
            status_ok=1 if status else 0,
        )

        if status:
            row.device_id = str(status.get("device_id", "") or "")
            for name in _STATUS_SCALARS:
                _set_typed(row, name, status.get(name))
            self._flatten_table_stats(row, status.get("table_stats"))
            self._flatten_importance(row, status.get("by_importance"))

        # External footprint is sampled even for a down node (du on the data-dir
        # still works after the process exits; ps RSS is None and stays default 0).
        self._flatten_measure(row, measured)
        return row

    def _flatten_table_stats(self, row: TimeseriesRow, table_stats) -> None:
        """Map TableStats (Option in JSON) onto the tbl_* columns. Missing => default 0."""
        if not isinstance(table_stats, dict):
            return
        for name in TABLE_STAT_FIELDS:
            _set_typed(row, f"tbl_{name}", table_stats.get(name))

    def _flatten_importance(self, row: TimeseriesRow, by_importance) -> None:
        """Map by_importance buckets onto imp_<bucket>_count / imp_<bucket>_mean_p.

        by_importance is a list of {bucket, block_count, mean_p_recoverable, ...}.
        We index by the bucket name so column placement is independent of the order
        the daemon happens to emit them in. Buckets we don't recognize are ignored;
        recognized buckets that are absent stay at their default 0.
        """
        if not isinstance(by_importance, list):
            return
        by_name = {}
        for entry in by_importance:
            if isinstance(entry, dict):
                name = entry.get("bucket")
                if name:
                    by_name[name] = entry
        for bucket in IMPORTANCE_BUCKETS:
            entry = by_name.get(bucket)
            if entry is None:
                continue
            _set_typed(row, f"imp_{bucket}_count", entry.get("block_count"))
            _set_typed(row, f"imp_{bucket}_mean_p", entry.get("mean_p_recoverable"))

    def _flatten_measure(self, row: TimeseriesRow, measured) -> None:
        """Map Fleet.measure() output onto the ext_* columns. None => default 0
        (a down node has no RSS; the leak oracle treats the down stretch as no
        growth, which is correct — the process isn't accumulating anything)."""
        if not isinstance(measured, dict):
            return
        _set_typed(row, "ext_rss_kb", measured.get("rss_kb"))
        _set_typed(row, "ext_du_holdings_kb", measured.get("du_holdings_kb"))
        _set_typed(row, "ext_du_db_redb_bytes", measured.get("du_db_redb_bytes"))
        _set_typed(row, "ext_du_datadir_kb", measured.get("du_datadir_kb"))

    def _emit_edges(
        self, tick, now_wall, virtual_day, src, src_archetype, status
    ) -> None:
        """Emit one EdgeRow per PeerSummary this node reports (AC3)."""
        peers = status.get("peers")
        if not isinstance(peers, list):
            return
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            identity_hex = str(peer.get("identity_hex", "") or "")
            if not identity_hex:
                # No join key => the edge is unattributable to a fleet node; skip
                # rather than write a dangling edge the oracle can't map.
                continue
            edge = EdgeRow(
                tick=tick,
                wall_secs=float(now_wall),
                virtual_day=float(virtual_day),
                src=src,
                src_archetype=src_archetype,
                dst_identity_hex=identity_hex,
                last_seen=str(peer.get("last_seen", "") or ""),
                link=str(peer.get("link", "") or ""),
            )
            for name in _PEER_SCALARS:
                _set_typed(edge, name, peer.get(name))
            self._edge_writer.writerow(_edge_dict(edge))

    # ------------------------------------------------------------- helpers
    def _fleet_labels(self) -> list:
        """Every label the fleet knows about. A node that has not yet late-joined
        is still listed (it is a planned member); its sample is status_ok=0/down
        until its join event fires, which keeps the grid rectangular (AC1)."""
        try:
            return list(self.fleet.labels())
        except Exception:
            return []

    def _archetype_of(self, label: str) -> str:
        idx = {}
        try:
            idx = self.fleet.node_index()
        except Exception:
            idx = {}
        entry = idx.get(label) if isinstance(idx, dict) else None
        if isinstance(entry, dict) and entry.get("archetype"):
            return str(entry["archetype"])
        plan = self.fleet._plans.get(label) if hasattr(self.fleet, "_plans") else None
        return str(getattr(plan, "archetype", "") or "")

    def _up_state(self, label: str, now_wall: float) -> str:
        try:
            return up_state_at(label, self.churn_queue, now_wall)
        except Exception:
            return ""

    def _safe_status(self, label: str):
        try:
            return self.fleet.status_json(label)
        except Exception:
            return None

    def _safe_measure(self, label: str):
        try:
            return self.fleet.measure(label)
        except Exception:
            return None

    # ------------------------------------------------------------- teardown
    def finalize(self) -> None:
        """Flush and close both CSV handles. Idempotent."""
        if self._closed:
            return
        self._closed = True
        for fh in (self._ts_fh, self._edge_fh):
            try:
                fh.flush()
                fh.close()
            except (OSError, ValueError):
                pass


# ---------------------------------------------------------------------------
# Module-level helpers (no daemon knowledge; pure typing/coercion).
# ---------------------------------------------------------------------------


def _set_typed(row, name: str, value) -> None:
    """Set row.<name> from a raw JSON value, coercing to the field's declared type.

    The dataclass default tells us the target type (int vs float vs str). A missing
    / None value leaves the existing default in place (so down-node rows stay at the
    schema defaults — AC1). Non-numeric junk in a numeric column is dropped to the
    default rather than crashing the whole sample.
    """
    if value is None:
        return
    current = getattr(row, name, None)
    if isinstance(current, bool):
        # No bool columns in the schema, but guard so a bool isn't treated as int.
        setattr(row, name, value)
        return
    if isinstance(current, int):
        try:
            setattr(row, name, int(value))
        except (TypeError, ValueError):
            try:
                setattr(row, name, int(float(value)))
            except (TypeError, ValueError):
                pass
        return
    if isinstance(current, float):
        try:
            setattr(row, name, float(value))
        except (TypeError, ValueError):
            pass
        return
    # str column
    setattr(row, name, str(value))


def _row_dict(row: TimeseriesRow) -> dict:
    return row.__dict__


def _edge_dict(edge: EdgeRow) -> dict:
    return edge.__dict__
