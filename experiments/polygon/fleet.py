#!/usr/bin/env python3
# Viaticum Polygon — L1 fleet-manager primitives.
#
# WHY THIS MODULE EXISTS (intent / acceptance criteria — fixed before the code):
#   The polygon is a REUSABLE proving ground that spins up a fleet of REAL viaticum
#   daemons and drives them through scenarios many times. Every other layer
#   (feasibility probe, churn engine, collector, oracles) needs ONE trustworthy way
#   to manipulate a node by a durable label: init it as an independent owner, launch
#   it under --time-scale, find its libp2p addr, connect the star, kill it, restart
#   it on the SAME data-dir, onboard a fresh node mid-run, request a restore and
#   locate the staged bytes, sample its resources, and tear the whole fleet down
#   without corrupting redb.
#
#   This generalizes the spin-up pattern that local_scale_test.sh / local_delete_test.sh
#   / local_dr_test.sh each re-implement by hand. It must NOT duplicate any one of
#   them — it is the single shared primitive layer they should all have used.
#
#   The load-bearing correctness properties this module is responsible for:
#     P1 (distinct master): every node init's its OWN master identity. Same-master
#        siblings are excluded from each other's placement pool by design, so reusing
#        a data-dir or a mnemonic would silently zero out placements -> false
#        "backup failure" in the oracle. init_node NEVER reuses a data-dir.
#     P2 (ephemeral ports): web_api bind 127.0.0.1:0 and libp2p listen_port=0 are
#        self-assigned and CHANGE across restarts. We MUST re-resolve a node's addr at
#        every (re)connect and NEVER cache an addr across a restart. The seed addr used
#        for star/reconnect is always freshly fetched from the seed's live status.
#     P3 (no -9 before scan): kill -9 without a SIGTERM grace can corrupt redb -> a
#        false DB-integrity FAIL. Teardown is two-pass (TERM, grace sleep, then KILL),
#        and the stderr panic scan runs BEFORE any -9 escalation so a real panic is
#        never masked by our own forced kill.
#     P4 (durable label): the launch-index label "node-NN" is the stable handle across
#        the node's whole lifecycle (the daemon's ephemeral ports and even
#        peer_count_authenticated reset on restart, but node_identity/device_id persist
#        in the keyfile). node_index.json records label <-> node_identity/device_id once
#        each node is first ready, so the collector can join self-rows to peer-edges.
#
# This module starts NO multi-node fleet on its own (that is the orchestrator's job in
# run.py); it only provides the primitives. It is stdlib-only (subprocess, os, signal,
# json, time, pathlib, shutil).

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# common.py is the single source of truth for shared types / IO helpers.
# We import it for save_json; NodePlan is consumed only via attribute access so the
# two modules stay decoupled (no field-by-field coupling beyond the documented shape).
from common import save_json

# libp2p multiaddr as it appears on the `addr:` status line.
_ADDR_RE = re.compile(r"/ip4/[^\s]+")
# `identity:` line from text status — readiness signal.
_IDENTITY_RE = re.compile(r"identity:")

DEFAULT_BINARY = "./target/release/viaticum"


class Fleet:
    """Manages a fleet of real viaticum daemons by durable label ("node-NN").

    Construction does not launch anything. Every node is identified by its label
    for the whole run; the label maps to a fixed data-dir under results_dir/nodes/.
    """

    def __init__(self, results_dir, time_scale: int, log) -> None:
        self.results_dir = Path(results_dir)
        self.time_scale = int(time_scale)
        self.log = log
        # Where every node's data-dir lives. Durable across (re)launches.
        self.nodes_root = self.results_dir / "nodes"
        self.nodes_root.mkdir(parents=True, exist_ok=True)

        self.binary: Optional[str] = None
        # label -> Popen (or None when intentionally down).
        self._procs: dict[str, Optional[subprocess.Popen]] = {}
        # label -> last known pid (kept even after a node is killed, for measure()).
        self._pids: dict[str, Optional[int]] = {}
        # label -> NodePlan (set by join_node / recorded by the orchestrator via
        # set_plan); used for full fresh onboarding mid-run.
        self._plans: dict[str, object] = {}
        # label -> {node_identity, device_id, archetype, join_virtual_day} once ready.
        self._index: dict[str, dict] = {}
        # label of the star seed (set by star_connect / join_node for reconnects).
        self._seed_label: Optional[str] = None

    # ----------------------------------------------------------------- paths
    def node_dir(self, label: str) -> Path:
        return self.nodes_root / label

    def node_log(self, label: str) -> Path:
        # stderr+stdout of the daemon (JSON log lines when --log-format json).
        return self.node_dir(label) / "daemon.log"

    def files_dir(self, label: str) -> Path:
        return self.node_dir(label) / "files"

    # ------------------------------------------------------------- binary
    def resolve_binary(self, env_binary: Optional[str] = None) -> str:
        """Resolve the daemon binary: explicit arg -> BINARY env -> default path.

        Exits the process (non-zero) if no executable binary is found — a polygon
        run with no binary is unrecoverable and must fail loudly, not silently.
        """
        candidates: list[str] = []
        if env_binary:
            candidates.append(env_binary)
        env = os.environ.get("BINARY")
        if env:
            candidates.append(env)
        candidates.append(DEFAULT_BINARY)
        # Also accept a binary on PATH named "viaticum".
        on_path = shutil.which("viaticum")
        if on_path:
            candidates.append(on_path)

        for cand in candidates:
            p = Path(cand)
            if p.is_file() and os.access(p, os.X_OK):
                self.binary = str(p.resolve())
                self.log(f"[fleet] binary resolved: {self.binary}")
                return self.binary
            # `which`-style bare name already filtered above; absolute/relative paths only.
        self.log(
            "[fleet] FATAL: viaticum binary not found "
            f"(tried: {', '.join(candidates)}). Build it with ./rbuild.sh."
        )
        sys.exit(2)

    def _bin(self) -> str:
        if self.binary is None:
            # Lazily resolve so callers that forgot are still safe.
            return self.resolve_binary()
        return self.binary

    # ------------------------------------------------------------- CLI helper
    def _cli(self, label: str, args: list[str], timeout: float = 30.0) -> subprocess.CompletedProcess:
        """Run a one-shot CLI command against a node's data-dir. Never raises on
        non-zero exit — callers inspect returncode/stdout (mirrors run_cli_q)."""
        cmd = [self._bin(), "--data-dir", str(self.node_dir(label))] + args
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            # Synthesize a CompletedProcess-like result.
            return subprocess.CompletedProcess(cmd, returncode=124, stdout=e.stdout or "", stderr="timeout")

    # ------------------------------------------------------------- lifecycle
    def init_node(self, label: str) -> None:
        """Init a node as an INDEPENDENT owner (distinct master). mkdir + init.

        P1: never reuse an existing data-dir — a stale keyfile would make this node a
        sibling of a previous run / another node and silently break placement. If the
        data-dir already exists with a keyfile, it is wiped first.
        """
        d = self.node_dir(label)
        if d.exists():
            # Fresh independent owner each init — clear any prior state.
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)
        res = self._cli(label, ["init"], timeout=60.0)
        if res.returncode != 0:
            self.log(f"[fleet] WARN init {label} rc={res.returncode}: {res.stderr.strip()[:200]}")

    def write_config(self, label: str, toml_text: str) -> None:
        """Write the per-node config.toml (rendered by config_gen)."""
        cfg = self.node_dir(label) / "config.toml"
        cfg.write_text(toml_text)

    def set_plan(self, label: str, plan: object) -> None:
        """Record a node's NodePlan so restart/join can rebuild its launch args.

        Called by the orchestrator after building plans; join_node sets it itself.
        """
        self._plans[label] = plan

    def launch_node(
        self,
        label: str,
        watch_dirs: list,
        importance_via_watchblock: bool = False,
    ) -> int:
        """Spawn the daemon for an already-init'd node and return its pid.

        Creates files/ if missing, spawns `daemon --time-scale S --watch-dir ...
        --log-format json` with stderr+stdout redirected to DIR/daemon.log (append
        so restarts keep history), and records the pid.

        importance_via_watchblock: when True the [[watch]] importance block in
        config.toml drives importance, so we do NOT pass --watch-dir for those dirs
        (the daemon reads them from config). When False we pass --watch-dir flags.
        """
        self.files_dir(label).mkdir(parents=True, exist_ok=True)
        for wd in watch_dirs:
            Path(wd).mkdir(parents=True, exist_ok=True)

        args = [
            self._bin(),
            "--data-dir",
            str(self.node_dir(label)),
            "daemon",
            "--time-scale",
            str(self.time_scale),
            "--log-format",
            "json",
        ]
        if not importance_via_watchblock:
            for wd in watch_dirs:
                args += ["--watch-dir", str(wd)]

        logf = open(self.node_log(label), "a")
        logf.write(f"\n=== launch {label} @ {time.strftime('%Y-%m-%dT%H:%M:%S')} ===\n")
        logf.flush()
        env = dict(os.environ)
        env.setdefault("RUST_LOG", "info")
        proc = subprocess.Popen(
            args,
            stdout=logf,
            stderr=subprocess.STDOUT,
            env=env,
            # New process group so we can signal cleanly without hitting our own shell.
            start_new_session=True,
        )
        self._procs[label] = proc
        self._pids[label] = proc.pid
        return proc.pid

    def wait_ready(self, label: str, timeout_s: int = 60) -> bool:
        """Poll `status` until the `identity:` line appears (keyfile loaded)."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            res = self._cli(label, ["status"], timeout=10.0)
            if res.returncode == 0 and _IDENTITY_RE.search(res.stdout or ""):
                self._record_index(label)
                return True
            time.sleep(0.5)
        return False

    def _record_index(self, label: str) -> None:
        """Record label <-> node_identity/device_id once (P4 durable label)."""
        if label in self._index:
            return
        data = self.status_json(label)
        if not data:
            return
        plan = self._plans.get(label)
        entry = {
            "label": label,
            "archetype": getattr(plan, "archetype", "") if plan is not None else "",
            "node_identity": data.get("node_identity", ""),
            "device_id": data.get("device_id", ""),
            "join_virtual_day": getattr(plan, "join_virtual_day", 0) if plan is not None else 0,
        }
        if entry["node_identity"]:
            self._index[label] = entry
            self._write_node_index()

    def _write_node_index(self) -> None:
        save_json(self.results_dir / "node_index.json", list(self._index.values()))

    # ------------------------------------------------------------- addr / connect
    def get_addr(self, label: str) -> Optional[str]:
        """Poll 20x0.5s for the libp2p `addr:` line; rewrite 0.0.0.0 -> 127.0.0.1.

        P2: the addr is ephemeral and the swarm listen address appears ~1s AFTER
        identity, so a freshly/just-restarted node races — always re-resolve, never
        cache across a restart.
        """
        for _ in range(20):
            res = self._cli(label, ["status"], timeout=10.0)
            if res.returncode == 0:
                for line in (res.stdout or "").splitlines():
                    if "addr:" in line:
                        m = _ADDR_RE.search(line)
                        if m:
                            return m.group(0).replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/")
            time.sleep(0.5)
        return None

    def connect(self, label: str, addr: str) -> bool:
        """Run `viaticum connect <addr>` from this node. True iff it reports success."""
        if not addr:
            return False
        res = self._cli(label, ["connect", addr], timeout=30.0)
        out = ((res.stdout or "") + (res.stderr or "")).lower()
        return res.returncode == 0 and "connect" in out and "error" not in out

    def star_connect(self, seed_label: str, member_labels: list) -> int:
        """Connect every member to the seed in parallel. Returns success count.

        Resolves the seed addr ONCE here (it is stable for the life of this seed
        process); members fire connects concurrently. The seed label is remembered
        for later reconnects (restart_node / join_node).
        """
        self._seed_label = seed_label
        addr = self.get_addr(seed_label)
        if not addr:
            self.log(f"[fleet] star_connect: cannot resolve seed {seed_label} addr")
            return 0

        procs: list[tuple[str, subprocess.Popen]] = []
        for label in member_labels:
            if label == seed_label:
                continue
            cmd = [self._bin(), "--data-dir", str(self.node_dir(label)), "connect", addr]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            procs.append((label, p))

        ok = 0
        for label, p in procs:
            try:
                out, _ = p.communicate(timeout=40.0)
            except subprocess.TimeoutExpired:
                p.kill()
                out = ""
            low = (out or "").lower()
            if p.returncode == 0 and "connect" in low and "error" not in low:
                ok += 1
        self.log(f"[fleet] star_connect: {ok}/{len(procs)} members connected to {seed_label}")
        return ok

    # ------------------------------------------------------------- status
    def status_json(self, label: str) -> Optional[dict]:
        """Return parsed `status --json`, or None if the node is unreachable/down."""
        res = self._cli(label, ["status", "--json"], timeout=15.0)
        if res.returncode != 0 or not res.stdout:
            return None
        try:
            return json.loads(res.stdout)
        except (json.JSONDecodeError, ValueError):
            return None

    # ------------------------------------------------------------- kill / restart
    def _signal(self, label: str, sig: int) -> None:
        proc = self._procs.get(label)
        if proc is None or proc.poll() is not None:
            return
        try:
            # Signal the whole process group (start_new_session=True set the pgid).
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError):
            try:
                proc.send_signal(sig)
            except ProcessLookupError:
                pass

    def kill_node(self, label: str) -> None:
        """Gracefully stop a node (SIGTERM) and mark it down. Keeps the data-dir
        intact so restart_node can relaunch the SAME identity."""
        self._signal(label, signal.SIGTERM)
        proc = self._procs.get(label)
        if proc is not None:
            try:
                proc.wait(timeout=8.0)
            except subprocess.TimeoutExpired:
                self._signal(label, signal.SIGKILL)
                try:
                    proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    pass
        self._procs[label] = None

    def restart_node(self, label: str, watch_dirs: list) -> int:
        """Relaunch a previously-killed node on its SAME data-dir, then re-resolve
        the seed addr and reconnect (P2: addr changed across the restart).

        Returns the new pid (0 if the node never became ready).
        """
        importance = getattr(self._plans.get(label), "importance_multiplier", 1.0) != 1.0
        pid = self.launch_node(label, watch_dirs, importance_via_watchblock=importance)
        if not self.wait_ready(label, timeout_s=60):
            self.log(f"[fleet] restart {label}: not ready after 60s")
            return 0
        self._reconnect_to_seed(label)
        return pid

    def _reconnect_to_seed(self, label: str) -> None:
        """Re-resolve the seed's CURRENT addr and connect this node to it.

        P2: never reuse a cached seed addr — the seed may itself have restarted on a
        new ephemeral port. If this node IS the seed, nothing to do (Kademlia mesh
        re-propagates from members reconnecting).
        """
        if self._seed_label is None or label == self._seed_label:
            return
        addr = self.get_addr(self._seed_label)
        if addr:
            self.connect(label, addr)

    def join_node(self, label: str, plan: object, seed_label: str) -> int:
        """Full fresh onboarding of a brand-new node mid-run: init (distinct master),
        write config, launch, wait ready, star-connect to the seed.

        Used by the churn engine for late-join / newcomer scenarios. Returns the pid
        (0 on failure). The seed_label is recorded for any later reconnects.
        """
        self._seed_label = seed_label
        self._plans[label] = plan

        self.init_node(label)
        toml_text = getattr(plan, "config_toml", None)
        if toml_text:
            self.write_config(label, toml_text)

        watch_dirs = [self.files_dir(label)]
        importance = getattr(plan, "importance_multiplier", 1.0) != 1.0
        pid = self.launch_node(label, watch_dirs, importance_via_watchblock=importance)
        if not self.wait_ready(label, timeout_s=60):
            self.log(f"[fleet] join {label}: not ready after 60s")
            return 0
        addr = self.get_addr(seed_label)
        if addr:
            self.connect(label, addr)
        return pid

    # ------------------------------------------------------------- restore
    def request_restore(self, label: str, original_path) -> None:
        """Ask the node to restore a backed-up path. Fire-and-forget: restore is
        async ('started'/'queued'), so the caller polls find_restored() afterwards.

        The restored bytes are staged under <data_dir>/restore/<job_id>/<rel_path>
        (the staging writer strips the leading '/' from the absolute path)."""
        res = self._cli(label, ["restore", str(original_path)], timeout=30.0)
        if res.returncode != 0:
            self.log(f"[fleet] restore {label} {original_path} rc={res.returncode}: "
                     f"{(res.stderr or res.stdout or '').strip()[:200]}")

    def find_restored(self, label: str, filename: str) -> Optional[Path]:
        """Find a restored file by basename under <data_dir>/restore/.

        Returns the first match (per-job staging dirs are unique, and the polygon
        restores distinct filenames), or None if the restore has not landed yet.
        """
        restore_root = self.node_dir(label) / "restore"
        if not restore_root.exists():
            return None
        base = os.path.basename(filename)
        for p in restore_root.rglob("*"):
            if p.is_file() and p.name == base:
                return p
        return None

    # ------------------------------------------------------------- stderr scan
    def scan_stderr(self, label: str) -> dict:
        """Scan a node's daemon.log for panics / ERROR lines.

        Returns {panicked: bool, error_lines: int, first_error: str|None}. Used by
        the bug oracle as the crash gate (P3: this runs BEFORE any -9 in teardown so a
        real panic is never masked by our forced kill).
        """
        logp = self.node_log(label)
        result = {"panicked": False, "error_lines": 0, "first_error": None}
        if not logp.exists():
            return result
        try:
            text = logp.read_text(errors="replace")
        except OSError:
            return result
        for line in text.splitlines():
            low = line.lower()
            if "panicked" in low or "panic at" in low:
                result["panicked"] = True
                if result["first_error"] is None:
                    result["first_error"] = line.strip()[:500]
            # JSON log lines carry "level":"ERROR"; text logs carry " ERROR ".
            if '"level":"error"' in low or '"level": "error"' in low or " error " in low or low.startswith("error"):
                result["error_lines"] += 1
                if result["first_error"] is None:
                    result["first_error"] = line.strip()[:500]
        return result

    # ------------------------------------------------------------- measure
    def measure(self, label: str, pid: Optional[int] = None) -> dict:
        """Sample external resource use for one node.

        Returns {rss_kb, du_holdings_kb, du_db_redb_bytes, du_datadir_kb}. Process RSS
        comes from `ps -o rss=` (None when the node is down); disk footprint comes from
        `du`/`stat` on the data-dir. These are the external signals the status JSON does
        NOT expose (RAM, real holdings/db disk), feeding the bug oracle's leak gates.
        """
        out = {
            "rss_kb": None,
            "du_holdings_kb": None,
            "du_db_redb_bytes": None,
            "du_datadir_kb": None,
        }
        use_pid = pid if pid is not None else self._pids.get(label)
        if use_pid is not None:
            r = self._ps_rss(use_pid)
            if r is not None:
                out["rss_kb"] = r

        d = self.node_dir(label)
        out["du_holdings_kb"] = self._du_kb(d / "holdings")
        out["du_datadir_kb"] = self._du_kb(d)
        db = d / "db.redb"
        try:
            if db.is_file():
                out["du_db_redb_bytes"] = db.stat().st_size
        except OSError:
            pass
        return out

    @staticmethod
    def _ps_rss(pid: int) -> Optional[int]:
        try:
            res = subprocess.run(
                ["ps", "-o", "rss=", "-p", str(pid)],
                capture_output=True,
                text=True,
                timeout=10.0,
            )
            s = (res.stdout or "").strip()
            return int(s) if s else None
        except (subprocess.SubprocessError, ValueError):
            return None

    @staticmethod
    def _du_kb(path: Path) -> Optional[int]:
        if not path.exists():
            return None
        try:
            res = subprocess.run(
                ["du", "-sk", str(path)],
                capture_output=True,
                text=True,
                timeout=30.0,
            )
            field = (res.stdout or "").split()
            return int(field[0]) if field else None
        except (subprocess.SubprocessError, ValueError, IndexError):
            return None

    # ------------------------------------------------------------- teardown
    def teardown(self, scan_first: bool = True) -> dict:
        """Tear the whole fleet down. Two-pass (TERM -> grace -> KILL).

        P3: when scan_first is True, every node's stderr is scanned for panics/ERROR
        BEFORE any -9 escalation, so our forced kill never masks a real crash. The
        results dir (data-dirs, logs) is KEPT for the oracles.

        Returns {scans: {label: scan_dict}, terminated: int, killed: int}.
        """
        scans: dict[str, dict] = {}
        if scan_first:
            for label in self._procs:
                scans[label] = self.scan_stderr(label)

        terminated = 0
        for label, proc in self._procs.items():
            if proc is not None and proc.poll() is None:
                self._signal(label, signal.SIGTERM)
                terminated += 1

        # Grace window for redb to flush cleanly.
        time.sleep(3.0)

        killed = 0
        for label, proc in self._procs.items():
            if proc is None:
                continue
            if proc.poll() is None:
                self._signal(label, signal.SIGKILL)
                killed += 1
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                pass

        self.log(f"[fleet] teardown: {terminated} TERM, {killed} KILL, results kept at {self.results_dir}")
        return {"scans": scans, "terminated": terminated, "killed": killed}

    # ------------------------------------------------------------- introspection
    def labels(self) -> list:
        """All labels the fleet currently knows about (launched or planned)."""
        seen = list(self._procs.keys())
        for label in self._plans:
            if label not in seen:
                seen.append(label)
        return seen

    def pid_of(self, label: str) -> Optional[int]:
        return self._pids.get(label)

    def is_up(self, label: str) -> bool:
        proc = self._procs.get(label)
        return proc is not None and proc.poll() is None

    def node_index(self) -> dict:
        return dict(self._index)
