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
# `viaticum init` prints "Mnemonic (SAVE THIS):" then the 24-word phrase on the
# NEXT line, indented (main.rs:74 -> `println!("\nMnemonic (SAVE THIS):\n  {}", ...)`).
_MNEMONIC_HDR = "Mnemonic (SAVE THIS):"
# `viaticum dr` success line (mirrors local_dr_test.sh grep "restore successful|restored").
_DR_OK_RE = re.compile(r"restore successful|restored", re.IGNORECASE)

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
        # label -> the 24-word mnemonic `viaticum init` GENERATED for this node,
        # captured from init stdout. Needed to re-derive the node's identity in a
        # disaster-recovery (`viaticum dr --mnemonic ...`) — the only way to prove
        # the network copy is recoverable after a full data-dir wipe.
        self._mnemonics: dict[str, Optional[str]] = {}
        # label -> last known pid (kept even after a node is killed, for measure()).
        self._pids: dict[str, Optional[int]] = {}
        # label -> NodePlan (set by join_node / recorded by the orchestrator via
        # set_plan); used for full fresh onboarding mid-run.
        self._plans: dict[str, object] = {}
        # (label, basename) -> restore job id from `restore --no-wait --json`.
        self._restore_jobs: dict[tuple[str, str], str] = {}
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
        # Capture the generated mnemonic so this node can be DR-recovered later
        # (the seed phrase is the ONLY way to re-derive the identity after a wipe).
        self._mnemonics[label] = self._parse_mnemonic(res.stdout or "")
        if self._mnemonics[label] is None:
            self.log(f"[fleet] WARN init {label}: could not capture mnemonic from stdout "
                     "(DR recovery for this node will be unavailable)")

    @staticmethod
    def _parse_mnemonic(stdout: str) -> Optional[str]:
        """Extract the 24-word phrase printed by `viaticum init`.

        main.rs prints `\\nMnemonic (SAVE THIS):\\n  {phrase}` — the header line
        followed by the indented phrase on the NEXT non-empty line. We find the
        header, then return the first subsequent non-empty line, stripped.
        """
        lines = stdout.splitlines()
        for i, line in enumerate(lines):
            if _MNEMONIC_HDR in line:
                for nxt in lines[i + 1:]:
                    phrase = nxt.strip()
                    if phrase:
                        return phrase
                return None
        return None

    def mnemonic(self, label: str) -> Optional[str]:
        """The mnemonic `viaticum init` generated for this label, or None."""
        return self._mnemonics.get(label)

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
        """Submit a restore job and return at once (`restore --no-wait --json`).

        Restore is a job in the daemon (restore-i4): the CLI prints the accepted
        job (with its id) and exits; find_restored() then follows the job with
        `restore --status <id> --json`. A refused request (path not in the catalog,
        nothing backed up) exits 1 and records no job."""
        res = self._cli(
            label, ["restore", str(original_path), "--no-wait", "--json"], timeout=30.0
        )
        first = (res.stdout or "").strip().splitlines()[:1]
        job_id = None
        if res.returncode == 0 and first:
            try:
                job_id = json.loads(first[0]).get("job_id")
            except ValueError:
                job_id = None
        if job_id:
            self._restore_jobs[(label, os.path.basename(str(original_path)))] = job_id
        else:
            self.log(f"[fleet] restore {label} {original_path} rc={res.returncode}: "
                     f"{(res.stderr or res.stdout or '').strip()[:200]}")

    def find_restored(self, label: str, filename: str) -> Optional[Path]:
        """The restored file, once its job is finished and lists it as restored.

        Asks the daemon for the job (`restore --status <id> --json`); returns
        <staging_path>/<catalog path> for the restored path whose basename is
        `filename` (the polygon restores distinct filenames), or None while the
        job runs, if it did not restore the file, or if no job was submitted.
        """
        base = os.path.basename(filename)
        job_id = self._restore_jobs.get((label, base))
        if not job_id:
            return None
        res = self._cli(label, ["restore", "--status", job_id, "--json"], timeout=30.0)
        if res.returncode != 0:
            return None
        try:
            job = json.loads((res.stdout or "").strip().splitlines()[-1])
        except (ValueError, IndexError):
            return None
        if job.get("state") != "finished":
            return None
        for p in job.get("restored_paths", []):
            if os.path.basename(p) == base:
                staged = Path(job["staging_path"]) / p.lstrip("/")
                return staged if staged.is_file() else None
        return None

    # ------------------------------------------------------------- disaster recovery
    def dr_recover(self, label: str, peer_addr: str, timeout_s: int = 240) -> bool:
        """TRUE network-recoverability: wipe a node's whole data-dir and rebuild its
        metadata FROM HOLDERS via `viaticum dr`, then relaunch the daemon.

        This is the only honest no-data-loss ground truth in the polygon. The daemon's
        restore is by-design 2-tier (restore/mod.rs): it rebuilds a file from the owner's
        LOCAL source first and only fetches from holders if the source is gone. In a live
        polygon node the watch-dir source is always present, so a plain `restore` ALWAYS
        uses tier-1 and never touches the network — a node that placed zero blocks still
        "restores ok". A full data-dir wipe deletes the source files too, so after DR the
        subsequent `restore` is FORCED down tier-2 (fetch symbols from holders, decode),
        which is the property we actually want to prove.

        Steps (mirror local_dr_test.sh Phase 4/5):
          1. stop the node's daemon (graceful, reuse kill_node);
          2. `rm -rf <node_dir>/*` — FULL wipe (identity is re-derived from the mnemonic);
          3. `viaticum --data-dir <node_dir> dr --mnemonic '<phrase>' --peer <peer_addr>`
             (capture output; success iff exit 0 AND output says "restore successful"/
             "restored" — same grep local_dr_test.sh uses);
          4. on success, re-apply the node's polygon config (dr writes the init default
             config: web_api enabled on the fixed 127.0.0.1:7383, which every node of the
             fleet on this host would share — P2 wants the plan's ephemeral ports) and
             relaunch the daemon + reconnect to the seed, so the caller can then drive
             per-file `request_restore` / `find_restored` (tier-2 network fetch).

        Returns True iff the dr command itself succeeded (a recovered daemon is then live);
        the per-file hash comparison is the caller's job (run.py), exactly as the local
        restore ledger separates the restore request from the hash check.
        """
        phrase = self._mnemonics.get(label)
        if not phrase:
            self.log(f"[dr] {label}: no captured mnemonic — cannot DR-recover")
            return False
        if not peer_addr:
            self.log(f"[dr] {label}: no peer addr for DR bootstrap")
            return False

        d = self.node_dir(label)
        # 1. stop the daemon (keeps the dir; we wipe its contents next).
        self.kill_node(label)
        # 2. full wipe of the data-dir contents (dir kept, identity re-derived from phrase).
        try:
            for child in d.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    try:
                        child.unlink()
                    except OSError:
                        pass
        except OSError as exc:
            self.log(f"[dr] {label}: wipe failed: {exc}")
            return False

        # 3. run `dr` — re-derive identity from the phrase, discover the SelfPointer via
        #    the --peer bootstrap, fetch SS blocks from holders, restore the DB metadata.
        cmd = [
            self._bin(),
            "--data-dir",
            str(d),
            "dr",
            "--mnemonic",
            phrase,
            "--peer",
            peer_addr,
        ]
        env = dict(os.environ)
        env.setdefault("RUST_LOG", "info")
        try:
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=float(timeout_s), env=env
            )
        except subprocess.TimeoutExpired as e:
            self.log(f"[dr] {label}: dr command timed out after {timeout_s}s")
            res = subprocess.CompletedProcess(cmd, 124, e.stdout or "", e.stderr or "timeout")

        out = (res.stdout or "") + (res.stderr or "")
        # Persist the dr transcript next to the node for post-mortem.
        try:
            (d / "dr.log").write_text(out)
        except OSError:
            pass
        ok = res.returncode == 0 and bool(_DR_OK_RE.search(out))
        if not ok:
            self.log(f"[dr] {label}: dr FAILED rc={res.returncode}; tail: "
                     f"{out.strip()[-300:]}")
            return False
        self.log(f"[dr] {label}: dr restore successful (metadata recovered from holders)")

        # 4. dr wrote the init DEFAULT config (web_api on the fixed 127.0.0.1:7383, shared
        #    by every fleet node on this host) — re-apply the node's polygon config (P2:
        #    ephemeral ports), then relaunch + reconnect.
        plan = self._plans.get(label)
        toml_text = getattr(plan, "config_toml", None) if plan is not None else None
        if toml_text:
            self.write_config(label, toml_text)
        watch_dirs = [str(self.files_dir(label))]
        importance = getattr(plan, "importance_multiplier", 1.0) != 1.0 if plan is not None else False
        self.launch_node(label, watch_dirs, importance_via_watchblock=importance)
        if not self.wait_ready(label, timeout_s=90):
            self.log(f"[dr] {label}: daemon not ready after DR relaunch")
            return False
        self._reconnect_to_seed(label)
        return True

    def find_dr_recovered(self, label: str, filename: str) -> Optional[Path]:
        """Locate a file recovered AFTER a DR + per-file restore.

        After dr_recover() rebuilt the metadata and the caller drove `request_restore`,
        the recovered bytes land in the SAME staging area as any restore
        (<data_dir>/restore/<job_id>/<rel_path>), so this just reuses find_restored.
        Kept as a distinctly-named entry point so run.py's DR flow reads clearly and a
        future DR-specific landing path is a single-line change here.
        """
        return self.find_restored(label, filename)

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
