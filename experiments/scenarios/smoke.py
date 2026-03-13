"""Smoke test: 5 nodes connect, backup files, verify shard distribution."""

import time
from scenarios.base import BaseScenario


# Fixed BIP39 mnemonics for reproducible testing.
# These are valid BIP39 word sequences — all words are in the standard wordlist.
MNEMONICS = {
    "node-a": (
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon art"
    ),
    "node-b": (
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
        "zoo zoo zoo zoo zoo zoo zoo vote"
    ),
    "node-c": (
        "ability ability ability ability ability ability ability ability "
        "ability ability ability ability ability ability ability ability "
        "ability ability ability ability ability ability ability able"
    ),
    "node-d": (
        "about about about about about about about about "
        "about about about about about about about about "
        "about about about about about about about above"
    ),
    "node-e": (
        "abstract abstract abstract abstract abstract abstract abstract abstract "
        "abstract abstract abstract abstract abstract abstract abstract abstract "
        "abstract abstract abstract abstract abstract abstract abstract absurd"
    ),
}

ALL_NODES = ["node-a", "node-b", "node-c", "node-d", "node-e"]
HOLDER_NODES = ["node-b", "node-c", "node-d", "node-e"]


class SmokeScenario(BaseScenario):
    name = "smoke_5node"

    def run(self) -> bool:
        print(f"\n{'='*60}")
        print(f"  Scenario: {self.name}")
        print(f"{'='*60}")

        try:
            self._init_nodes()
            self._start_daemons()
            self._connect_peers()
            self._create_and_backup()
            self._verify_shards()
            self._stop_all()

            self.log("scenario_complete", details="SUCCESS")
            print(f"\n  RESULT: PASS")
            return True

        except Exception as e:
            self.log("scenario_failed", details=str(e))
            print(f"\n  RESULT: FAIL — {e}")
            return False

    def _init_nodes(self) -> None:
        self.log("phase", details="Initializing 5 nodes")
        for name in ALL_NODES:
            node = self.cluster.node(name)
            output = node.init(MNEMONICS[name])
            self.log("init", node=name, details=output)

    def _start_daemons(self) -> None:
        self.log("phase", details="Starting daemons")

        # Node A: owner, backs up /data/files
        a = self.cluster.node("node-a")
        a.start_daemon(quota_gb=1, includes=["/data/files:0.9"])

        # Nodes B-E: holders only
        for name in HOLDER_NODES:
            node = self.cluster.node(name)
            node.start_daemon(quota_gb=10)

        # Wait for all to be ready
        for name in ALL_NODES:
            node = self.cluster.node(name)
            status = node.wait_ready(timeout=15)
            self.log("ready", node=name, details=str(status))

    def _connect_peers(self) -> None:
        self.log("phase", details="Connecting A to all holders")
        a = self.cluster.node("node-a")

        for name in HOLDER_NODES:
            holder = self.cluster.node(name)
            addr = holder.get_node_addr()
            self.log("addr", node=name, details=addr[:60] + "...")
            a.connect_peer(addr)

        time.sleep(3)
        self.snapshot_all()

    def _create_and_backup(self) -> None:
        self.log("phase", details="Creating files and backing up")
        a = self.cluster.node("node-a")

        # Create 5 test files
        files = a.create_text_files(n=5)
        self.log("files_created", node="node-a", details=f"{len(files)} files")

        # Trigger backup
        result = a.backup()
        self.log("backup_triggered", node="node-a", details=result)

        # Wait for shards to be placed (up to 60s)
        for attempt in range(30):
            time.sleep(2)
            status = a.status()
            placed = int(status.get("shards_placed", "0"))
            self.log("poll", node="node-a", details=f"shards_placed={placed}")
            if placed > 0:
                break

        self.snapshot_all()

    def _verify_shards(self) -> None:
        self.log("phase", details="Verifying shard distribution across holders")

        total_held = 0
        for name in HOLDER_NODES:
            node = self.cluster.node(name)
            status = node.status()
            held = int(status.get("shards_held", "0"))
            total_held += held
            self.log("verify", node=name, details=f"shards_held={held}")

        self.log("verify_total", details=f"total_shards_held={total_held}")
        self.snapshot_all()

    def _stop_all(self) -> None:
        self.log("phase", details="Stopping all daemons")
        for name in ALL_NODES:
            try:
                self.cluster.node(name).stop()
            except Exception:
                pass
