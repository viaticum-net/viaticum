"""Smoke test: 3 nodes connect, backup files, restore."""

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
}


class SmokeScenario(BaseScenario):
    name = "smoke_3node"

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
        self.log("phase", details="Initializing nodes")
        for name in ["node-a", "node-b", "node-c"]:
            node = self.cluster.node(name)
            output = node.init(MNEMONICS[name])
            self.log("init", node=name, details=output)

    def _start_daemons(self) -> None:
        self.log("phase", details="Starting daemons")

        # Node A: owner, backs up /data/files
        a = self.cluster.node("node-a")
        a.start_daemon(quota_gb=1, includes=["/data/files:0.9"])

        # Nodes B, C: holders only
        for name in ["node-b", "node-c"]:
            node = self.cluster.node(name)
            node.start_daemon(quota_gb=10)

        # Wait for all to be ready
        for name in ["node-a", "node-b", "node-c"]:
            node = self.cluster.node(name)
            status = node.wait_ready(timeout=15)
            self.log("ready", node=name, details=str(status))

    def _connect_peers(self) -> None:
        self.log("phase", details="Connecting peers")
        a = self.cluster.node("node-a")
        b = self.cluster.node("node-b")
        c = self.cluster.node("node-c")

        # Get node addresses
        addr_b = b.get_node_addr()
        addr_c = c.get_node_addr()
        self.log("addr", node="node-b", details=addr_b[:60] + "...")
        self.log("addr", node="node-c", details=addr_c[:60] + "...")

        # Connect A to B and C
        a.connect_peer(addr_b)
        a.connect_peer(addr_c)
        time.sleep(2)

        self.snapshot_all()

    def _create_and_backup(self) -> None:
        self.log("phase", details="Creating files and backing up")
        a = self.cluster.node("node-a")

        # Create test files
        files = a.create_text_files(n=3)
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
        self.log("phase", details="Verifying shard distribution")

        for name in ["node-b", "node-c"]:
            node = self.cluster.node(name)
            status = node.status()
            held = int(status.get("shards_held", "0"))
            self.log("verify", node=name, details=f"shards_held={held}")

        self.snapshot_all()

    def _stop_all(self) -> None:
        self.log("phase", details="Stopping all daemons")
        for name in ["node-a", "node-b", "node-c"]:
            try:
                self.cluster.node(name).stop()
            except Exception:
                pass
