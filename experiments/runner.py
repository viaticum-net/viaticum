#!/usr/bin/env python3
"""SyncBack experiment runner — manages Docker containers and sends CLI commands."""

import json
import subprocess
import time
import sqlite3
from pathlib import Path
from typing import Optional
from datetime import datetime


class Node:
    """Represents a single syncback node running in Docker."""

    def __init__(self, container_name: str):
        self.container = container_name
        self.node_addr: Optional[str] = None

    def exec(self, *args: str, timeout: int = 30) -> str:
        """Run a command in the container, return stdout."""
        cmd = ["docker", "exec", self.container] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(f"docker exec failed: {result.stderr}")
        return result.stdout.strip()

    def exec_bg(self, *args: str) -> None:
        """Run a command in the container detached."""
        cmd = ["docker", "exec", "-d", self.container] + list(args)
        subprocess.run(cmd, check=True)

    def init(self, mnemonic: str) -> str:
        """Initialize the node with a mnemonic. Returns identity hex."""
        output = self.exec("syncback", "init", "--mnemonic", mnemonic)
        return output

    def start_daemon(self, time_scale: int = 1, quota_gb: int = 100,
                     includes: Optional[list[str]] = None) -> None:
        """Start the daemon in background."""
        args = ["syncback", "daemon", "--time-scale", str(time_scale),
                "--quota-gb", str(quota_gb)]
        if includes:
            for inc in includes:
                args.extend(["--include", inc])
        self.exec_bg(*args)

    def wait_ready(self, timeout: int = 10) -> dict:
        """Wait for daemon to respond to status."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                status = self.status()
                return status
            except Exception:
                time.sleep(0.5)
        raise TimeoutError(f"{self.container} not ready after {timeout}s")

    def status(self) -> dict:
        """Query daemon status via CLI. Parse human output into dict."""
        raw = self.exec("syncback", "status")
        result = {}
        for line in raw.strip().split('\n'):
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip().replace(' ', '_')
                val = parts[1].strip()
                result[key] = val
        return result

    def status_json(self) -> dict:
        """Query daemon status via raw socket JSON."""
        raw = self.exec("sh", "-c",
            'echo \'{"cmd":"status"}\' | socat - UNIX-CONNECT:/home/syncback/.syncback/syncback.sock')
        return json.loads(raw)

    def peers(self) -> str:
        """Get peers list."""
        return self.exec("syncback", "peers")

    def peers_json(self) -> dict:
        """Get peers via socket."""
        raw = self.exec("sh", "-c",
            'echo \'{"cmd":"peers"}\' | socat - UNIX-CONNECT:/home/syncback/.syncback/syncback.sock')
        return json.loads(raw)

    def connect_peer(self, node_addr: str) -> str:
        """Connect to another peer by node_addr JSON string."""
        escaped = node_addr.replace('"', '\\"')
        raw = self.exec("sh", "-c",
            f'echo \'{{"cmd":"connect_peer","node_addr":"{escaped}"}}\' | socat - UNIX-CONNECT:/home/syncback/.syncback/syncback.sock')
        return raw

    def backup(self) -> str:
        """Trigger immediate backup."""
        return self.exec("syncback", "backup")

    def stop(self) -> str:
        """Gracefully stop daemon."""
        return self.exec("syncback", "stop")

    def get_node_addr(self) -> str:
        """Get this node's addr from status."""
        status = self.status_json()
        # StatusOk has own_node_id field
        if "own_node_id" in status:
            self.node_addr = status["own_node_id"]
        elif "status_ok" in status:
            self.node_addr = status["status_ok"].get("own_node_id", "")
        return self.node_addr or ""

    def create_test_files(self, n: int = 5, size_kb: int = 10) -> list[str]:
        """Create test files in /data/files/."""
        files = []
        for i in range(n):
            filename = f"testfile_{i}.dat"
            self.exec("sh", "-c",
                f"dd if=/dev/urandom of=/data/files/{filename} bs=1024 count={size_kb} 2>/dev/null")
            files.append(f"/data/files/{filename}")
        return files

    def create_text_files(self, n: int = 5) -> list[tuple[str, str]]:
        """Create text files with known content. Returns (path, content) pairs."""
        files = []
        for i in range(n):
            filename = f"text_{i}.txt"
            content = f"Hello from file {i}! " * 100 + "\n"
            self.exec("sh", "-c",
                f"echo -n '{content}' > /data/files/{filename}")
            files.append((f"/data/files/{filename}", content))
        return files


class Cluster:
    """Manages a cluster of syncback nodes via Docker Compose."""

    def __init__(self, compose_file: str = "experiments/docker/compose.yml",
                 project_dir: str = "."):
        self.compose_file = compose_file
        self.project_dir = project_dir
        self.nodes: dict[str, Node] = {}

    def build(self) -> None:
        """Build Docker images."""
        print("Building Docker images...")
        subprocess.run(
            ["docker", "compose", "-f", self.compose_file, "build"],
            cwd=self.project_dir, check=True
        )

    def up(self, node_names: Optional[list[str]] = None) -> None:
        """Start containers."""
        cmd = ["docker", "compose", "-f", self.compose_file, "up", "-d"]
        if node_names:
            cmd.extend(node_names)
        subprocess.run(cmd, cwd=self.project_dir, check=True)

        # Discover container names
        result = subprocess.run(
            ["docker", "compose", "-f", self.compose_file, "ps", "--format", "json"],
            cwd=self.project_dir, capture_output=True, text=True
        )
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            info = json.loads(line)
            name = info.get("Name", "")
            service = info.get("Service", "")
            self.nodes[service] = Node(name)

    def down(self) -> None:
        """Stop and remove containers."""
        subprocess.run(
            ["docker", "compose", "-f", self.compose_file, "down", "-v"],
            cwd=self.project_dir, check=True
        )
        self.nodes.clear()

    def node(self, name: str) -> Node:
        """Get a node by service name."""
        return self.nodes[name]


class MetricsCollector:
    """Collects metrics from nodes into SQLite."""

    def __init__(self, db_path: str = "experiments/results/metrics.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self._init_tables()

    def _init_tables(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                scenario TEXT NOT NULL,
                node TEXT NOT NULL,
                uptime_secs INTEGER,
                peer_count INTEGER,
                shards_held INTEGER,
                shards_placed INTEGER,
                budget_gb REAL,
                dirty_files INTEGER,
                raw_json TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS peer_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                scenario TEXT NOT NULL,
                node TEXT NOT NULL,
                peer_identity TEXT,
                trust_p REAL,
                trust_i REAL,
                trust_s REAL,
                trust_score REAL,
                weeks_in_network INTEGER,
                shards_held_for_us INTEGER
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                scenario TEXT NOT NULL,
                event_type TEXT NOT NULL,
                node TEXT,
                details TEXT
            )
        """)
        self.conn.commit()

    def snapshot(self, scenario: str, node_name: str, node: Node) -> None:
        """Take a status snapshot from a node."""
        try:
            status = node.status_json()
            ts = datetime.utcnow().isoformat()

            payload = status.get("status_ok", status)
            self.conn.execute("""
                INSERT INTO snapshots (ts, scenario, node, uptime_secs, peer_count,
                    shards_held, shards_placed, budget_gb, dirty_files, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts, scenario, node_name,
                payload.get("uptime_secs", 0),
                payload.get("peer_count", 0),
                payload.get("shards_held", 0),
                payload.get("shards_placed", 0),
                payload.get("budget_gb", 0.0),
                payload.get("dirty_files", 0),
                json.dumps(status)
            ))
            self.conn.commit()
        except Exception as e:
            print(f"  [metrics] snapshot failed for {node_name}: {e}")

    def snapshot_peers(self, scenario: str, node_name: str, node: Node) -> None:
        """Take a peers snapshot from a node."""
        try:
            peers = node.peers_json()
            ts = datetime.utcnow().isoformat()

            peer_list = peers.get("peers_ok", {}).get("peers", [])
            for p in peer_list:
                self.conn.execute("""
                    INSERT INTO peer_snapshots (ts, scenario, node, peer_identity,
                        trust_p, trust_i, trust_s, trust_score, weeks_in_network,
                        shards_held_for_us)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ts, scenario, node_name,
                    p.get("identity", ""),
                    p.get("trust_p", 0.0),
                    p.get("trust_i", 0.0),
                    p.get("trust_s", 0.0),
                    p.get("trust_score", 0.0),
                    p.get("weeks_in_network", 0),
                    p.get("shards_held_for_us", 0)
                ))
            self.conn.commit()
        except Exception as e:
            print(f"  [metrics] peers snapshot failed for {node_name}: {e}")

    def log_event(self, scenario: str, event_type: str,
                  node: Optional[str] = None, details: str = "") -> None:
        """Log a scenario event."""
        ts = datetime.utcnow().isoformat()
        self.conn.execute("""
            INSERT INTO events (ts, scenario, event_type, node, details)
            VALUES (?, ?, ?, ?, ?)
        """, (ts, scenario, event_type, node, details))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
