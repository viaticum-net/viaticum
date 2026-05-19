#!/usr/bin/env python3
"""Viaticum experiment runner — manages Docker containers and sends CLI commands."""

import json
import subprocess
import time
import sqlite3
from pathlib import Path
from typing import Optional
from datetime import datetime


class Node:
    """Represents a single viaticum node running in Docker."""

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
        output = self.exec("viaticum", "init", "--mnemonic", mnemonic)
        return output

    def start_daemon(self, time_scale: int = 1, quota_gb: int = 100,
                     includes: Optional[list[str]] = None) -> None:
        """Start the daemon in background."""
        args = ["viaticum", "daemon", "--time-scale", str(time_scale),
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
        """Query daemon status via CLI JSON output."""
        raw = self.exec("viaticum", "status", "--json")
        return json.loads(raw)

    def connect_peer(self, node_addr: str) -> str:
        """Connect to another peer by node address."""
        return self.exec("viaticum", "connect", node_addr)

    def backup(self) -> str:
        """Trigger immediate backup."""
        return self.exec("viaticum", "backup")

    def stop(self) -> str:
        """Gracefully stop daemon."""
        return self.exec("viaticum", "stop")

    def get_node_addr(self) -> str:
        """Get this node's addr from status."""
        status = self.status()
        self.node_addr = status.get("node_addr", "")
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
    """Manages a cluster of viaticum nodes via Docker Compose."""

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
            status = node.status()
            ts = datetime.utcnow().isoformat()
            self.conn.execute("""
                INSERT INTO snapshots (ts, scenario, node, uptime_secs, peer_count,
                    shards_held, shards_placed, budget_gb, dirty_files, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts, scenario, node_name,
                0,  # uptime not in status yet
                status.get("peer_count", 0),
                status.get("holding_bytes", 0),
                status.get("placement_count", 0),
                0.0,  # budget_gb not directly available
                0,    # dirty_files not in status yet
                json.dumps(status)
            ))
            self.conn.commit()
        except Exception as e:
            print(f"  [metrics] snapshot failed for {node_name}: {e}")

    def snapshot_peers(self, scenario: str, node_name: str, node: Node) -> None:
        """Take a peers snapshot from a node."""
        try:
            status = node.status()
            ts = datetime.utcnow().isoformat()
            for p in status.get("peers", []):
                self.conn.execute("""
                    INSERT INTO peer_snapshots (ts, scenario, node, peer_identity,
                        trust_p, trust_i, trust_s, trust_score, weeks_in_network,
                        shards_held_for_us)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ts, scenario, node_name,
                    p.get("identity_hex", ""),
                    p.get("trust_p", 0.0),
                    p.get("trust_i", 0.0),
                    p.get("trust_s", 0.0),
                    p.get("trust", 0.0),
                    0,  # weeks_in_network not directly available
                    p.get("bytes_peer_stores", 0)
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
