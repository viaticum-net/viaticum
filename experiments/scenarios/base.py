"""Base class for experiment scenarios."""

from abc import ABC, abstractmethod
from runner import Cluster, MetricsCollector, Node


class BaseScenario(ABC):
    """Abstract base for all experiment scenarios."""

    name: str = "base"

    def __init__(self, cluster: Cluster, metrics: MetricsCollector):
        self.cluster = cluster
        self.metrics = metrics

    @abstractmethod
    def run(self) -> bool:
        """Run the scenario. Returns True on success."""
        ...

    def snapshot_all(self) -> None:
        """Take metrics snapshot from all nodes."""
        for name, node in self.cluster.nodes.items():
            self.metrics.snapshot(self.name, name, node)
            self.metrics.snapshot_peers(self.name, name, node)

    def log(self, event_type: str, node: str = "", details: str = "") -> None:
        """Log an event."""
        self.metrics.log_event(self.name, event_type, node, details)
        print(f"  [{self.name}] {event_type}: {details}")
