# Architecture Decision Records

Each ADR captures one intentional, non-obvious design decision: the context, the
choice, and the trade-off accepted. ADRs are immutable once accepted — a later
decision supersedes an earlier one with a new ADR rather than editing it.

Format: short. Context → Decision → Consequences. No template ceremony.

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-001](ADR-001-cluster-deferred.md) | Cluster mode is forward-compat investment, not an alpha feature | Accepted |
| [ADR-002](ADR-002-demo-cluster-scale.md) | Alpha validated at demo-cluster scale; no band-aids to naive primitives | Accepted |
| [ADR-003](ADR-003-own-kademlia.md) | Our own Kademlia DHT from day one, no IPFS | Accepted |
| [ADR-004](ADR-004-mailbox-bus.md) | Mailbox bus: directed store-and-forward replaces epidemic relay + blob push | Accepted |
