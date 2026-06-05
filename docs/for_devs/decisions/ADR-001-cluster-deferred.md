# ADR-001 — Cluster mode is forward-compat investment, not an alpha feature

**Status:** Accepted (2026-05-23)

## Context

The codebase contains cluster-mode machinery: device certificates, cert exchange
(`/viaticum/cert/1`), `ClusterState`, an event log with `apply_events`,
`ClusterSyncManager`, a two-level (device/master) trust model, and ESI-namespace
partitioning per device. A reader might reasonably expect multi-device-one-owner
clusters to work.

They do not work as an end-user feature in the alpha. The application layer is
intentionally incomplete: `apply_events` drops file/symbol events, there is no
intra-cluster deduplication, no `DeviceJoinRequest` flow, no cross-cluster mailbox.

## Decision

Cluster mode was built **for protocol and certificate forward-compatibility**, not
to ship a feature. The alpha targets a **single-node use case**: one user, one
device, backup to a P2P network, restore via mnemonic.

We do not add cluster features in the alpha. The passive cluster code stays because
removing it and re-adding it later would force breaking changes to the wire format,
key derivations, and cert exchange.

## Consequences

- Single-node backup/restore is the only supported, validated path for v0.1.0-alpha.
- Cluster code is present but inert; it does not affect single-node operation.
- Documentation states plainly: **cluster is experimental — use single-device for the alpha.**
- When cluster work resumes (a funded, dedicated phase), the wire format, cert
  format, and sync protocol do not have to break — the investment pays off then.
- The deferred part is the cluster **feature** (multi-device join, intra-cluster
  dedup, cross-cluster) → grant-funded R&D. Cluster **design bugs that touch the
  wire format or disaster recovery** (the self-pointer hints, staged rotation, TTL
  preservation — CL-7 Bug-A/D/G) are NOT deferred: they are fixed pre-release because
  the wire format freezes before the public release (see ADR-002).
