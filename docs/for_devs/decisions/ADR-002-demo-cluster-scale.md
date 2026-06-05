# ADR-002 — Replace the naive distribution primitives before the public release, not band-aid them

**Status:** Accepted (2026-05-23, revised 2026-06-05)

## Context

Two subsystems — SystemState distribution and the relay board — use "push-to-all"
primitives: a node pushes sequentially to every peer returned by `list_all_peers()`
with a short timeout. This is demo-grade. It works at the scale we validate today
(a ~20–100 node demo cluster) but does not scale, and the relay board / SystemState
paths also underlie single-node disaster recovery and PoS-relay fallback.

A planned redesign — unified mailbox routing with deterministic Kademlia-based
discovery and self-pointers — replaces both primitives wholesale. The design is
complete (see `cluster_mode_audit.md` §"Final design"). It is bounded engineering
(~2–3 weeks), not research, and it is independent of the grant-funded cluster R&D
(deduplication is owner-side and does not touch the wire format).

Two tempting shortcuts were considered and rejected:

- **Band-aid the naive primitives** (filter to connected peers, parallelise, add a
  sync cursor) to stretch them to N ≤ 100 for one release.
- **Defer the mailbox redesign to a later funded phase** and ship the alpha on the
  demo-grade primitives with an honest "demo-cluster scale" disclaimer.

## Decision

Do neither. **Implement the mailbox redesign as one clean replacement before the
public release**, so the wire format is frozen with mailbox in place.

- No band-aids: a band-aid whose lifetime is short (a replacement is planned) is
  net-negative, and its new fields / wire changes would risk breaking the migration
  path to the redesign.
- Not deferred to the grant: the redesign breaks the wire format, and the grant's
  cluster work was deliberately scoped to leave the wire format untouched — so it has
  no funded home. It is pre-release cleanup done with our own hands.

## Consequences

- The mailbox refactor is the last step of the pre-release cleanup sequence (CL-6 in
  the system review), after the correctness and DR-prep fixes it depends on
  (notably the self-pointer `base_holder_hints`, CL-7 Bug-A).
- The wire format is frozen **with mailbox in place** — early adopters do not receive
  a later network-breaking upgrade. Breaking the format before there are real users is
  cheap; breaking it after is not.
- Single-node DR improves as a side effect: restore walks a self-pointer via
  deterministic discovery instead of relying on push-to-all reaching online peers.
- Before implementation, the change is scoped precisely (exact wire deltas, whether a
  version-negotiated migration is feasible vs a hard break) rather than committed blind.
