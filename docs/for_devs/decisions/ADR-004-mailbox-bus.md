# ADR-004 — Mailbox bus: directed store-and-forward replaces the epidemic relay and the blob push

**Status:** Accepted (2026-07-05)

Implements the decision recorded in [ADR-002](ADR-002-demo-cluster-scale.md). ADR-002
committed to replacing the two "push-to-all" primitives (the epidemic relay board and
the SystemState blob push) with a mailbox redesign before the public release. This ADR
records the design that was built and the non-obvious sub-decisions taken along the way,
so they are not re-litigated later.

## Context

Before the redesign, two mechanisms carried deferred messages (messages the addressee
cannot receive synchronously because it is offline — the normal case for cold backup):

- **Epidemic relay board** — an append-only board gossiped hop-by-hop (`MAX_RELAY_HOP = 2`)
  between peers via `BoardSync`. Directed entries were sealed with per-message ECDH
  (X25519). Carried PoS challenges, drop notices, peer announces, revocations.
- **SystemState blob push** — the daemon serialised its whole metadata DB into one
  encrypted blob and pushed it to *every* peer (`list_all_peers()`), each keeping one blob
  per owner in a `system_state_blobs` table. Disaster recovery asked seed peers for the blob.

Both are demo-grade: gossip floods, blob-push is O(peers) per cycle and duplicates the
redundancy machinery the backup pipeline already provides. Neither has any live-fleet
constraint to preserve — there is no deployed network (the wire format is being frozen
now, with the replacement in place, precisely so early adopters never take a breaking
upgrade).

## Decision

A single **directed mailbox bus**. Every message is addressed to one recipient's master
identity. The peers Kademlia-closest to `SHA256(target_pub)` act as **postmen**: senders
deposit an entry with the closest `MAILBOX_WRITE_FANOUT = 30`, the addressee later polls
the closest `MAILBOX_READ_FANOUT = 300` for its own mail. No hops, no flooding. Entries
ride the main `/viaticum/1` request-response protocol (`MailboxStore*` / `MailboxFetch*`);
there is no separate mailbox protocol. Full wire and behavioural detail: [protocol.md §1.5](../protocol.md).

Four sub-decisions worth their own record:

1. **Directed, not epidemic.** Postman store-and-forward keyed on XOR distance gives
   deterministic, bounded delivery: a sender knows exactly which peers to deposit with and
   an addressee knows exactly which to poll. Gossip's appeal — reaching peers you have no
   address for — is already served by the Kademlia DHT for discovery; deferred *delivery*
   does not need it.

2. **Revocation goes to storage-relationship peers only, not broadcast.** When a device is
   revoked, the `Revocation` entry is addressed to the master's actual storage peers
   (holders of our data ∪ owners we hold for) — the set that must act on it — rather than
   flooded to everyone. Broadcasting to peers with no storage relationship was
   over-engineering. The accepted gap: a storage peer offline longer than `REVOCATION_TTL`
   (30 days) misses it; the eventual fix is pull-on-verify (a receiver queries the sender's
   revocation list on connect), tracked separately.

3. **SystemState becomes an erasure-coded SS-block plus a signed self-pointer**, not a
   dedicated blob. The DB snapshot is encrypted (key derived from the seed) and erasure-coded
   like ordinary user data, so it inherits the same redundancy, per-holder binding and PoS.
   The only thing DR must find "from nothing" is a tiny signed `SelfPointer` naming the
   SS-block and its holders — and that lives in the mailbox under the owner's own identity,
   as a **high-trust** entry (5-year TTL, never evicted by churn or disk pressure). This
   removed a whole parallel storage/transport mechanism and its `system_state_blobs` table.

4. **No per-message ECDH.** Point-to-point delivery already runs over Noise IX, and each
   mailbox payload carries an Ed25519 signature verified against `entry.sender`. The
   relay-era X25519 seal is therefore redundant. The keypair is still derived and gossiped
   in `PeerAnnounce`/`PeerRecord` for now (reserved), but no code path consumes it.

## Consequences

- **Wire format changed and is now frozen with mailbox in place.** Removed: `BoardSync`,
  `SystemState{Backup,Ack,Request,Response}` message variants; the `system_state_blobs`
  table (a one-time `drop_legacy_system_state_blobs` migration deletes it on DB open). Added:
  `MailboxStoreRequest/Response`, `MailboxFetchRequest/Response` and the `mailbox_entries` /
  `mailbox_bytes_by_target` tables. No live nodes to break.
- **DR is more robust.** It walks a deterministic self-pointer discovered via Kademlia
  (`get_closest_peers` → `dr_walk`) instead of hoping a push-to-all reached an online peer.
- **Storage is bounded per target.** `MAX_MAILBOX_BYTES_PER_PEER` (100 MiB) and
  `MAX_ENTRY_BYTES` (256 KiB) cap what a postman stores; TTL and membership sweeps reclaim it;
  a sender-supplied TTL is clamped down to the per-class maximum to prevent squatting.
- **Two vestiges remain as tech-debt, not behaviour:** the relay/board constants
  (`MAX_RELAY_HOP`, `RELAY_TTL_SECS`, `MAX_BOARD_*`) and the X25519 plumbing still compile but
  have no live caller. They are safe to delete in a follow-up cleanup; documenting them here
  so a reader does not mistake dead constants for active behaviour.
- **Latent-but-unwired capabilities:** `CancelDelete` has a full receiver path but no
  production producer yet; LRU disk-pressure eviction of mailbox entries is implemented and
  unit-tested at the DB layer but not wired to a live disk-pressure trigger (the store path
  rejects over-quota instead). Documented so they are not mistaken for active features.
