# syncback-core

Pure logic library. No network, no async, no tokio. Millisecond tests.

## Dependencies

redb, blake3, reed-solomon-erasure, chacha20poly1305, ed25519-dalek, x25519-dalek, hkdf, sha2, serde, ciborium, thiserror, tracing.

## Module Build Order

Each module depends on the ones above it:

1. **types.rs** — newtype IDs, records (FileRecord, ShardRecord, PeerRecord, etc.), Timestamp, CBOR serialization
2. **db.rs** — `Db` newtype over `Arc<redb::Database>`, table definitions, CRUD operations, secondary index tables
3. **trust.rs** — `TrustEngine { db }`, P/I/S calculation, `trust = (kp*P + ki*I) * clamp(S, 0.1, 1.0)`
4. **escrow.rs** — `EscrowChecker { db }`, weeks_in_network tiers (4/13/26 weeks), free tier (1 GB)
5. **placement.rs** — `PlacementEngine { db }`, weighted selection (w=trust^2), cap 6/partner, adaptive n, erasure tiers
6. **budget.rs** — `BudgetPlanner { db }`, estimate budget_gb, importance sorting, cutoff
7. **messages.rs** — message types (CBOR), signing/verification, ShardDescriptor, directed encryption (ECDH)

## Conventions

- Newtype wrappers for all IDs (compiler prevents mixing shard_id with unit_id)
- `thiserror` error enum per module, no `anyhow`
- Module pattern: `pub struct FooEngine { db: Db }` + `impl` + error enum
- No traits for future flexibility, no builder patterns
- `Db` passed by clone (`Arc<redb::Database>` inside)

## Testing

- Unit tests in `#[cfg(test)] mod tests` in same file
- Real redb on tmpfile, no mocks
- Integration tests in `tests/` directory (cross-module scenarios)
- Test naming: `what_when_then` pattern
- Helper module: `testutil.rs` (test_db, test_peer, test_peers, week, test_shard)

## Protocol References

Read BEFORE implementing:
- `docs/protocol/overview.md` — wire format (§0.1), messages (§1.5), trust (§2.1-2.7), escrow (§2.6)
- `docs/protocol/architecture.md` — DB schema, data flow
- `docs/protocol/ADR-003-implementation-architecture.md` — conventions, error handling, code examples
