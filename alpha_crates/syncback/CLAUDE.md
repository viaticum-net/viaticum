# syncback (daemon + CLI)

Binary crate. Depends on syncback-core + iroh + notify + tokio.

## Phase 2-3 (build after syncback-core is complete)

## Architecture

Single process, 5 tokio tasks:

| Task | Event loop | Role |
|------|-----------|------|
| Watcher | notify events | Sends DirtyEvent to Processor |
| Scheduler | tokio timer | Sends commands (WeeklySync, PosRound, Vacuum) |
| Network | iroh endpoint | Connections, gossip, blob transfer |
| Processor | cmd_rx + net_rx | Central orchestrator, sole DB writer |
| CLI Server | Unix socket | Serves CLI commands |

Trust, Shard Manager, Budget, Escrow, Packer — modules (not tasks), called from Processor.

## Communication

All DB writes go through Processor only. Other tasks send events via tokio::mpsc channels.

## Modules

- `daemon/processor.rs` — central command handler, holds all engine instances
- `daemon/network.rs` — iroh endpoint, handshake, board sync
- `daemon/watcher.rs` — notify file watching
- `daemon/scheduler.rs` — timer loop for periodic tasks
- `daemon/packer.rs` — files -> units (pack/chunk/delta/vacuum)
- `daemon/storage.rs` — holder: accept/store foreign shards, PoS responses, eviction
- `daemon/shard_manager.rs` — encrypt -> erasure -> placement -> upload, repair
- `daemon/cli_server.rs` — Unix socket JSON API
- `cli.rs` — subcommands: daemon, init, status, backup, restore

## Error Handling (alpha)

- Expected (peer offline, not enough peers): log info, continue, retry next cycle
- Unexpected (DB error, invalid message): panic (systemd restarts)
- Fatal (iroh endpoint closed): log error, graceful shutdown

## Testing

- Integration tests in `tests/` — real iroh, 2 nodes on localhost
- Smoke tests in `tests/` — daemon starts, nodes discover each other
- No mocks — real iroh, real redb

## Protocol References

- `docs/protocol/overview.md` — shard ops (§1.7), PoS (§1.3), disk pressure (§2.8)
- `docs/protocol/architecture.md` — daemon components, scheduler, data flow
- `docs/protocol/ADR-003-implementation-architecture.md` — tokio tasks, channels, shutdown
