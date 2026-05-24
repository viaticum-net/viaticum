# Viaticum

Decentralized peer-to-peer cold backup with trust-based reputation. No tokens. No central operators. Week-scale time constant.

## What it is

Peers store encrypted erasure-coded fragments of each other's files. Trust between peers is earned over weeks of verifiable Proof-of-Storage. The protocol is built as a PID-style control loop applied to peer reputation, validated through ~24 numerical experiments before production implementation began.

The deliberate week-scale time constant is what makes Viaticum work on user-grade hardware: residential connections, laptops that sleep, NAS boxes behind NAT. Most P2P storage projects compete with hot cloud and lose, because they need second-scale operations that user devices cannot reliably provide. Viaticum competes with "nothing" — the 98% of people with no offsite backup.

For the full picture: see `docs/overview.md`.

## Status

**Pre-alpha.** Working prototype, not yet publicly released.

- ~73,000 lines of Rust across two crates (`viaticum-core`, `viaticum`)
- ~1,400 unit and integration tests passing
- E2E verified through 20-node fault-tolerance experiments (kill+recovery, repair-from-source, PoS under network partition); larger experiments (~100 nodes, ~1 year of simulated time) ongoing
- Protocol and core daemon: feature-complete
- Web UI prototype under [`web-ui/`](web-ui/): Svelte panels for connect / dashboard / folders / files / devices / settings, all wired to the daemon API; visual polish and a11y are Phase 3 work
- Packaging, distribution, integration documentation, public release: in progress

This is a research-grade prototype on its way to becoming infrastructure. If you are looking for something stable to back up your photos today, this is not yet that thing. If you are interested in the protocol design or want to participate as the project matures, read on.

## Documentation

- [`docs/overview.md`](docs/overview.md) — what Viaticum is, module map, end-to-end flows
- [`docs/why.md`](docs/why.md) — why Viaticum exists, where it sits in the field, the reasoning behind the design
- [`docs/protocol.md`](docs/protocol.md) — wire format, message types, handshake, key derivation
- [`docs/logic.md`](docs/logic.md) — algorithms: trust, placement, Proof-of-Storage, repair, deletion
- [`docs/architecture.md`](docs/architecture.md) — crate structure, data flow, config, DB schema
- [`docs/features.md`](docs/features.md) — prioritized future work
- [`docs/tech-debt.md`](docs/tech-debt.md) — known issues and deferred improvements
- [`docs/design/`](docs/design/) — design rationale for major decisions (RaptorQ choice, cluster mode, backup pipeline)
- [`docs/archive/research/`](docs/archive/research/) — research notes from the design phase
- [`docs/archive/experiments/`](docs/archive/experiments/) — 24 documented numerical experiments validating the trust protocol
- [`simulations/`](simulations/) — Python source for the experiments above (reproducible)

## Where it sits

Decentralized cold backup with trust earned over time, no token, owned and restored only by you. The projects that tried this exact thing — Wuala, CrashPlan's P2P backup, BuddyBackup — were proprietary and died with their companies; everything alive today (Tahoe-LAFS, Storj, Syncthing, Restic + B2) solves an adjacent problem. Why that niche stays empty, and the reasoning behind the design, is in [`docs/why.md`](docs/why.md).

## Maintainers

- **Ilya Cheshkov** — author and lead: protocol design, architecture, core implementation
- **Rostislav Snegirev** — contributor, learning the codebase and helping carry it toward release

## License

[AGPL-3.0-only](LICENSE). The Affero clause matters: if you modify Viaticum and run it as a network service, you must publish the modifications under the same license. This protects the project against being absorbed into closed-source forks.

## Acknowledgments

The Phase 2 implementation used substantial assistance from generative AI (Claude / Claude Code) for boilerplate, test scaffolding, and refactoring. All architecture, protocol design, and final code review are human-authored. The Phase 1 research and simulation work (`docs/archive/research/`, `docs/archive/experiments/`) was conducted with conventional numerical tooling.
