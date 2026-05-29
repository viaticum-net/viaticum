# Viaticum

Decentralized peer-to-peer cold backup with trust-based reputation. No tokens. No central operators. Week-scale time constant.

## What it is

Peers store encrypted, erasure-coded fragments of each other's files. You earn the right to be backed up by backing others up, and trust between peers grows over weeks of verified storage. There are no accounts and no subscription, and nobody runs a server in the middle.

It's a cold backup, not a cloud drive. Restores take days rather than seconds, and that is the point: it lets the network tolerate peers that sleep, sit behind NAT, or come online only a few hours a day, which is what ordinary home machines actually do. What it competes with is having no offsite backup at all.

See [`docs/overview.md`](docs/overview.md) for how it works and [`docs/why.md`](docs/why.md) for why it's built this way.

## Who it's for

Self-hosters who would rather not hand their data to a cloud: people running TrueNAS, Unraid or OpenMediaVault, or apps like Immich and Nextcloud, and anyone whose backup today is `rsync` to a drive in the same room. And people for whom privacy is not negotiable, whose backups must stay encrypted and outside any single company's reach: journalists, activists, anyone holding sensitive data. And anyone who would rather not pay a monthly backup bill but has spare disk to trade — lend space to the network, get space back.

## Status

Pre-release, and rough. It works: you can run the daemon, back up folders, and get them back, and it has been tested end to end across 20 nodes with node kills and recovery. It is not stable, though. Breaking changes are coming, including planned changes to the wire protocol, so don't point it at data you can't afford to lose.

If you want to poke at it or help test, you're welcome. Today there's a web UI and a Linux daemon. Windows and macOS builds are work in progress.

## Try it

There's no prebuilt package yet, so you build from source. You need Rust (stable) and Node.js.

```sh
# build the web UI — the daemon embeds it at compile time
cd web-ui && npm install && npm run build && cd ..

# build the daemon and CLI
cargo build --release --workspace

# create an identity (writes a 24-word recovery phrase — keep it safe)
./target/release/viaticum init

# run the daemon and watch a folder
./target/release/viaticum daemon --watch ~/Documents

# open the web UI in your browser
./target/release/viaticum open
```

To back up with a friend, swap node addresses (`viaticum status` prints yours) and run `viaticum connect <addr>` on each side.

## Documentation

- [`docs/overview.md`](docs/overview.md) — what Viaticum is, module map, end-to-end flows
- [`docs/usage.md`](docs/usage.md) — how to use it: CLI and web UI, from first run to disaster recovery
- [`docs/why.md`](docs/why.md) — why Viaticum exists, where it sits in the field, the reasoning behind the design
- [`docs/features.md`](docs/features.md) — roadmap: what works today and where it's heading
- [`docs/for_devs/protocol.md`](docs/for_devs/protocol.md) — wire format, message types, handshake, key derivation
- [`docs/for_devs/logic.md`](docs/for_devs/logic.md) — algorithms: trust, placement, Proof-of-Storage, repair, deletion
- [`docs/for_devs/architecture.md`](docs/for_devs/architecture.md) — crate structure, data flow, config, DB schema
- [`docs/for_devs/design/`](docs/for_devs/design/) — design rationale for major decisions (RaptorQ choice, cluster mode, backup pipeline)
- [`docs/archive/research/`](docs/archive/research/) — research notes from the design phase
- [`docs/archive/experiments/`](docs/archive/experiments/) — 24 documented numerical experiments validating the trust protocol
- [`simulations/`](simulations/) — Python source for the experiments above (reproducible)

## Maintainers

- **Ilya Cheshkov** — author and lead: protocol design, architecture, core implementation
- **Rostislav Snegirev** — contributor: built the web-based UI, now learning the wider codebase while helping carry the project toward release

## License

[AGPL-3.0-only](LICENSE). The Affero clause matters: if you modify Viaticum and run it as a network service, you must publish the modifications under the same license. This protects the project against being absorbed into closed-source forks.

## Acknowledgments

Implementation used substantial assistance from generative AI (Claude / Claude Code) for boilerplate, test scaffolding, and refactoring. The architecture, protocol design, and final code review are human-authored. The earlier research and simulation work (`docs/archive/research/`, `docs/archive/experiments/`) used conventional numerical tooling.
