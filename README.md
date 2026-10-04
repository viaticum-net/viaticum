# Viaticum

Decentralized peer-to-peer cold backup with trust-based reputation. No tokens. No central operators. Week-scale time constant.

## What it is

Peers store encrypted, erasure-coded fragments of each other's files. You earn the right to be backed up by backing others up, and trust between peers grows over weeks of verified storage. There are no accounts and no subscription, and nobody runs a server in the middle.

It's a cold backup, not a cloud drive. Restores take days rather than seconds, and that is the point: it lets the network tolerate peers that sleep, sit behind NAT, or come online only a few hours a day, which is what ordinary home machines actually do. What it competes with is having no offsite backup at all.

See [`docs/overview.md`](docs/overview.md) for how it works and [`docs/why.md`](docs/why.md) for why it's built this way.

## Who it's for

Self-hosters who would rather not hand their data to a cloud: people running TrueNAS, Unraid or OpenMediaVault, or apps like Immich and Nextcloud, and anyone whose backup today is `rsync` to a drive in the same room. And people for whom privacy is not negotiable, whose backups must stay encrypted and outside any single company's reach: journalists, activists, anyone holding sensitive data. And anyone who would rather not pay a monthly backup bill but has spare disk to trade — lend space to the network, get space back.

## Status

Pre-release, and rough. You can run the daemon, back up folders and get them back, but breaking changes are still coming, including the wire protocol. Don't point it at data you can't afford to lose.

If you want to poke at it or help test, you're welcome. Today there's a web UI and a Linux daemon. Windows and macOS builds are work in progress.

### Where the work is (autumn 2026)

**The trust model is being rebuilt.** The first model scored each peer with a single number. A review of its experiments found that one of their inputs, a peer's overall contribution to the network, came from the simulator's ground truth rather than from anything a real node could see. Much of the rest held up, but the model needed to stand on observable inputs only. The new model, called 4R internally, starts from what a node sees first-hand: how much a peer has stored for it and for how long, confirmed by storage proofs. Trust is a slowly fading pairwise memory of that service. It can't be transferred or bought in bulk, so there's nothing to inflate and nothing a Sybil farm can pool. A holder keeps each owner's data in proportion to the service that owner has given it, which stops one large user from filling someone else's disk.

**It went through a new round of simulation.** The simulator now runs adversarial worlds (Sybil farms, collusion rings, eclipse, a large provider leaving, cartels shutting out newcomers) and serves as the reference. Where the design notes and the simulator disagree, the simulator wins until the disagreement is explained.

**The messaging layer was replaced.** Peers exchange service messages through a store-and-forward mailbox kept by other nodes, so a machine that is online a few hours a day still receives its storage challenges, deletion notices and recovery pointers.

**Now: moving 4R into the daemon, and finishing the rest.** The ledger that records service between each pair of peers already runs in the daemon, and the new model runs in shadow next to the old one before it is allowed to make decisions. Alongside that we are getting ready for a first public network. End-to-end tests now prove that a restore really comes from the network rather than from local files. Disaster recovery from the 24-word phrase stops on a typo instead of overwriting anything. The daemon shuts down cleanly and finds its peers again after a restart. A data-loss bug in how small files are packed together has been fixed.

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
./target/release/viaticum daemon --watch-dir ~/Documents

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
- [`docs/archive/experiments/`](docs/archive/experiments/) — 24 numerical experiments behind the first trust model (superseded by 4R, see Status)
- [`simulations/`](simulations/) — Python source for the experiments above (reproducible)

## Maintainers

- **Ilya Cheshkov** — author and lead: protocol design, architecture, core implementation
- **Rostislav Snegirev** — contributor: built the web-based UI, now learning the wider codebase while helping carry the project toward release

## License

[AGPL-3.0-only](LICENSE). The Affero clause matters: if you modify Viaticum and run it as a network service, you must publish the modifications under the same license. This protects the project against being absorbed into closed-source forks.

## Acknowledgments

Implementation used substantial assistance from generative AI (Claude / Claude Code) for boilerplate, test scaffolding, and refactoring. The architecture, protocol design, and final code review are human-authored. Under Anthropic's terms of service, rights in the model's output pass to the user, so these AI-assisted contributions are ours to publish under AGPL-3.0; a human remains accountable for every line and can explain the design decisions behind it. The earlier research and simulation work (`docs/archive/research/`, `docs/archive/experiments/`) used conventional numerical tooling.
