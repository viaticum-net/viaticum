# Roadmap

Viaticum is a working alpha. This is what runs today and where it is going. No dates: it is built in spare time, and the protocol still has breaking changes ahead.

## What works today

- **Backup and restore** — watch folders, encode, distribute fragments to peers, get files back by path, by version, or by date.
- **Earned trust** — pairwise reputation that grows over weeks of verified Proof-of-Storage. No central score, each peer judges the others.
- **Adaptive redundancy** — the number of fragments is solved against a target recovery probability and the trust of the chosen peers, not a fixed ratio. Reliable peers get fewer copies, shaky ones more.
- **Importance by file type** — documents, media and code are weighted differently; bursts of near-identical shots are detected and down-weighted.
- **Repair** — lost fragments are rebuilt from the source file or refetched from surviving peers, then re-placed.
- **Multi-device identity** — several devices can share one cluster identity and the trust it has accumulated.
- **Storage limits** — cap how much disk you lend the network with soft and hard quotas and a reserve the daemon never crosses; under pressure, other people's data is evicted before your own.
- **Disaster recovery** — rebuild a node from the 24-word seed phrase alone, no old database needed.
- **Web UI and CLI**, NAT traversal (relay + hole punching), and ignore rules for excluding paths.

## Where it is heading

Grouped by what it gives you, not by priority.

### Restore that does not give up

A restore should survive offline peers. A persistent queue that retries as peers come back, and a periodic drill that checks holders actually return data rather than just claim to hold it — a defence against "stored, but pay me to give it back".

### Importance-aware backup

When disk budget runs short, keep the memory rather than lose it: compress photos and video on the fly, then replace them with the originals as budget grows. On-device detection of faces and near-duplicates to rank what matters, with pictures never leaving the machine to be ranked.

### Multi-device clusters

Invite another of your own devices, or a friend, into a cluster without copying the seed phrase. Back a VPS up to a home machine that sits idle anyway. Family and friend circles with a shared view.

### Storage control

Per-peer quotas ("Alice up to 2 TB, Bob up to 500 GB"), several disks used as separate pools (cold HDD, hot SSD), and a lean profile with explicit RAM targets for a Raspberry Pi or a 1 GB VPS.

### Recovery and resilience

Inheritance through secret-sharing: split the seed M-of-N across trusted contacts, hand over access after long inactivity. Local bit-rot detection. Geographic spread of fragments against local disasters.

### Network reach

QUIC alongside TCP for awkward middleboxes, a fully private network mode for a closed group, and pluggable transports such as Tor or mesh over time.

### Research

A formal protocol specification so others can build compatible clients, and formal arguments that the incentives hold — that freeloading does not pay, and that collusion between holders does not either.
