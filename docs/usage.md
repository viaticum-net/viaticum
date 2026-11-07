# Using Viaticum

What Viaticum can do today and how to drive it. Draft: the commands are stable, the UX around them is still rough. What the alpha does and does not promise is in [What Viaticum promises today](promises.md).

There are two ways to talk to the daemon: the web UI and the `viaticum` CLI. The UI is the easy path for day-to-day use; the CLI does everything and is the only way to run disaster recovery.

## First run

No installer or release yet: build from source (Rust stable and Node.js), as the README shows. Then one command walks you through the rest:

```sh
viaticum setup
```

It asks whether this is a new installation or a restore, which folders to keep safe, and how much space to give friends. It then shows your 24 recovery words in the terminal. Write them on paper, in order, and keep the paper safe: they are the only way back to your data if the machine is lost. `setup` asks for three of the words before it finishes.

Start the daemon and open the UI:

```sh
viaticum daemon
viaticum open
```

`viaticum open` prints the Dashboard address even without a screen, with an `ssh -L` line to reach it from another machine.

### Your 24 words

```sh
viaticum phrase show     # print them again, in a terminal only
viaticum phrase check    # answer three random positions from your paper
```

The words are also stored in the node's `identity.key`, readable only by you, so anyone who can read your files can read the phrase. `phrase show` refuses to print when its output is not a terminal. A successful `phrase check` is remembered; `setup` does that check for you.

## The web UI

`viaticum open` launches the browser on a local, token-authenticated page. Six screens:

- **Dashboard** — node identity and address, storage in and out, backup progress, proof-of-storage pass rate, top peers by trust, and a backup-by-importance breakdown. The health of your node at a glance.
- **Folders** — add, edit, or stop watching backup folders, live, without restarting the daemon. The main way to choose what gets backed up.
- **Files** — everything in the backup catalog, with a filter box and a Restore button per file.
- **Connect** — add a peer by their address.
- **Devices** — the devices sharing your cluster identity; add or revoke.
- **Settings** — daemon configuration: storage quotas, network, and so on.

## Backing up

Pick folders on the **Folders** screen, or start the daemon with a folder already attached:

```sh
viaticum daemon --watch-dir ~/Documents
```

Folders added in the UI take effect without a restart. Files are encoded and queued straight away, but they only become safe once peers accept the fragments. So you need at least one peer.

## Connecting with a peer

Backup needs someone to hold your fragments: a friend, or your own second machine.

Your node finds the network through seeds: the `kademlia_bootstrap_peers` list in `config.toml`, written by `viaticum setup`. A seed introduces you to other nodes; it does not hold your files.

To back up with a friend, trade node addresses (`viaticum status` prints yours) and connect each side to the other. A node address is a libp2p multiaddr, for example `/ip4/192.168.1.20/tcp/4500/p2p/12D3KooW...`:

```sh
viaticum connect <multiaddr>
```

Connected peers start storing fragments for each other and trust accumulates. It is slow by design: proof-of-storage runs weekly.

Two peers behind NAT need a relay to coordinate hole punching. Without one, a side needs a directly reachable address (a public IP or a forwarded port), or both peers sit on the same LAN. Once relays are running, two peers behind NAT will connect with none of this.

## Watching what happens

The Dashboard shows it live. From the CLI:

```sh
viaticum status            # peers, trust, storage, reliability by importance
viaticum files             # everything backed up
viaticum files Documents   # filter by path prefix
viaticum versions <path>   # every stored version of one file
```

## Restoring

On the **Files** screen press Restore, or from the CLI:

```sh
viaticum restore <path>                     # latest version, into staging
viaticum restore <path> --version 2         # a specific version
viaticum restore <path> --date 2026-01-15   # latest version backed up before midnight UTC of that date
```

Restore never overwrites your files. Everything lands in the staging directory inside the data directory: `restore/`, by default `~/.local/share/viaticum/restore/` on Linux, one directory per job. Move the files out yourself. A restore is a job in the daemon; `--status` lists recent jobs and `--no-wait` submits one and returns.

The network keeps the current state of your folders, not a long history. Earlier versions and deleted files stay restorable for about four weeks, then leave. Moving a file to the trash counts as deleting it.

A cold-backup restore can take days: it waits on peers that may be offline. Retry if it stops.

## Several of your own devices

Devices can share one identity and the trust it carries. On the new machine, join with the same seed phrase:

```sh
viaticum init --mnemonic --new-device
```

With no value after `--mnemonic`, the command asks for the 24 words on stdin, so they do not land in the shell history.

Then, on the **Devices** screen or the CLI:

```sh
viaticum device list
viaticum device add laptop
viaticum device revoke <device-id>     # e.g. after theft
```

Invite-based join without copying the seed phrase is on the roadmap.

## Driving a daemon on a NAS

Run the daemon on a NAS and drive it from your laptop. On the NAS, print the token:

```sh
viaticum token
```

Then from anywhere, with the CLI or by opening the UI against that URL:

```sh
viaticum --server http://nas.local:8080 --token <token> status
```

Or set `VIATICUM_SERVER` and `VIATICUM_TOKEN` in the environment.

## When the machine is gone

Disaster recovery rebuilds a node from the 24 words alone, no old database needed. On a fresh machine, run the same first command:

```sh
viaticum setup
```

Choose `Restore from my 24 words` and type the words. `setup` runs disaster recovery before creating any identity, then asks which folders to watch and how much space to give. The catalog comes back from the network; the files themselves come next:

```sh
viaticum daemon
viaticum restore <folder>/
```

Files land in staging, as with any restore. `viaticum status` shows how many are still missing locally until you move the restored copies back to their original paths.

Disaster recovery can also run without `setup`:

```sh
viaticum dr --peer /ip4/<address>/tcp/<port>/p2p/<peer-id>
```

`--mnemonic` with no value makes `dr` ask for the words. `--peer` is a friend's node address as `viaticum status` shows it. It discovers peers, finds your latest encrypted state snapshot, and restores the database.

DR is safe to repeat: a mistyped phrase, a folder that belongs to another identity, a running node's folder, a network failure or Ctrl-C all stop it without changing anything. A successful DR into a folder that already had a database keeps the old one as `db.redb.dr-bak` (then `.dr-bak.1`, …). If the network holds more than one catalog for your phrase (for example a node you once started with `init --mnemonic`), DR lists them with their file counts and asks you to pick one with `--catalog <prefix>`.
