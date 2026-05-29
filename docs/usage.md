# Using Viaticum

What Viaticum can do today and how to drive it. Draft — the commands are stable, the UX around them is still rough.

There are two ways to talk to the daemon: the web UI and the `viaticum` CLI. The UI is the easy path for day-to-day use; the CLI does everything and is the only way to run disaster recovery.

## First run

No prebuilt packages yet — build from source (Rust stable + Node.js); see the README for the build steps.

Create an identity. This writes a 24-word recovery phrase. Write it down and keep it offline: it is the only way back to your data if the machine is lost.

    viaticum init

Start the daemon, then open the UI:

    viaticum daemon
    viaticum open

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

    viaticum daemon --watch-dir ~/Documents

Files are encoded and queued straight away, but they only become safe once peers accept the fragments. So you need at least one peer.

## Connecting with a peer

Backup needs someone to hold your fragments: a friend, or your own second machine.

There is no public network to join yet — the shared relay nodes are not up, so there is no open discovery. For now you build your own small network. Two ways:

- **Your own peers.** libp2p can punch through NAT, but the hole-punch needs a relay to coordinate it, and the shared relays are not up yet. So for now one side needs a directly reachable address — a public IP or a forwarded port — or both peers sit on the same LAN. Trade addresses and connect each side to the other. Once relays are running, two peers behind NAT will connect with none of this.
- **Test network.** Contact the developers for access to the test network if you want to try it without standing up your own.

Your address is on the Dashboard, or:

    viaticum status

Connect to a peer, on the **Connect** screen or the CLI:

    viaticum connect <device_id>@<ip>:<port>

Connected peers start storing fragments for each other and trust accumulates. It is slow by design — proof-of-storage runs weekly.

## Watching what happens

The Dashboard shows it live. From the CLI:

    viaticum status            # peers, trust, storage, reliability by importance
    viaticum files             # everything backed up
    viaticum files Documents   # filter by path prefix
    viaticum versions <path>   # every stored version of one file

## Restoring

On the **Files** screen press Restore, or from the CLI:

    viaticum restore <path>                     # latest version, in place
    viaticum restore <path> --version 2         # a specific version
    viaticum restore <path> --date 2026-01-15   # closest to a date
    viaticum restore <path> --dest /tmp/out     # to a different location

A cold-backup restore can take a while: it waits on peers that may be offline.

## Several of your own devices

Devices can share one identity and the trust it carries. On the new machine, join with the same seed phrase:

    viaticum init --mnemonic "<24 words>" --new-device

Then, on the **Devices** screen or the CLI:

    viaticum device list
    viaticum device add "laptop"
    viaticum device revoke <device_id>     # e.g. after theft

Invite-based join without copying the seed phrase is on the roadmap.

## Driving a daemon on a NAS

Run the daemon on a NAS and drive it from your laptop. On the NAS, print the token:

    viaticum token

Then from anywhere, with the CLI or by opening the UI against that URL:

    viaticum --server http://nas.local:8080 --token <token> status

Or set `VIATICUM_SERVER` and `VIATICUM_TOKEN` in the environment.

## When the machine is gone

Disaster recovery rebuilds a node from the seed phrase alone, no old database needed. On a fresh machine:

    viaticum dr --mnemonic "<24 words>" --peer <device_id>@<ip>:<port>

It discovers peers, finds your latest encrypted state snapshot, and restores the database. Then `viaticum daemon` and `viaticum restore` bring the files back.
