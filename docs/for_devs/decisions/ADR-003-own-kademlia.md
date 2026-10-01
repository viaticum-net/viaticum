# ADR-003 — Our own Kademlia DHT from day one, no IPFS

**Status:** Accepted (2026-10-01)

## Context

Viaticum finds peers over Kademlia (libp2p-kad). The ε.3 design started on the
shared IPFS DHT (`/ipfs/kad/1.0.0`): 200K+ nodes and public bootstrap nodes out of
the box, Viaticum nodes finding each other through a provider record
(`/viaticum/peers/v1`), and a planned switch to an own namespace "at ~100+ nodes".
The IPFS bootstrap list sat in the code behind a config switch
(`kademlia_disable_ipfs_bootstrap`, off by default since network-i11).

Running 40 nodes on one host (slice C-DK) showed what sharing the protocol name
costs, even with the switch off on 39 of them:

- **Strangers in our table.** Our Kademlia and IPFS's had the same name, so any
  IPFS node that connected to ours was accepted as a Kademlia peer: identify fed its
  addresses into the table, and an unconfirmed protocol only marks a peer, never
  removes it. One node with the switch on was enough: its IPFS records spread to
  the others through ordinary FIND_NODE answers, and once discovery worked at all,
  nearly every node dialed public IPFS infrastructure. A friend's NAS should not
  contact strangers on the internet because one friend in the circle flipped a
  switch.
- **Privacy.** On the shared DHT our PeerIds, addresses and lookups are visible to
  anyone crawling IPFS, which is the largest public DHT and is crawled routinely.
  The provider record named the whole set of Viaticum nodes under one key.
- **Answer size.** A provider record carries the provider's addresses, and in an
  open network anyone may store one with us. With the closer peers on top, a
  GET_PROVIDERS answer could outgrow the 16 KiB Kademlia frame, and an answer the
  asker cannot decode silences discovery — the failure C-DK measured for FIND_NODE
  (H1, 24–45 KB answers).

There is no deployed network yet, so nothing has to stay compatible with the
shared DHT.

## Decision

Run our own DHT from the first day of the network:

- Kademlia protocol `/viaticum/kad/1.0.0`. Identify feeds Kademlia only from peers
  that announce it. A node of another Kademlia cannot query us, is not answered, and
  never enters our routing table (network-i17).
- No built-in bootstrap nodes. The IPFS list and the
  `kademlia_disable_ipfs_bootstrap` switch are removed. A config that still carries
  the key loads and ignores it, like any unknown key.
- No provider namespace. Discovery is FIND_NODE only: a Kademlia bootstrap plus a
  periodic lookup of our own id. Incoming PUT_VALUE / ADD_PROVIDER are not stored, so
  every answer fits the default frame (network-i18, i20).

The network stays **open**: any Viaticum node that reaches a member can join
(network-i13). The own name keeps us apart from IPFS; it is not access control.

Rejected alternatives:

- **Keep the shared DHT until ~100 nodes.** All three costs above apply from the
  first node, and a later switch would split the network.
- **Keep the IPFS list behind a flag** ("for custom infrastructure on the IPFS DHT").
  A flag one friend can flip exposes the whole circle (see Context), and with a
  shared protocol name IPFS nodes get in through identify whatever the flag says.

## Consequences

- **A circle needs a seed.** A node with no `kademlia_bootstrap_peers` finds nobody:
  there are no public bootstrap nodes to fall back on. Somebody in the circle runs
  an always-on node with a fixed address and gives that address to the others. A
  circle whose only seed is lost cannot let new nodes in until another address is
  configured. DNS seeds and a lost seed are later work.
- No dial to public IPFS infrastructure from any configuration. The E2E checks this
  on every daemon: no TCP socket in any state to a non-local address.
- Our lookups return only Viaticum nodes, so discovery and DR spend no dials on
  foreign peers.
- Malicious nodes that speak our protocol are a separate problem: authenticating
  Kademlia peers (only cert-verified peers in the table) is deferred to the
  allowlist work.
