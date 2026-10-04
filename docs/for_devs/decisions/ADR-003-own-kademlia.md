# ADR-003 — Our own Kademlia DHT from day one, no IPFS

**Status:** Accepted (2026-10-01)

## Context

Viaticum finds peers over Kademlia (libp2p-kad). The ε.3 design started on the
shared IPFS DHT (`/ipfs/kad/1.0.0`): 200K+ nodes and public bootstrap nodes out of
the box, Viaticum nodes finding each other through a provider record
(`/viaticum/peers/v1`), and a planned switch to an own namespace "at ~100+ nodes".
The IPFS bootstrap list sat in the code behind a config switch,
`kademlia_disable_ipfs_bootstrap`: it defaulted to `true`, so by default a node
did not contact the IPFS bootstrap nodes, and a user could set it to `false` to
turn them on.

A 40-node test network on one host showed what sharing the protocol name costs,
even with the IPFS bootstrap off on 39 of the nodes:

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
  asker cannot decode silences discovery. The same test network measured exactly
  this failure on FIND_NODE answers (24–45 KB answers from peers with many
  addresses).

There is no deployed network yet, so nothing has to stay compatible with the
shared DHT.

## Decision

Run our own DHT from the first day of the network:

- Kademlia protocol `/viaticum/kad/1.0.0`. Identify feeds Kademlia only from peers
  that announce it, and a peer whose identify does not announce it is removed from
  the routing table. A node of another Kademlia cannot query us, is not answered,
  and is never handed to other peers by our answers.
- The one boundary: a foreign address a user puts into `kademlia_bootstrap_peers`
  gets one dial at start and is dropped from the routing table after identify; it
  is never handed to other peers.
- No built-in bootstrap nodes. The IPFS list and the
  `kademlia_disable_ipfs_bootstrap` switch are removed. A config that still carries
  the key loads and ignores it, like any unknown key.
- No provider namespace. Discovery is FIND_NODE only: a Kademlia bootstrap plus a
  periodic lookup of our own id. Incoming PUT_VALUE / ADD_PROVIDER are not stored,
  and the addresses kept per peer are capped, so every answer is bounded and fits
  the default 16 KiB frame with margin.

The network stays **open**: any Viaticum node that reaches a member can join. The
own name keeps us apart from IPFS; it is not access control.

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
- No dial to public IPFS infrastructure unless a user writes such an address into
  `kademlia_bootstrap_peers` — and then only that node's own start-up dial. The
  end-to-end test checks every daemon: no TCP socket in any state to a non-local
  address.
- Our lookups return only Viaticum nodes, so discovery and disaster recovery spend
  no dials on foreign peers.
