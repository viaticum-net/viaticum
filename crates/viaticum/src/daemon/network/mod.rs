// Network module: libp2p transport layer for Viaticum.
//
// Provides:
//   - SwarmHandle: libp2p swarm with Kademlia DHT, NAT traversal (relay + DCUtR)
//
// See swarm.rs for the full implementation.

pub mod swarm;

// Address format utilities (used by handle/mod.rs for loading stored peer addrs).
pub mod addr;

// PeerRecord address book: known peers and their dialable addresses (network-i14).
pub mod address_book;

// The connection cache: at most `cap` idle peers, the single owner of voluntary
// closes (C-DK Р-11, network-i41).
pub(crate) mod conn_lru;

// When the Kademlia lookups run and when they slow down (C-DK Р-17, network-i43).
mod kad_cadence;

// What identify feeds into a peer's Kademlia record: filtered, ranked, capped
// (C-DK Р-3, network-i18).
mod kad_feed;

// `send_to_device` to a known peer without a connection: waiters, the dial
// queue and the negative cache (C-DK Р-12, network-i42).
mod on_demand;

// Kademlia lookup statistics and the "lookup found no peers" warning (C-DK Р-7).
mod kad_stats;

// Test-only size amplifier of peer records (C-DK Р-10). Never in a user build.
#[cfg(feature = "e2e-tools")]
mod e2e_amp;

// Transport wrapper that strips `PortUse::Reuse` from outgoing dials. Used by
// swarm.rs to keep flows compatible with tun-based VPN/proxy stacks (sing-box,
// some hysteria2 setups) that drop TCP whose source port matches a listener.
mod no_port_reuse;

#[cfg(test)]
mod swarm_addr_tests;
#[cfg(test)]
mod swarm_conn_tests;
#[cfg(test)]
mod swarm_discovery_tests;
#[cfg(all(test, feature = "e2e-tools"))]
mod swarm_e2e_tests;
#[cfg(test)]
mod swarm_kad_cadence_tests;
#[cfg(test)]
mod swarm_kad_foreign_tests;
#[cfg(test)]
mod swarm_kad_frame_tests;
#[cfg(test)]
mod swarm_kad_tests;
#[cfg(test)]
mod swarm_lru_tests;
#[cfg(test)]
mod swarm_nat_tests;
#[cfg(test)]
mod swarm_on_demand_tests;
#[cfg(test)]
mod swarm_port_tests;
#[cfg(test)]
pub(crate) mod swarm_test_helpers;
#[cfg(test)]
mod swarm_tests;
#[cfg(test)]
mod tests;
