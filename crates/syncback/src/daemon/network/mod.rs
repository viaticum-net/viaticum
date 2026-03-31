// Network module: libp2p transport layer for SyncBack.
//
// Provides:
//   - SwarmHandle: libp2p swarm with Kademlia DHT, NAT traversal (relay + DCUtR)
//
// See swarm.rs for the full implementation.

pub mod swarm;

// Address format utilities (used by handle/mod.rs for loading stored peer addrs).
pub mod addr;

#[cfg(test)]
pub(crate) mod swarm_test_helpers;
#[cfg(test)]
mod swarm_tests;
#[cfg(test)]
mod swarm_kad_tests;
#[cfg(test)]
mod swarm_nat_tests;
