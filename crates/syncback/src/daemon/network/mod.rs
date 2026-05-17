// Network module: libp2p transport layer for SyncBack.
//
// Provides:
//   - SwarmHandle: libp2p swarm with Kademlia DHT, NAT traversal (relay + DCUtR)
//
// See swarm.rs for the full implementation.

pub mod swarm;

// Address format utilities (used by handle/mod.rs for loading stored peer addrs).
pub mod addr;

// Transport wrapper that strips `PortUse::Reuse` from outgoing dials. Used by
// swarm.rs to keep flows compatible with tun-based VPN/proxy stacks (sing-box,
// some hysteria2 setups) that drop TCP whose source port matches a listener.
mod no_port_reuse;

#[cfg(test)]
pub(crate) mod swarm_test_helpers;
#[cfg(test)]
mod swarm_tests;
#[cfg(test)]
mod swarm_kad_tests;
#[cfg(test)]
mod swarm_nat_tests;
#[cfg(test)]
mod tests;
