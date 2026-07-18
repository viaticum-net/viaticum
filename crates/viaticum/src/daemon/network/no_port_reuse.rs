// Forces every outgoing libp2p dial to use a fresh ephemeral source port,
// stripping `PortUse::Reuse` requests from the dialing behaviours (Kad,
// Identify, manual `Swarm::dial`, ...). Without this wrapper, rust-libp2p's
// TCP transport binds outgoing sockets to the listener port via SO_REUSEPORT,
// which breaks through several tun-based VPN / transparent-proxy stacks that
// silently drop TCP flows whose source port matches a local listener
// (observed: sing-box + hysteria2). For a cold-backup workload we don't need
// the NAT-traversal benefit of port reuse, so we strip it at the transport
// edge — a single point of enforcement for every dial path.
//
// Wraps any `Transport`; `dial()` overrides `opts.port_use` to `PortUse::New`.
// All other methods delegate verbatim.

use std::pin::Pin;
use std::task::{Context, Poll};

use libp2p::Multiaddr;
use libp2p::core::transport::{
    DialOpts, ListenerId, PortUse, Transport, TransportError, TransportEvent,
};

pub(crate) struct NoPortReuse<T> {
    inner: T,
}

impl<T> NoPortReuse<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: Transport + Unpin> Transport for NoPortReuse<T> {
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.inner.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        mut opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        opts.port_use = PortUse::New;
        self.inner.dial(addr, opts)
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

#[cfg(test)]
mod tests;
