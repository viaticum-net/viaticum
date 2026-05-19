use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::{Pending, pending};
use libp2p::Multiaddr;
use libp2p::core::connection::Endpoint;
use libp2p::core::transport::{
    DialOpts, ListenerId, PortUse, Transport, TransportError, TransportEvent,
};

use super::NoPortReuse;

/// Records every `port_use` value dial() saw, so the test can assert the
/// outer wrapper masks `PortUse::Reuse` requests.
#[derive(Default)]
struct CaptureTransport {
    seen_port_use: Vec<PortUse>,
}

impl Transport for CaptureTransport {
    type Output = ();
    type Error = std::io::Error;
    type ListenerUpgrade = Pending<Result<(), std::io::Error>>;
    type Dial = Pending<Result<(), std::io::Error>>;

    fn listen_on(
        &mut self,
        _id: ListenerId,
        _addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        Ok(())
    }

    fn remove_listener(&mut self, _id: ListenerId) -> bool {
        false
    }

    fn dial(
        &mut self,
        _addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.seen_port_use.push(opts.port_use);
        Ok(pending())
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Poll::Pending
    }
}

fn dial_opts(port_use: PortUse) -> DialOpts {
    DialOpts {
        role: Endpoint::Dialer,
        port_use,
    }
}

#[test]
fn dial_with_reuse_is_rewritten_to_new() {
    let mut wrapped = NoPortReuse::new(CaptureTransport::default());
    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();

    let _ = wrapped.dial(addr, dial_opts(PortUse::Reuse));

    assert_eq!(wrapped.inner.seen_port_use, vec![PortUse::New]);
}

#[test]
fn dial_with_new_is_passed_through() {
    let mut wrapped = NoPortReuse::new(CaptureTransport::default());
    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();

    let _ = wrapped.dial(addr, dial_opts(PortUse::New));

    assert_eq!(wrapped.inner.seen_port_use, vec![PortUse::New]);
}

#[test]
fn multiple_dials_all_get_new() {
    let mut wrapped = NoPortReuse::new(CaptureTransport::default());
    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();

    for use_in in [PortUse::Reuse, PortUse::New, PortUse::Reuse, PortUse::Reuse] {
        let _ = wrapped.dial(addr.clone(), dial_opts(use_in));
    }

    assert_eq!(
        wrapped.inner.seen_port_use,
        vec![PortUse::New, PortUse::New, PortUse::New, PortUse::New]
    );
}
