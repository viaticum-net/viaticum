// The DNS layer of the swarm's transport: libp2p-dns, plus a re-read of the OS
// resolver configuration after a failed lookup (network-i46).
//
// libp2p-dns reads `resolv.conf` (Windows: the adapters) once, when the
// transport is built, and offers no way to swap its resolver. A node that
// started before DHCP (no nameserver yet) or moved to another network would
// then fail every `/dns*` dial until a restart. Here, a failed lookup marks
// the configuration stale; the next dial — at most once per
// `RESOLVER_REREAD_MIN_INTERVAL` — re-reads it and rebuilds the libp2p-dns
// layer over the SAME inner transport, so listeners and dials in flight
// survive. A successful lookup re-reads nothing.
//
// The inner transport is shared (`SharedTransport`) because libp2p-dns takes
// it by value: each rebuild hands it a new handle to the one inner transport.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::future::{BoxFuture, FutureExt as _, TryFutureExt as _};
use libp2p::Multiaddr;
use libp2p::core::transport::{DialOpts, ListenerId, Transport, TransportError, TransportEvent};
use libp2p::dns::{ResolveError, ResolverConfig, ResolverOpts};
use tracing::{debug, error, info, warn};

/// At most one re-read of the OS resolver configuration per minute
/// (network-i46): a node with no network fails a lookup on every dial.
pub(super) const RESOLVER_REREAD_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// The OS resolver configuration, as `hickory_resolver::system_conf` reads it.
pub(super) type ResolverConf = (ResolverConfig, ResolverOpts);

/// Reads the resolver configuration: the OS one in production, a scripted one
/// in tests.
pub(super) type ReadResolverConf = Box<dyn Fn() -> Result<ResolverConf, ResolveError> + Send>;

/// When the resolver configuration is re-read: only after a lookup failed,
/// and not sooner than `min_interval` after the previous read (the start's
/// read counts).
pub(super) struct RereadGate {
    last_read: Instant,
    min_interval: Duration,
    /// Set by a dial future whose lookup failed; cleared by the re-read.
    lookup_failed: Arc<AtomicBool>,
}

impl RereadGate {
    pub(super) fn new(read_at: Instant, min_interval: Duration) -> Self {
        Self {
            last_read: read_at,
            min_interval,
            lookup_failed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The flag a dial future sets when its lookup fails.
    pub(super) fn failure_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.lookup_failed)
    }

    /// True when the configuration must be re-read at `now`; the caller then
    /// re-reads, and the gate counts it as the latest read.
    pub(super) fn take_due(&mut self, now: Instant) -> bool {
        if !self.lookup_failed.load(Ordering::Relaxed) {
            return false;
        }
        if now.saturating_duration_since(self.last_read) < self.min_interval {
            return false;
        }
        self.lookup_failed.store(false, Ordering::Relaxed);
        self.last_read = now;
        true
    }
}

/// libp2p-dns over `T`, rebuilt with a freshly read OS resolver configuration
/// after a failed lookup (see the module comment).
pub(super) struct ReloadingDns<T> {
    inner: Arc<Mutex<T>>,
    dns: libp2p::dns::tokio::Transport<SharedTransport<T>>,
    read_conf: ReadResolverConf,
    gate: RereadGate,
    /// Outcome of the last re-read (`true` = readable); a repeat of the same
    /// outcome logs at DEBUG only, so an offline node does not log every minute.
    last_reread_ok: Option<bool>,
}

impl<T: Send> ReloadingDns<T> {
    /// The production transport: the OS configuration, re-read at most once
    /// per `RESOLVER_REREAD_MIN_INTERVAL`.
    pub(super) fn system(inner: T) -> Self {
        Self::with_reader(
            inner,
            Box::new(hickory_resolver::system_conf::read_system_conf),
            RESOLVER_REREAD_MIN_INTERVAL,
        )
    }

    /// Unreadable at the start — an offline box with no nameserver — the node
    /// still starts: IP addresses work, a DNS name fails its dial and so
    /// triggers the re-read.
    pub(super) fn with_reader(
        inner: T,
        read_conf: ReadResolverConf,
        min_interval: Duration,
    ) -> Self {
        let (cfg, opts) = match read_conf() {
            Ok(conf) => conf,
            Err(e) => {
                error!(
                    error = %e,
                    "DNS: the system resolver configuration is unreadable; \
                     seeds named by DNS will not resolve until it is"
                );
                (ResolverConfig::new(), ResolverOpts::default())
            }
        };
        let inner = Arc::new(Mutex::new(inner));
        let dns =
            libp2p::dns::tokio::Transport::custom(SharedTransport(Arc::clone(&inner)), cfg, opts);
        Self {
            inner,
            dns,
            read_conf,
            gate: RereadGate::new(Instant::now(), min_interval),
            last_reread_ok: None,
        }
    }

    /// Re-read the configuration and rebuild the DNS layer over the same
    /// inner transport. Still unreadable → keep the current resolver.
    fn reread(&mut self) {
        match (self.read_conf)() {
            Ok((cfg, opts)) => {
                self.dns = libp2p::dns::tokio::Transport::custom(
                    SharedTransport(Arc::clone(&self.inner)),
                    cfg,
                    opts,
                );
                if self.last_reread_ok == Some(true) {
                    debug!("DNS: re-read the system resolver configuration after a failed lookup");
                } else {
                    info!("DNS: re-read the system resolver configuration after a failed lookup");
                }
                self.last_reread_ok = Some(true);
            }
            Err(e) => {
                if self.last_reread_ok == Some(false) {
                    debug!(error = %e, "DNS: the system resolver configuration is still unreadable");
                } else {
                    warn!(
                        error = %e,
                        "DNS: a lookup failed and the system resolver configuration is still unreadable"
                    );
                }
                self.last_reread_ok = Some(false);
            }
        }
    }
}

/// A lookup failed somewhere in this dial (libp2p-dns reports a failed
/// lookup as `Dial([ResolveError])`).
fn is_lookup_failure<E>(e: &libp2p::dns::Error<E>) -> bool {
    match e {
        libp2p::dns::Error::ResolveError(_) => true,
        libp2p::dns::Error::Dial(errs) => errs.iter().any(is_lookup_failure),
        _ => false,
    }
}

impl<T> Transport for ReloadingDns<T>
where
    T: Transport + Send + Unpin + 'static,
    T::Error: Send + 'static,
    T::Dial: Send + 'static,
    T::Output: 'static,
{
    type Output = T::Output;
    type Error = libp2p::dns::Error<T::Error>;
    type ListenerUpgrade =
        <libp2p::dns::tokio::Transport<SharedTransport<T>> as Transport>::ListenerUpgrade;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.dns.listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.dns.remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        if self.gate.take_due(Instant::now()) {
            self.reread();
        }
        let failed = self.gate.failure_flag();
        let dial = self.dns.dial(addr, opts)?;
        Ok(dial
            .inspect_err(move |e| {
                if is_lookup_failure(e) {
                    failed.store(true, Ordering::Relaxed);
                }
            })
            .boxed())
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.dns).poll(cx)
    }
}

/// One inner transport behind every rebuilt libp2p-dns layer.
pub(super) struct SharedTransport<T>(Arc<Mutex<T>>);

impl<T: Transport + Unpin> Transport for SharedTransport<T> {
    type Output = T::Output;
    type Error = T::Error;
    type ListenerUpgrade = T::ListenerUpgrade;
    type Dial = T::Dial;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .listen_on(id, addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove_listener(id)
    }

    fn dial(
        &mut self,
        addr: Multiaddr,
        opts: DialOpts,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .dial(addr, opts)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let mut inner = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        Pin::new(&mut *inner).poll(cx)
    }
}

#[cfg(test)]
mod tests;
