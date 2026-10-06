// network-i46: a failed lookup re-reads the OS resolver configuration (at most
// once per minute); the next dial resolves with the new one, no restart.
//
// The "OS configuration" is a scripted reader; the nameserver is a fake one on
// 127.0.0.1 that answers every A query with 127.0.0.1, so no test touches the
// real network or the host's resolv.conf.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfigGroup, ResolveHosts};
use hickory_resolver::proto::op::{Message, MessageType, OpCode};
use hickory_resolver::proto::rr::rdata::A;
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use libp2p::Multiaddr;
use libp2p::core::connection::Endpoint;
use libp2p::core::transport::{DialOpts, PortUse, Transport};
use libp2p::dns::{ResolveError, ResolveErrorKind, ResolverConfig, ResolverOpts};

use super::{ReadResolverConf, ReloadingDns, RereadGate, ResolverConf};

const SEED_NAME: &str = "seed.viaticum.test";

/// A nameserver on 127.0.0.1 answering every A query with 127.0.0.1.
async fn spawn_fake_nameserver() -> SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the fake nameserver");
    let addr = sock.local_addr().expect("nameserver addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let mut resp = Message::new();
            resp.set_id(query.id())
                .set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query)
                .set_recursion_desired(true)
                .set_recursion_available(true);
            for q in query.queries() {
                resp.add_query(q.clone());
                if q.query_type() == RecordType::A {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A(Ipv4Addr::LOCALHOST)),
                    ));
                }
            }
            if let Ok(bytes) = resp.to_vec() {
                let _ = sock.send_to(&bytes, from).await;
            }
        }
    });
    addr
}

/// The configuration a node reads once the network is up: the fake nameserver.
fn valid_conf(nameserver: SocketAddr) -> ResolverConf {
    let cfg = ResolverConfig::from_parts(
        None,
        vec![],
        NameServerConfigGroup::from_ips_clear(&[nameserver.ip()], nameserver.port(), true),
    );
    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = ResolveHosts::Never;
    opts.attempts = 1;
    opts.timeout = Duration::from_secs(2);
    (cfg, opts)
}

fn no_nameserver() -> ResolveError {
    ResolveErrorKind::Message("no nameservers found in config").into()
}

/// A reader that is unreadable until `up` is set, then returns `valid_conf`;
/// `reads` counts the calls.
fn scripted_reader(
    nameserver: SocketAddr,
    up: Arc<AtomicBool>,
    reads: Arc<AtomicUsize>,
) -> ReadResolverConf {
    Box::new(move || {
        reads.fetch_add(1, Ordering::SeqCst);
        if up.load(Ordering::SeqCst) {
            Ok(valid_conf(nameserver))
        } else {
            Err(no_nameserver())
        }
    })
}

fn dial_opts() -> DialOpts {
    DialOpts {
        role: Endpoint::Dialer,
        port_use: PortUse::New,
    }
}

fn tcp() -> libp2p::tcp::tokio::Transport {
    libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default())
}

/// Dial `/dns4/<SEED_NAME>/tcp/<port>`: true when the TCP connection opened.
async fn dial_seed(transport: &mut ReloadingDns<libp2p::tcp::tokio::Transport>, port: u16) -> bool {
    let addr: Multiaddr = format!("/dns4/{SEED_NAME}/tcp/{port}")
        .parse()
        .expect("a DNS multiaddr");
    let dial = transport.dial(addr, dial_opts()).expect("dial accepted");
    let out = tokio::time::timeout(Duration::from_secs(10), dial)
        .await
        .expect("the dial ends within 10 s");
    out.is_ok()
}

/// A TCP listener for the seed to "be"; the kernel completes the handshake.
async fn seed_listener() -> (tokio::net::TcpListener, u16) {
    let l = tokio::net::TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind the seed listener");
    let port = l.local_addr().expect("seed addr").port();
    (l, port)
}

// ── the gate, on model time ────────────────────────────────────────────────

#[test]
fn reread_gate_without_failed_lookup_never_rereads() {
    let t0 = Instant::now();
    let mut gate = RereadGate::new(t0, Duration::from_secs(60));
    assert!(!gate.take_due(t0 + Duration::from_secs(600)));
}

// Mutation: drop the `min_interval` check in `take_due` → the 30 s step
// re-reads, red.
#[test]
fn reread_gate_after_failed_lookup_rereads_once_per_minute() {
    let t0 = Instant::now();
    let mut gate = RereadGate::new(t0, Duration::from_secs(60));
    let failed = gate.failure_flag();

    failed.store(true, Ordering::Relaxed);
    assert!(
        !gate.take_due(t0 + Duration::from_secs(30)),
        "30 s after the start's read: too early"
    );
    assert!(
        gate.take_due(t0 + Duration::from_secs(60)),
        "a minute after the start's read: re-read"
    );
    assert!(
        !gate.take_due(t0 + Duration::from_secs(61)),
        "the re-read cleared the failure"
    );

    failed.store(true, Ordering::Relaxed);
    assert!(
        !gate.take_due(t0 + Duration::from_secs(100)),
        "40 s after the last re-read: too early"
    );
    assert!(
        gate.take_due(t0 + Duration::from_secs(120)),
        "a minute after the last re-read: re-read"
    );
}

// ── the transport ──────────────────────────────────────────────────────────

// network-i46 check. Mutation: drop `self.reread()` from `dial` (or the
// failure flag in the dial future) → the third dial still has no nameserver,
// red.
#[tokio::test]
async fn dns_name_with_no_nameserver_at_start_resolves_after_config_becomes_valid() {
    let nameserver = spawn_fake_nameserver().await;
    let (_seed, port) = seed_listener().await;
    let up = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let mut transport = ReloadingDns::with_reader(
        tcp(),
        scripted_reader(nameserver, Arc::clone(&up), Arc::clone(&reads)),
        Duration::ZERO,
    );

    assert!(
        !dial_seed(&mut transport, port).await,
        "no nameserver at the start: the name must not resolve"
    );
    // A failed lookup with the configuration still unreadable keeps failing.
    assert!(!dial_seed(&mut transport, port).await);

    // DHCP came: the OS configuration now has a nameserver.
    up.store(true, Ordering::SeqCst);
    assert!(
        dial_seed(&mut transport, port).await,
        "the dial after a failed lookup re-reads the configuration and resolves"
    );
    assert_eq!(reads.load(Ordering::SeqCst), 3, "start + two re-reads");
}

// Mutation: set the failure flag on every dial outcome → the second dial
// re-reads, red.
#[tokio::test]
async fn dns_name_resolved_rereads_nothing() {
    let nameserver = spawn_fake_nameserver().await;
    let (_seed, port) = seed_listener().await;
    let reads = Arc::new(AtomicUsize::new(0));
    let mut transport = ReloadingDns::with_reader(
        tcp(),
        scripted_reader(
            nameserver,
            Arc::new(AtomicBool::new(true)),
            Arc::clone(&reads),
        ),
        Duration::ZERO,
    );

    assert!(dial_seed(&mut transport, port).await);
    assert!(dial_seed(&mut transport, port).await);
    assert_eq!(reads.load(Ordering::SeqCst), 1, "only the start's read");
}

// The transport honours the gate: with the production interval, failed
// lookups in quick succession re-read nothing within the minute.
#[tokio::test]
async fn dns_name_failing_twice_within_a_minute_rereads_nothing() {
    let nameserver = spawn_fake_nameserver().await;
    let (_seed, port) = seed_listener().await;
    let reads = Arc::new(AtomicUsize::new(0));
    let mut transport = ReloadingDns::with_reader(
        tcp(),
        scripted_reader(
            nameserver,
            Arc::new(AtomicBool::new(false)),
            Arc::clone(&reads),
        ),
        super::RESOLVER_REREAD_MIN_INTERVAL,
    );

    assert!(!dial_seed(&mut transport, port).await);
    assert!(!dial_seed(&mut transport, port).await);
    assert!(!dial_seed(&mut transport, port).await);
    assert_eq!(reads.load(Ordering::SeqCst), 1, "only the start's read");
}
