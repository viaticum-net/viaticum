// The Kademlia lookup cadence in a real swarm (C-DK Р-17 v3.3, network-i43):
// our timer runs discovery then bootstrap on every tick; the cadence settles on
// ≥ 20 known peers or 2 quiet discovery rounds, and then the timer slows down.

use std::time::Duration;

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use viaticum_core::types::IdentityPub;

use super::address_book::AddressBook;
use super::swarm::{SwarmConfig, SwarmHandle};
use super::swarm_test_helpers::{
    device_of, get_listen_addr, make_cert, make_signing_key, make_swarm_config, peer_record_with,
    test_cluster_master_pub,
};

const TICK: Duration = Duration::from_millis(200);

/// A device of another master: authenticated on the Cross path, i.e. KNOWN.
fn stranger_config(seed: u8, master_seed: u8) -> SwarmConfig {
    let mut cfg = make_swarm_config(seed);
    let master = make_signing_key(master_seed);
    let identity = IdentityPub(master.verifying_key().to_bytes());
    cfg.device_cert = make_cert(&master, &cfg.device_signing_key);
    cfg.master_signing_key = master;
    cfg.identity_pub = identity;
    cfg.cluster_master_pub = identity;
    cfg
}

/// A swarm with a fast lookup tick, `time_scale`, and `bootstrap` (if any).
fn ticking_config(seed: u8, time_scale: Option<u64>, bootstrap: Option<Multiaddr>) -> SwarmConfig {
    let mut cfg = make_swarm_config(seed);
    cfg.kad_discovery_interval_override = Some(TICK);
    cfg.conn_policy.time_scale = time_scale;
    cfg.kademlia_bootstrap_peers = bootstrap.into_iter().collect();
    cfg
}

/// A stranger S to bootstrap from; returns it and its `/p2p/` address.
async fn stranger_seed(
    seed: u8,
) -> (
    SwarmHandle,
    tokio::sync::mpsc::Receiver<super::swarm::ProtocolEvent>,
    Multiaddr,
) {
    let (s, ev) = SwarmHandle::start(stranger_config(seed, 0x60))
        .await
        .expect("seed");
    let addr = get_listen_addr(&s).await.with(Protocol::P2p(s.peer_id));
    (s, ev, addr)
}

async fn wait_settled(a: &SwarmHandle, within: Duration) -> Option<&'static str> {
    tokio::time::timeout(within, async {
        loop {
            if let (_, Some(r)) = a.test_kad_lookups().await {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .ok()
}

#[tokio::test]
async fn kad_lookup_tick_runs_discovery_then_bootstrap() {
    let (_s, _evs, addr_s) = stranger_seed(230).await;
    let (a, _ev) = SwarmHandle::start(ticking_config(231, None, Some(addr_s)))
        .await
        .expect("A");
    tokio::time::sleep(TICK * 4).await;
    let (log, _) = a.test_kad_lookups().await;
    assert_eq!(
        log.first().map(String::as_str),
        Some("bootstrap:start"),
        "{log:?}"
    );
    let ours: Vec<&str> = log
        .iter()
        .map(String::as_str)
        .filter(|l| *l != "bootstrap:auto")
        .collect();
    let ticks = ours.iter().filter(|l| **l == "discovery").count();
    assert!(ticks >= 2, "{log:?}");
    for (i, l) in ours.iter().enumerate() {
        if *l == "discovery" {
            assert_eq!(
                ours.get(i + 1),
                Some(&"bootstrap:timer"),
                "every tick: discovery, then our bootstrap ({log:?})"
            );
        }
    }
}

/// M19: in a circle of < 20 owners the cadence settles after two quiet rounds.
#[tokio::test]
async fn kad_cadence_settles_after_two_quiet_rounds() {
    let (_s, _evs, addr_s) = stranger_seed(232).await;
    let (a, _ev) = SwarmHandle::start(ticking_config(233, Some(60), Some(addr_s)))
        .await
        .expect("A");
    assert_eq!(
        wait_settled(&a, Duration::from_secs(5)).await,
        Some("quiet")
    );
}

#[tokio::test]
async fn kad_cadence_empty_round_does_not_count() {
    // Nobody to ask: every round is empty.
    let (a, _ev) = SwarmHandle::start(ticking_config(234, Some(60), None))
        .await
        .expect("A");
    tokio::time::sleep(TICK * 8).await;
    let (log, settled) = a.test_kad_lookups().await;
    assert!(
        log.iter().filter(|l| *l == "discovery").count() >= 4,
        "{log:?}"
    );
    assert_eq!(settled, None, "empty rounds never settle");
}

#[tokio::test]
async fn kad_cadence_never_settles_with_policy_off() {
    let (_s, _evs, addr_s) = stranger_seed(235).await;
    let (a, _ev) = SwarmHandle::start(ticking_config(236, None, Some(addr_s)))
        .await
        .expect("A");
    assert_eq!(wait_settled(&a, TICK * 10).await, None);
}

/// After settling, the lookups come at max(30 min / ts, 60 s): at ts = 1200 the
/// 60 s floor — no further tick within seconds (M15: no slowdown).
#[tokio::test]
async fn kad_lookup_timer_uses_own_bootstrap_and_60s_floor_after_settle() {
    let (_s, _evs, addr_s) = stranger_seed(237).await;
    let (a, _ev) = SwarmHandle::start(ticking_config(238, Some(1200), Some(addr_s)))
        .await
        .expect("A");
    assert_eq!(
        wait_settled(&a, Duration::from_secs(5)).await,
        Some("quiet")
    );
    let (log, _) = a.test_kad_lookups().await;
    let before = log.iter().filter(|l| *l == "discovery").count();
    assert!(
        log.iter().any(|l| l == "bootstrap:timer"),
        "our own bootstrap: {log:?}"
    );
    tokio::time::sleep(TICK * 8).await;
    let (log, _) = a.test_kad_lookups().await;
    let after = log.iter().filter(|l| *l == "discovery").count();
    assert!(
        after <= before + 1,
        "at most the tick already scheduled, then 60 s: {before} → {after}"
    );
}

/// Twenty known peers in the address book: settled at start (a restarted node).
fn with_twenty_known(cfg: &mut SwarmConfig, own_seed: u8) -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db = viaticum_core::db::Db::open(&dir.path().join("db.redb")).expect("db");
    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9".parse().unwrap();
    for seed in 1..=20u8 {
        db.upsert_peer(&peer_record_with(
            device_of(seed),
            IdentityPub([0xBB; 32]),
            std::slice::from_ref(&addr),
        ))
        .expect("record");
    }
    cfg.conn_policy.address_book = Some(AddressBook::new(
        db,
        test_cluster_master_pub(),
        device_of(own_seed),
    ));
    dir
}

#[tokio::test]
async fn discovery_interval_settles_after_known_20() {
    let mut cfg = ticking_config(239, Some(1), None);
    let _dir = with_twenty_known(&mut cfg, 239);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let (_, settled) = a.test_kad_lookups().await;
    assert_eq!(settled, Some("known"));
}

/// Settled before the first tick: that tick still runs (its time was set), the
/// next ones come at the slow period.
#[tokio::test]
async fn kad_first_tick_kept_when_settled_before_it() {
    let mut cfg = ticking_config(240, Some(1), None);
    let _dir = with_twenty_known(&mut cfg, 240);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    tokio::time::sleep(TICK * 2).await;
    let (log, _) = a.test_kad_lookups().await;
    assert_eq!(
        log.iter().filter(|l| *l == "discovery").count(),
        1,
        "{log:?}"
    );
    tokio::time::sleep(TICK * 5).await;
    let (log, _) = a.test_kad_lookups().await;
    assert_eq!(
        log.iter().filter(|l| *l == "discovery").count(),
        1,
        "then 30 min: {log:?}"
    );
}
