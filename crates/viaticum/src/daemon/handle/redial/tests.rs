// Tests for the auto-dial pass (network-i2): real redb on a tmpfile, real
// libp2p swarms on loopback (same harness as network/swarm_tests.rs).

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use tempfile::TempDir;
use viaticum_core::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, PeerRecord, Timestamp};

use super::{
    Candidate, RedialState, RedialStats, plan_redial, redial_devices, redial_floor,
    redial_known_peers,
};
use crate::daemon::network::swarm::{SwarmHandle, device_id_to_peer_id};
use crate::daemon::network::swarm_test_helpers::{
    get_listen_addr, make_swarm_config, wait_for_authenticated,
};

fn peer_record(device_id: DeviceId, addrs: Vec<String>) -> PeerRecord {
    let now = Timestamp::now();
    PeerRecord {
        device_id,
        master_identity: viaticum_core::types::IdentityPub(device_id.0),
        trust_p: INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs,
        x25519_pub: None,
        avail_ewma: AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

fn tmp_db() -> (TempDir, Db) {
    let dir = TempDir::new().expect("tempdir");
    let db = Db::open(&dir.path().join("db.redb")).expect("db open");
    (dir, db)
}

/// The failure of 09-26: identify stores listen addrs WITHOUT `/p2p/`, and the
/// old redial derived the PeerId only from that suffix, so it dialed nobody.
/// Now the PeerId comes from device_id and the peer is reached and authenticated.
#[tokio::test]
async fn redial_dials_peer_whose_addrs_lack_p2p_suffix() {
    let (_dir, db) = tmp_db();
    let (handle_a, mut events_a) = SwarmHandle::start(make_swarm_config(71))
        .await
        .expect("swarm A");
    let (handle_b, _events_b) = SwarmHandle::start(make_swarm_config(72))
        .await
        .expect("swarm B");
    let addr_b = get_listen_addr(&handle_b).await;
    assert!(
        !addr_b.iter().any(|p| matches!(p, Protocol::P2p(_))),
        "precondition: stored address has no /p2p/ suffix: {addr_b}"
    );
    db.upsert_peer(&peer_record(handle_b.device_id, vec![addr_b.to_string()]))
        .unwrap();

    let stats = redial_known_peers(&db, &handle_a, &mut RedialState::default())
        .await
        .expect("pass");
    assert_eq!(
        stats,
        RedialStats {
            known_peers: 1,
            already_connected: 0,
            dialed: 1,
            no_addrs: 0,
            skipped_addrs: 0,
            ..RedialStats::default()
        }
    );
    // The dial really reaches B: A authenticates it (on another swarm, not by counter).
    wait_for_authenticated(&mut events_a, handle_b.device_id).await;

    // Next pass sees it connected and does not dial again.
    let stats = redial_known_peers(&db, &handle_a, &mut RedialState::default())
        .await
        .expect("pass 2");
    assert_eq!(stats.already_connected, 1);
    assert_eq!(stats.dialed, 0);
}

/// A stored address whose `/p2p/` names another peer is not a route to this
/// peer: skipped, never dialed under the record's id (I3).
#[tokio::test]
async fn redial_skips_addr_with_foreign_p2p_suffix() {
    let (_dir, db) = tmp_db();
    let (handle_a, _events_a) = SwarmHandle::start(make_swarm_config(73))
        .await
        .expect("swarm A");
    let (handle_b, _events_b) = SwarmHandle::start(make_swarm_config(74))
        .await
        .expect("swarm B");
    let addr_b = get_listen_addr(&handle_b).await;
    let stranger = DeviceId(
        make_swarm_config(75)
            .device_signing_key
            .verifying_key()
            .to_bytes(),
    );
    let foreign: Multiaddr = addr_b
        .clone()
        .with(Protocol::P2p(device_id_to_peer_id(&stranger).unwrap()));
    db.upsert_peer(&peer_record(handle_b.device_id, vec![foreign.to_string()]))
        .unwrap();

    let stats = redial_known_peers(&db, &handle_a, &mut RedialState::default())
        .await
        .expect("pass");
    assert_eq!(stats.known_peers, 1);
    assert_eq!(stats.skipped_addrs, 1, "foreign-suffix address is dropped");
    assert_eq!(stats.no_addrs, 1, "nothing left to dial");
    assert_eq!(stats.dialed, 0);

    // With the peer's own suffix alongside, the valid address is still used.
    let own: Multiaddr = addr_b.with(Protocol::P2p(handle_b.peer_id));
    db.upsert_peer(&peer_record(
        handle_b.device_id,
        vec![foreign.to_string(), own.to_string()],
    ))
    .unwrap();
    let stats = redial_known_peers(&db, &handle_a, &mut RedialState::default())
        .await
        .expect("pass 2");
    assert_eq!(stats.skipped_addrs, 1);
    assert_eq!(stats.no_addrs, 0);
    assert_eq!(stats.dialed, 1);
}

/// A known peer without any stored address is counted, not silently ignored:
/// `no_addrs` is what tells "nothing to dial" apart from "dial failed" in the log.
#[tokio::test]
async fn redial_counts_peer_without_addrs() {
    let (_dir, db) = tmp_db();
    let (handle_a, _events_a) = SwarmHandle::start(make_swarm_config(76))
        .await
        .expect("swarm A");
    let device_c = DeviceId(
        make_swarm_config(77)
            .device_signing_key
            .verifying_key()
            .to_bytes(),
    );
    db.upsert_peer(&peer_record(device_c, vec![])).unwrap();
    // Own device in the peers table is not a peer to dial.
    db.upsert_peer(&peer_record(handle_a.device_id, vec![]))
        .unwrap();

    let stats = redial_known_peers(&db, &handle_a, &mut RedialState::default())
        .await
        .expect("pass");
    assert_eq!(
        stats,
        RedialStats {
            known_peers: 1,
            already_connected: 0,
            dialed: 0,
            no_addrs: 1,
            skipped_addrs: 0,
            ..RedialStats::default()
        }
    );
}

/// restore-i26: the redial before a restore retry dials only the given holders
/// (once each, however often listed), counts a holder without a PeerRecord as
/// `no_addrs`, and really reaches the holder.
#[tokio::test]
async fn redial_devices_dials_only_given_holders_once() {
    let (_dir, db) = tmp_db();
    let (handle_a, mut events_a) = SwarmHandle::start(make_swarm_config(78))
        .await
        .expect("swarm A");
    let (handle_b, _events_b) = SwarmHandle::start(make_swarm_config(79))
        .await
        .expect("swarm B");
    let (handle_c, _events_c) = SwarmHandle::start(make_swarm_config(80))
        .await
        .expect("swarm C");
    let addr_b = get_listen_addr(&handle_b).await;
    let addr_c = get_listen_addr(&handle_c).await;
    db.upsert_peer(&peer_record(handle_b.device_id, vec![addr_b.to_string()]))
        .unwrap();
    db.upsert_peer(&peer_record(handle_c.device_id, vec![addr_c.to_string()]))
        .unwrap();
    let unknown = DeviceId(
        make_swarm_config(81)
            .device_signing_key
            .verifying_key()
            .to_bytes(),
    );

    let stats = redial_devices(
        &db,
        &handle_a,
        &[
            handle_b.device_id,
            handle_b.device_id,
            unknown,
            handle_a.device_id,
        ],
    )
    .await
    .expect("pass");
    assert_eq!(
        stats,
        RedialStats {
            known_peers: 2,
            already_connected: 0,
            dialed: 1,
            no_addrs: 1,
            skipped_addrs: 0,
            ..RedialStats::default()
        }
    );
    wait_for_authenticated(&mut events_a, handle_b.device_id).await;
    let (authenticated, _) = handle_a.peer_sets().await.unwrap();
    assert!(
        !authenticated.contains(&handle_c.device_id),
        "C was not in the list: not dialed"
    );

    let stats = redial_devices(&db, &handle_a, &[handle_b.device_id])
        .await
        .expect("pass 2");
    assert_eq!(stats.already_connected, 1);
    assert_eq!(stats.dialed, 0);
}

// ── The floor (C-DK Р-13, network-i43): the pure planner ────────────────────

fn cand(n: u8, last_seen: u64, infra: bool) -> Candidate {
    Candidate {
        device: DeviceId([n; 32]),
        peer: libp2p::PeerId::random(),
        addrs: vec![],
        last_seen: Timestamp(last_seen),
        infra,
    }
}

fn devices(plan: &[Candidate]) -> Vec<u8> {
    plan.iter().map(|c| c.device.0[0]).collect()
}

fn conn_stats(cap: Option<u32>, seed_role: bool) -> crate::daemon::network::swarm::ConnStats {
    crate::daemon::network::swarm::ConnStats {
        cap,
        seed_role,
        ..Default::default()
    }
}

#[test]
fn redial_floor_is_half_cap() {
    assert_eq!(redial_floor(&conn_stats(Some(48), false)), Some(16));
    assert_eq!(redial_floor(&conn_stats(Some(24), false)), Some(12));
    assert_eq!(redial_floor(&conn_stats(Some(12), false)), Some(6));
    assert_eq!(
        redial_floor(&conn_stats(None, false)),
        None,
        "no cache: no floor"
    );
}

#[test]
fn seed_redial_dials_all_known() {
    assert_eq!(redial_floor(&conn_stats(Some(48), true)), None);
    let mut state = RedialState::default();
    let mut stats = RedialStats::default();
    let all: Vec<Candidate> = (1..=39).map(|n| cand(n, 0, false)).collect();
    let plan = plan_redial(all, 30, None, &mut state, &mut stats);
    assert_eq!(plan.len(), 39, "floor = ∞: every known peer, every pass");
}

#[test]
fn redial_without_cap_dials_all() {
    let mut state = RedialState::default();
    for _ in 0..3 {
        let mut stats = RedialStats::default();
        let all: Vec<Candidate> = (1..=20).map(|n| cand(n, 0, false)).collect();
        let plan = plan_redial(all, 5, None, &mut state, &mut stats);
        assert_eq!(plan.len(), 20, "ConnPolicy::off: as before C4, no rotation");
        assert_eq!(stats.skipped_rotation, 0);
    }
}

#[test]
fn redial_stops_at_floor() {
    let mut state = RedialState::default();
    let mut stats = RedialStats::default();
    let plan = plan_redial(
        (1..=10).map(|n| cand(n, 0, false)).collect(),
        16,
        Some(16),
        &mut state,
        &mut stats,
    );
    assert!(plan.is_empty(), "authenticated ≥ floor: nobody");
    assert_eq!(stats.skipped_floor, 10);

    let mut stats = RedialStats::default();
    let plan = plan_redial(
        (1..=10).map(|n| cand(n, 0, false)).collect(),
        13,
        Some(16),
        &mut state,
        &mut stats,
    );
    assert_eq!(plan.len(), 3, "floor − authenticated places");
}

#[test]
fn redial_orders_by_last_seen_and_rotates() {
    let mut state = RedialState::default();
    let all = || {
        vec![
            cand(1, 100, false),
            cand(2, 300, false),
            cand(3, 200, false),
            cand(4, 50, false),
        ]
    };
    let mut stats = RedialStats::default();
    let plan = plan_redial(all(), 14, Some(16), &mut state, &mut stats);
    assert_eq!(devices(&plan), vec![2, 3], "freshest last_seen first");
    let mut stats = RedialStats::default();
    let plan = plan_redial(all(), 14, Some(16), &mut state, &mut stats);
    assert_eq!(
        devices(&plan),
        vec![1, 4],
        "2 and 3 were dialed last pass: rotated out"
    );
    assert_eq!(stats.skipped_rotation, 2);
    let mut stats = RedialStats::default();
    let plan = plan_redial(all(), 14, Some(16), &mut state, &mut stats);
    assert!(
        plan.is_empty(),
        "all four dialed in the two previous passes"
    );
    let mut stats = RedialStats::default();
    let plan = plan_redial(all(), 14, Some(16), &mut state, &mut stats);
    assert_eq!(
        devices(&plan),
        vec![2, 3],
        "three passes later 2 and 3 are back"
    );
}

/// v3.1 W7: rotation only when there are more candidates than places — an
/// offline peer is dialed again every pass otherwise (door of network-i2).
#[test]
fn redial_no_rotation_when_candidates_fit() {
    let mut state = RedialState::default();
    for _ in 0..3 {
        let mut stats = RedialStats::default();
        let plan = plan_redial(
            vec![cand(1, 0, false), cand(2, 0, false)],
            3,
            Some(16),
            &mut state,
            &mut stats,
        );
        assert_eq!(plan.len(), 2);
        assert_eq!(stats.skipped_rotation, 0);
    }
}

#[test]
fn redial_always_dials_bootstrap_peers() {
    let mut state = RedialState::default();
    for _ in 0..3 {
        let mut stats = RedialStats::default();
        let plan = plan_redial(
            vec![cand(9, 0, true), cand(1, 0, false)],
            20,
            Some(16),
            &mut state,
            &mut stats,
        );
        assert_eq!(
            devices(&plan),
            vec![9],
            "infrastructure above the floor too"
        );
    }
}

/// The executor reads the floor from the swarm's cache (a friend policy with
/// cap 48 → floor 16) and still reaches a peer below it.
#[tokio::test]
async fn redial_pass_reports_floor_of_the_cache() {
    let (_dir, db) = tmp_db();
    let mut cfg = make_swarm_config(82);
    cfg.conn_policy.cap = Some(48);
    let (handle_a, mut events_a) = SwarmHandle::start(cfg).await.expect("swarm A");
    let (handle_b, _events_b) = SwarmHandle::start(make_swarm_config(83))
        .await
        .expect("swarm B");
    let addr_b = get_listen_addr(&handle_b).await;
    db.upsert_peer(&peer_record(handle_b.device_id, vec![addr_b.to_string()]))
        .unwrap();
    let stats = redial_known_peers(&db, &handle_a, &mut RedialState::default())
        .await
        .expect("pass");
    assert_eq!(stats.floor, Some(16));
    assert_eq!(stats.dialed, 1, "0 authenticated < 16: dialed");
    wait_for_authenticated(&mut events_a, handle_b.device_id).await;
}
