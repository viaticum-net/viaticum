// Tests for the auto-dial pass (network-i2): real redb on a tmpfile, real
// libp2p swarms on loopback (same harness as network/swarm_tests.rs).

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use tempfile::TempDir;
use viaticum_core::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, PeerRecord, Timestamp};

use super::{RedialStats, redial_devices, redial_known_peers};
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

    let stats = redial_known_peers(&db, &handle_a).await.expect("pass");
    assert_eq!(
        stats,
        RedialStats {
            known_peers: 1,
            already_connected: 0,
            dialed: 1,
            no_addrs: 0,
            skipped_addrs: 0,
        }
    );
    // The dial really reaches B: A authenticates it (on another swarm, not by counter).
    wait_for_authenticated(&mut events_a, handle_b.device_id).await;

    // Next pass sees it connected and does not dial again.
    let stats = redial_known_peers(&db, &handle_a).await.expect("pass 2");
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

    let stats = redial_known_peers(&db, &handle_a).await.expect("pass");
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
    let stats = redial_known_peers(&db, &handle_a).await.expect("pass 2");
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

    let stats = redial_known_peers(&db, &handle_a).await.expect("pass");
    assert_eq!(
        stats,
        RedialStats {
            known_peers: 1,
            already_connected: 0,
            dialed: 0,
            no_addrs: 1,
            skipped_addrs: 0,
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
