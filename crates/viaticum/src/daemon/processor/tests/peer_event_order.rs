// C-DK C4 fix round 1 (network-i14): the swarm sends `PeerAuthenticated` (no
// addresses yet: the listener learns them from identify) and then
// `PeerIdentified`. The processor applies the record steps of both in that
// order, so every such peer ends up KNOWN (another master + a dialable
// address). Before the fix both handlers ran in separate `tokio::spawn`s: the
// identify write read no record (addresses dropped) or was overwritten by the
// authentication's later write.

use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp};

use crate::daemon::network::address_book::is_known;
use crate::daemon::network::swarm::{ProtocolEvent, device_id_to_peer_id};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identify_right_after_auth_keeps_the_addresses_of_every_peer() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let processor = super::make_processor(db.clone(), &dir).await;
    let own_master = processor.own_identity;
    let (tx, rx) = mpsc::channel(4096);
    let cancel = CancellationToken::new();
    let run = tokio::spawn(processor.run(rx, cancel.clone()));

    let other_master = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    let other = IdentityPub(other_master.verifying_key().to_bytes());
    let mut devices = Vec::new();
    for n in 0..50u8 {
        let key = ed25519_dalek::SigningKey::from_bytes(&[n.wrapping_add(1); 32]);
        let device_id = DeviceId(key.verifying_key().to_bytes());
        let peer_id = device_id_to_peer_id(&device_id).unwrap();
        let cert = viaticum_core::cluster::issue_device_certificate(
            &other_master,
            device_id,
            Timestamp::now(),
        );
        let addr: libp2p::Multiaddr =
            format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", 20000 + n as u16)
                .parse()
                .unwrap();
        tx.send(ProtocolEvent::PeerAuthenticated {
            peer_id,
            device_id,
            identity_pub: other,
            device_cert: cert,
            x25519_pub: None,
            listen_addrs: vec![],
        })
        .await
        .unwrap();
        tx.send(ProtocolEvent::PeerIdentified {
            device_id,
            listen_addrs: vec![addr],
        })
        .await
        .unwrap();
        devices.push(device_id);
    }

    let own_device = DeviceId([0u8; 32]);
    let all_known = || {
        devices.iter().all(|d| {
            db.get_peer(d)
                .unwrap()
                .is_some_and(|r| is_known(&r, &own_master, &own_device))
        })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !all_known() && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let unknown: Vec<String> = devices
        .iter()
        .filter(|d| {
            !db.get_peer(d)
                .unwrap()
                .is_some_and(|r| is_known(&r, &own_master, &own_device))
        })
        .map(|d| d.to_string())
        .collect();
    cancel.cancel();
    let _ = run.await;
    assert!(
        unknown.is_empty(),
        "{} of 50 peers not known (no address): {unknown:?}",
        unknown.len()
    );
}

/// Fix round 2 (WARN-B): a PeerAnnounce (handled in a spawned task) that read
/// the record before the inline identify wrote the addresses does not write the
/// record back without them. The announce update holds its read-modify-write
/// open for 20 ms (test hook), the identify arrives inside that window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_announce_racing_identify_keeps_the_addresses() {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let processor = Arc::new(super::make_processor(db.clone(), &dir).await);
    let own_master = processor.own_identity;
    super::super::peer::ANNOUNCE_RMW_DELAY_MS.store(20, Ordering::Relaxed);

    let mut devices = Vec::new();
    let mut announces = Vec::new();
    for n in 0..50u8 {
        // One master per device: each announce updates exactly its device.
        let master = ed25519_dalek::SigningKey::from_bytes(&[n.wrapping_add(100); 32]);
        let identity = IdentityPub(master.verifying_key().to_bytes());
        let key = ed25519_dalek::SigningKey::from_bytes(&[n.wrapping_add(1); 32]);
        let device_id = DeviceId(key.verifying_key().to_bytes());
        let peer_id = device_id_to_peer_id(&device_id).unwrap();
        let cert =
            viaticum_core::cluster::issue_device_certificate(&master, device_id, Timestamp::now());
        let addr: libp2p::Multiaddr =
            format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", 21000 + n as u16)
                .parse()
                .unwrap();
        // Processor::run: the record steps inline …
        assert!(
            processor
                .record_peer_authenticated(device_id, identity, &cert, None, &[])
                .is_some()
        );
        // … the announce spawned (dispatch_libp2p) …
        let pa =
            viaticum_core::messages::build_peer_announce(identity, Timestamp::now(), &master, None);
        let p = processor.clone();
        announces.push(tokio::spawn(
            async move { p.handle_peer_announce(pa).await },
        ));
        tokio::time::sleep(std::time::Duration::from_millis(5)).await; // it has read
        // … and the identify inline, inside the announce's window.
        processor.on_peer_identified(device_id, vec![addr]);
        devices.push(device_id);
    }
    for a in announces {
        a.await.expect("join").expect("announce handled");
    }
    super::super::peer::ANNOUNCE_RMW_DELAY_MS.store(0, Ordering::Relaxed);

    let own_device = DeviceId([0u8; 32]);
    let unknown: Vec<String> = devices
        .iter()
        .filter(|d| {
            !db.get_peer(d)
                .unwrap()
                .is_some_and(|r| is_known(&r, &own_master, &own_device))
        })
        .map(|d| d.to_string())
        .collect();
    assert!(
        unknown.is_empty(),
        "{} of 50 peers lost their address to an announce: {unknown:?}",
        unknown.len()
    );
}
