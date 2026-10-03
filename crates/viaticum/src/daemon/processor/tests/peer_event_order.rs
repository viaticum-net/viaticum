// C-DK C4 fix round 1 (network-i14): the swarm sends `PeerAuthenticated` (no
// addresses yet: the listener learns them from identify) and then
// `PeerIdentified`. The processor applies the record steps of both in that
// order, so every such peer ends up KNOWN (another master + a dialable
// address). Before the fix both handlers ran in separate `tokio::spawn`s: the
// identify write read no record (addresses dropped) or was overwritten by the
// authentication's later write.
//
// Fix round 3: the order is kept by the PeerRecord writer (one queue, one
// consumer), and the processor loop does not wait for the writer's commits.

use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp};

use crate::daemon::network::address_book::is_known;
use crate::daemon::network::swarm::{ProtocolEvent, device_id_to_peer_id};
use crate::daemon::processor::peer_record_writer::PeerRecordEvent;

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
/// the record before the writer's identify batch wrote the addresses does not
/// write the record back without them (both are one write transaction each). The announce update holds its read-modify-write
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
        // The PeerRecord writer: the authentication written …
        assert!(processor.admit_authenticated(device_id, identity, &cert));
        processor.peer_records.push(PeerRecordEvent::Authenticated {
            device_id,
            identity_pub: identity,
            device_cert: Box::new(cert),
            x25519_pub: None,
            listen_addrs: vec![],
        });
        assert_eq!(processor.write_peer_records_now().len(), 1);
        // … the announce spawned (dispatch_libp2p) …
        let pa =
            viaticum_core::messages::build_peer_announce(identity, Timestamp::now(), &master, None);
        let p = processor.clone();
        announces.push(tokio::spawn(
            async move { p.handle_peer_announce(pa).await },
        ));
        tokio::time::sleep(std::time::Duration::from_millis(5)).await; // it has read
        // … and the identify by the writer, inside the announce's window.
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

/// Fix round 3 (the regression of round 1): while the PeerRecord writer is in a
/// slow commit (each storage sync sleeps 2 s — a loaded disk), the processor
/// loop keeps handling every other event: the `ConnectionClosed` sent after 50
/// authentications + identifies is handled before a single commit finished.
/// The writer batches what piled up (commits << 50), and the after-steps (here:
/// the work-pipeline wake) run only once the record is committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_disk_does_not_hold_the_processor_loop() {
    use std::time::{Duration, Instant};

    let (db, probe) = viaticum_core::db::testutil::test_db_with_sync_probe();
    let dir = TempDir::new().unwrap();
    let mut processor = super::make_processor(db.clone(), &dir).await;
    let (work_tx, mut work_rx) = mpsc::channel(256);
    processor.set_work_event_tx(work_tx);
    let own_master = processor.own_identity;
    let cert_map = processor.peer_cert_map.clone();

    let before = probe.syncs();
    db.set_master_for_device(&DeviceId([0xEE; 32]), &IdentityPub([0xEE; 32]))
        .unwrap();
    let per_commit = probe.syncs() - before;
    assert!(per_commit >= 1);
    probe.set_sync_delay_ms(2000);
    let syncs_before = probe.syncs();

    let (tx, rx) = mpsc::channel(4096);
    let cancel = CancellationToken::new();
    let run = tokio::spawn(processor.run(rx, cancel.clone()));

    let other_master = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    let other = IdentityPub(other_master.verifying_key().to_bytes());
    let mut devices = Vec::new();
    let t0 = Instant::now();
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
            format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer_id}", 22000 + n as u16)
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
    let closed = devices[0];
    tx.send(ProtocolEvent::ConnectionClosed {
        peer_id: device_id_to_peer_id(&closed).unwrap(),
        device_id: Some(closed),
    })
    .await
    .unwrap();

    // The loop handled all 101 events (the last one removes `closed` from the
    // cert map) while the first commit still syncs.
    let loop_done = || {
        let map = cert_map.lock().unwrap();
        !map.contains_key(&closed) && devices[1..].iter().all(|d| map.contains_key(d))
    };
    while !loop_done() && t0.elapsed() < Duration::from_millis(1500) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let loop_took = t0.elapsed();
    let commits_meanwhile = (probe.syncs() - syncs_before) / per_commit;
    assert!(
        loop_done(),
        "the processor loop did not get through 101 events in {loop_took:?}: it waits for the PeerRecord commits"
    );
    assert_eq!(
        commits_meanwhile, 0,
        "a PeerRecord commit finished before the loop was through ({loop_took:?}): the check proves nothing"
    );

    // The writer catches up in a few batches; every wake comes after its commit.
    let own_device = DeviceId([0u8; 32]);
    let all_known = || {
        devices.iter().all(|d| {
            db.get_peer(d)
                .unwrap()
                .is_some_and(|r| is_known(&r, &own_master, &own_device))
        })
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut woken = 0;
    while !(all_known() && woken == 50) && Instant::now() < deadline {
        while let Ok(ev) = work_rx.try_recv() {
            if let crate::daemon::work_pipeline::WorkEvent::PeerAuthenticated { device_id } = ev {
                assert!(
                    db.get_peer(&device_id).unwrap().is_some(),
                    "after-steps of {device_id} ran before its PeerRecord was committed"
                );
                woken += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        all_known(),
        "not every peer known after the writer caught up"
    );
    let commits = (probe.syncs() - syncs_before) / per_commit;
    probe.set_sync_delay_ms(0);
    cancel.cancel();
    let _ = run.await;
    assert!(
        commits <= 5,
        "50 authentications + 50 identifies took {commits} commits: not batched"
    );
    assert_eq!(woken, 50, "every new peer is woken once, after its commit");
}
