// The PeerRecord writer's queue and batch write (C-DK C4 fix round 3): one commit per
// batch (record + device-to-master together), no write for an identify that changes
// nothing, events of one device folded in arrival order, the queue bounded by devices.

use std::time::{Duration, Instant};

use viaticum_core::constants::{AVAIL_EWMA_ALPHA, AVAIL_EWMA_INITIAL};
use viaticum_core::db::Db;
use viaticum_core::db::testutil::{SyncProbe, test_db_with_sync_probe};
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp, ewma_contact_observed};

use super::{BATCH_MAX, PeerRecordEvent, PeerRecordQueue, apply_batch};

fn other_master() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x77; 32])
}

fn device(n: u8) -> DeviceId {
    let key = ed25519_dalek::SigningKey::from_bytes(&[n.wrapping_add(1); 32]);
    DeviceId(key.verifying_key().to_bytes())
}

fn auth(n: u8, addrs: &[&str]) -> PeerRecordEvent {
    let master = other_master();
    let device_id = device(n);
    PeerRecordEvent::Authenticated {
        device_id,
        identity_pub: IdentityPub(master.verifying_key().to_bytes()),
        device_cert: Box::new(viaticum_core::cluster::issue_device_certificate(
            &master,
            device_id,
            Timestamp::now(),
        )),
        x25519_pub: None,
        listen_addrs: addrs.iter().map(|a| a.to_string()).collect(),
    }
}

fn identify(n: u8, addrs: &[&str]) -> PeerRecordEvent {
    PeerRecordEvent::Identified {
        device_id: device(n),
        listen_addrs: addrs.iter().map(|a| a.to_string()).collect(),
    }
}

fn addr(n: u8) -> String {
    format!("/ip4/127.0.0.1/tcp/{}", 20000 + n as u16)
}

/// Write everything queued, batch by batch (as the writer task does).
fn drain(db: &Db, q: &PeerRecordQueue) -> usize {
    let mut written = 0;
    loop {
        let batch = q.take_batch(BATCH_MAX);
        if batch.is_empty() {
            return written;
        }
        written += apply_batch(db, batch).expect("batch write").len();
    }
}

/// Syncs of one durable commit on this backend (a separate table: no PeerRecord added).
fn syncs_per_commit(db: &Db, probe: &SyncProbe) -> u64 {
    let before = probe.syncs();
    db.set_master_for_device(&DeviceId([0xEE; 32]), &IdentityPub([0xEE; 32]))
        .unwrap();
    let per = probe.syncs() - before;
    assert!(per >= 1, "a durable commit must sync the storage");
    per
}

#[test]
fn fifty_authentications_with_identify_are_one_commit() {
    let (db, probe) = test_db_with_sync_probe();
    let per = syncs_per_commit(&db, &probe);
    let q = PeerRecordQueue::new(1000);
    for n in 0..50u8 {
        assert!(q.push(auth(n, &[])));
        let a = addr(n);
        assert!(q.push(identify(n, &[a.as_str()])));
    }
    assert_eq!(q.len(), 50, "auth + identify of one device are one entry");
    let before = probe.syncs();
    let batch = q.take_batch(BATCH_MAX);
    assert_eq!(batch.len(), 50);
    let written = apply_batch(&db, batch).unwrap();
    let commits = (probe.syncs() - before) / per;
    assert_eq!(
        commits, 1,
        "50 authentications (record + device-to-master each) must be ONE durable commit, got {commits}"
    );
    assert_eq!(written.len(), 50);
    assert!(written.iter().all(|w| w.is_new_peer));
    let master = IdentityPub(other_master().verifying_key().to_bytes());
    for n in 0..50u8 {
        let r = db.get_peer(&device(n)).unwrap().expect("record");
        assert_eq!(r.addrs, vec![addr(n)]);
        assert_eq!(db.get_master_for_device(&device(n)).unwrap(), Some(master));
    }
}

#[test]
fn identify_that_changes_nothing_begins_no_write() {
    let (db, probe) = test_db_with_sync_probe();
    let q = PeerRecordQueue::new(1000);
    let a = addr(1);
    q.push(auth(1, &[a.as_str()]));
    drain(&db, &q);

    // Another writer holds redb's single write lock for 600 ms: a batch that began a
    // write transaction would wait for it.
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let db2 = db.clone();
    let holder = std::thread::spawn(move || {
        let txn = db2.write_txn().unwrap();
        held_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(600));
        drop(txn);
    });
    held_rx.recv().unwrap();

    let before = probe.syncs();
    let t0 = Instant::now();
    q.push(identify(1, &[a.as_str()])); // the same addresses
    q.push(identify(9, &[a.as_str()])); // no record (a revoked device is never recorded)
    drain(&db, &q);
    let took = t0.elapsed();
    holder.join().unwrap();
    assert!(
        took < Duration::from_millis(300),
        "an identify batch that changes nothing waited {took:?} for the write lock: it began a write"
    );
    assert_eq!(probe.syncs(), before, "nothing changed: no commit");
    assert!(db.get_peer(&device(9)).unwrap().is_none());
}

#[test]
fn identify_queued_before_its_authentication_is_written_keeps_the_addresses() {
    let (db, _probe) = test_db_with_sync_probe();
    let q = PeerRecordQueue::new(1000);
    let a = addr(2);
    q.push(identify(2, &[a.as_str()]));
    q.push(auth(2, &[])); // a listener: no addresses with the authentication
    drain(&db, &q);
    assert_eq!(db.get_peer(&device(2)).unwrap().unwrap().addrs, vec![a]);
}

#[test]
fn the_latest_addresses_win_in_arrival_order() {
    let (db, _probe) = test_db_with_sync_probe();
    let q = PeerRecordQueue::new(1000);
    q.push(identify(3, &["/ip4/127.0.0.1/tcp/1"]));
    q.push(auth(3, &["/ip4/127.0.0.1/tcp/2"]));
    drain(&db, &q);
    assert_eq!(
        db.get_peer(&device(3)).unwrap().unwrap().addrs,
        vec!["/ip4/127.0.0.1/tcp/2".to_string()]
    );

    q.push(auth(3, &["/ip4/127.0.0.1/tcp/4"]));
    q.push(identify(3, &["/ip4/127.0.0.1/tcp/5"]));
    q.push(auth(3, &[])); // empty: keeps what came before
    drain(&db, &q);
    assert_eq!(
        db.get_peer(&device(3)).unwrap().unwrap().addrs,
        vec!["/ip4/127.0.0.1/tcp/5".to_string()]
    );
}

#[test]
fn folded_authentications_count_every_contact() {
    let (db, _probe) = test_db_with_sync_probe();
    let q = PeerRecordQueue::new(1000);
    q.push(auth(4, &[]));
    drain(&db, &q);
    assert_eq!(
        db.get_peer(&device(4)).unwrap().unwrap().avail_ewma,
        AVAIL_EWMA_INITIAL
    );
    q.push(auth(4, &[]));
    q.push(auth(4, &[]));
    let written = drain(&db, &q);
    assert_eq!(written, 1, "one entry, one after-step run");
    let want = ewma_contact_observed(
        ewma_contact_observed(AVAIL_EWMA_INITIAL, AVAIL_EWMA_ALPHA),
        AVAIL_EWMA_ALPHA,
    );
    assert_eq!(db.get_peer(&device(4)).unwrap().unwrap().avail_ewma, want);
}

#[test]
fn queue_takes_first_arrivals_first_and_folds_repeats() {
    let q = PeerRecordQueue::new(1000);
    q.push(auth(5, &[]));
    q.push(auth(6, &[]));
    q.push(auth(5, &[])); // folds into the first entry, keeps its place
    q.push(auth(7, &[]));
    q.push(identify(8, &[])); // no addresses: nothing to queue
    assert_eq!(q.len(), 3);
    let first: Vec<DeviceId> = q.take_batch(2).iter().map(|p| p.device_id).collect();
    assert_eq!(first, vec![device(5), device(6)]);
    let rest: Vec<DeviceId> = q.take_batch(2).iter().map(|p| p.device_id).collect();
    assert_eq!(rest, vec![device(7)]);
    assert_eq!(q.len(), 0);
}

#[test]
fn queue_at_its_device_cap_refuses_only_new_devices() {
    let q = PeerRecordQueue::new(2);
    assert!(q.push(auth(10, &[])));
    assert!(q.push(auth(11, &[])));
    assert!(
        !q.push(auth(12, &[])),
        "a third distinct device is over the cap"
    );
    let a = addr(10);
    assert!(
        q.push(identify(10, &[a.as_str()])),
        "a queued device still folds in"
    );
    assert_eq!(q.len(), 2);
}
