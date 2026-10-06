// The PeerRecord writer's queue and batch write (C-DK C4 fix round 3): one commit per
// batch (record + device-to-master together), no write for an identify that changes
// nothing, events of one device folded in arrival order, the queue bounded by devices.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use viaticum_core::constants::{AVAIL_EWMA_ALPHA, AVAIL_EWMA_INITIAL};
use viaticum_core::db::Db;
use viaticum_core::db::testutil::{SyncProbe, test_db_with_sync_probe};
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp, ewma_contact_observed};

use super::{
    BATCH_MAX, DROP_LOG_EVERY, PeerRecordEvent, PeerRecordQueue, PendingState, apply_batch,
    run_writer,
};

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

// ── C-DK C4 fix round 4 ──────────────────────────────────────────────────────

/// Poll `cond` every 20 ms for up to `secs`.
async fn wait_until(secs: u64, cond: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !cond() {
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
}

/// WARN-2 (i), network-i2: an authentication pushed right before the shutdown is written
/// before the writer returns — the cancelled writer writes what is queued, it does not
/// just stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_writer_writes_what_is_queued_before_it_returns() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let processor =
        Arc::new(crate::daemon::processor::tests::make_processor(db.clone(), &dir).await);
    let a = addr(20);
    assert!(processor.peer_records.push(auth(20, &[a.as_str()])));
    let cancel = CancellationToken::new();
    cancel.cancel();
    tokio::time::timeout(
        Duration::from_secs(10),
        run_writer(processor.clone(), cancel),
    )
    .await
    .expect("the cancelled writer returns");
    let r = db
        .get_peer(&device(20))
        .unwrap()
        .expect("queued at the cancel: written before run_writer returned");
    assert_eq!(r.addrs, vec![a]);
    assert_eq!(processor.peer_records.len(), 0);
}

/// WARN-2 (ii): a batch whose write fails costs that batch only; the writer goes on and
/// writes the next one. The failure is a row that does not decode (the batch reads it):
/// a storage I/O error cannot serve here — redb marks the database failed after one
/// (`PreviousIo` on every later transaction), so nothing could be written afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_goes_on_after_a_failed_batch() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let processor =
        Arc::new(crate::daemon::processor::tests::make_processor(db.clone(), &dir).await);
    db.corrupt_peer_row_for_test(&device(21)).unwrap();
    let cancel = CancellationToken::new();
    let writer = tokio::spawn(run_writer(processor.clone(), cancel.clone()));

    assert!(processor.peer_records.push(auth(21, &[])));
    // Taken: the failing batch is in flight (one batch at a time), a later push is the
    // next batch.
    let q = processor.clone();
    assert!(wait_until(5, move || q.peer_records.len() == 0).await);
    let a = addr(22);
    assert!(processor.peer_records.push(auth(22, &[a.as_str()])));
    let db2 = db.clone();
    let written = wait_until(5, move || db2.get_peer(&device(22)).unwrap().is_some()).await;
    cancel.cancel();
    let _ = writer.await;
    assert!(
        written,
        "the batch after a failed one was never written: the writer stopped"
    );
    assert!(
        db.get_peer(&device(21)).is_err(),
        "control: the failed batch's row is still the undecodable one"
    );
}

/// N1: a revocation on the device's own PeerRecord committed between the push (admitted)
/// and the batch: the authentication is not written (no `last_seen` / contact update) and
/// nothing comes back for the after-steps.
#[test]
fn record_revoked_after_the_push_is_not_written() {
    let (db, _probe) = test_db_with_sync_probe();
    let q = PeerRecordQueue::new(1000);
    q.push(auth(23, &[]));
    assert_eq!(drain(&db, &q), 1);
    let mut revoked = db.get_peer(&device(23)).unwrap().unwrap();

    q.push(auth(23, &["/ip4/127.0.0.1/tcp/9"])); // admitted: not revoked yet
    revoked.revoked_device_pub_keys.push(device(23).0);
    db.upsert_peer(&revoked).unwrap(); // the signed revocation lands
    let batch = q.take_batch(BATCH_MAX);
    let written = apply_batch(&db, batch).unwrap();
    assert!(written.is_empty(), "no after-steps for a revoked device");
    let stored = db.get_peer(&device(23)).unwrap().unwrap();
    assert_eq!(stored.last_seen, revoked.last_seen);
    assert_eq!(stored.avail_ewma, revoked.avail_ewma);
    assert!(
        stored.addrs.is_empty(),
        "the revoked authentication wrote nothing"
    );
}

/// N1 through the writer task: a cluster revocation committed after the push — no
/// PeerRecord, no device-to-master mapping, no after-step (the work wake of the revoked
/// device never comes; the one of the other device in the same batch does).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cluster_revoked_after_the_push_gets_no_record_and_no_after_steps() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut processor = crate::daemon::processor::tests::make_processor(db.clone(), &dir).await;
    let (work_tx, mut work_rx) = tokio::sync::mpsc::channel(16);
    processor.set_work_event_tx(work_tx);
    let processor = Arc::new(processor);

    assert!(processor.peer_records.push(auth(24, &[]))); // admitted
    assert!(processor.peer_records.push(auth(25, &[]))); // control
    let mut cs = db
        .get_cluster_state()
        .unwrap()
        .expect("make_processor inits a cluster");
    cs.revoked_devices.push(device(24));
    db.set_cluster_state(&cs).unwrap(); // the revocation lands before the batch

    let cancel = CancellationToken::new();
    let writer = tokio::spawn(run_writer(processor.clone(), cancel.clone()));
    let mut woken = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !woken.contains(&device(25)) && Instant::now() < deadline {
        if let Ok(Some(crate::daemon::work_pipeline::WorkEvent::PeerAuthenticated { device_id })) =
            tokio::time::timeout(Duration::from_millis(100), work_rx.recv()).await
        {
            woken.push(device_id);
        }
    }
    // The after-steps of one batch are spawned together: give a stray one time to show.
    tokio::time::sleep(Duration::from_millis(300)).await;
    while let Ok(crate::daemon::work_pipeline::WorkEvent::PeerAuthenticated { device_id }) =
        work_rx.try_recv()
    {
        woken.push(device_id);
    }
    cancel.cancel();
    let _ = writer.await;
    assert!(
        woken.contains(&device(25)),
        "control: the other device's after-steps ran"
    );
    assert!(
        !woken.contains(&device(24)),
        "after-steps ran for a revoked device"
    );
    assert!(db.get_peer(&device(24)).unwrap().is_none());
    assert_eq!(db.get_master_for_device(&device(24)).unwrap(), None);
    assert!(db.get_peer(&device(25)).unwrap().is_some());
}

/// N8: the ERROR about drops at the cap is printed at most once per `DROP_LOG_EVERY` and
/// carries the number dropped since the last one; drops after it are reported once the
/// window has passed, also without a further drop.
#[test]
fn drop_error_is_rate_limited_and_counts_the_window() {
    let mut st = PendingState::default();
    let t0 = Instant::now();
    assert_eq!(
        st.note_drop(t0),
        Some(1),
        "the first drop is reported at once"
    );
    assert_eq!(st.note_drop(t0 + Duration::from_secs(1)), None);
    assert_eq!(st.note_drop(t0 + Duration::from_secs(2)), None);
    assert_eq!(st.drop_report_due(t0 + Duration::from_secs(5)), None);
    assert_eq!(
        st.drop_report_due(t0 + DROP_LOG_EVERY),
        Some(2),
        "the two drops of the window, without a further drop"
    );
    assert_eq!(
        st.drop_report_due(t0 + DROP_LOG_EVERY * 3),
        None,
        "nothing unreported"
    );
    assert_eq!(st.note_drop(t0 + DROP_LOG_EVERY * 3), Some(1));
}

/// pos-i21: an authentication does not reset the trust of a peer that failed every check
/// (p = 0, i = 0 — only `recalculate_trust` after all-failed PoS writes that, and only a
/// passed check lifts it). A new peer still starts at the prior.
#[test]
fn authentication_keeps_the_zero_trust_of_a_peer_that_failed_every_check() {
    use viaticum_core::constants::INITIAL_TRUST_P;

    let db = Db::open_in_memory().unwrap();
    let q = PeerRecordQueue::new(16);
    assert!(q.push(auth(1, &[])));
    drain(&db, &q);
    let fresh = db.get_peer(&device(1)).unwrap().expect("record");
    assert_eq!((fresh.trust_p, fresh.trust_i), (INITIAL_TRUST_P, 0.0));

    // What `recalculate_trust` leaves after every challenge in the window failed.
    db.update_peer(&device(1), |r| {
        let mut r = r?;
        r.trust_p = 0.0;
        r.trust_i = 0.0;
        Some(r)
    })
    .unwrap();
    assert!(q.push(auth(1, &[])));
    drain(&db, &q);

    let after = db.get_peer(&device(1)).unwrap().expect("record");
    assert_eq!(
        (after.trust_p, after.trust_i),
        (0.0, 0.0),
        "reconnecting must not turn a peer that failed every check into a newcomer"
    );
    assert!(
        after.avail_ewma > fresh.avail_ewma,
        "the contact itself is still counted"
    );
}
