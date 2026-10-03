// Db::update_peers — a batch of peer updates in one write transaction (C-DK C4 fix round 3).

use crate::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
use crate::db::testutil::test_db_with_sync_probe;
use crate::types::{DeviceId, IdentityPub, PeerRecord, Timestamp};

fn record(n: u8, addrs: Vec<String>) -> PeerRecord {
    PeerRecord {
        device_id: DeviceId([n; 32]),
        master_identity: IdentityPub([0x22; 32]),
        trust_p: INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1000),
        last_seen: Timestamp(1000),
        revoked_device_pub_keys: vec![],
        addrs,
        x25519_pub: None,
        avail_ewma: AVAIL_EWMA_INITIAL,
        last_avail_sample: 1000,
    }
}

/// Syncs of one durable commit on this backend (calibration: compare counts, not syncs).
fn syncs_per_commit(db: &crate::db::Db, probe: &crate::db::testutil::SyncProbe) -> u64 {
    let before = probe.syncs();
    db.upsert_peer(&record(0xEE, vec![])).unwrap();
    let per = probe.syncs() - before;
    assert!(per >= 1, "a durable commit must sync the storage");
    per
}

#[test]
fn update_peers_writes_fifty_records_and_mappings_in_one_commit() {
    let (db, probe) = test_db_with_sync_probe();
    let per = syncs_per_commit(&db, &probe);
    let before = probe.syncs();
    let master = IdentityPub([0x22; 32]);
    let ((), committed) = db
        .update_peers(|b| {
            for n in 1..=50u8 {
                assert!(b.put(&record(n, vec![format!("/ip4/127.0.0.1/tcp/{n}")]))?);
                assert!(b.set_master_for_device(&DeviceId([n; 32]), &master)?);
            }
            assert_eq!(b.writes(), 100);
            Ok(())
        })
        .unwrap();
    assert!(committed);
    assert_eq!(
        probe.syncs() - before,
        per,
        "50 records + 50 mappings = ONE commit"
    );
    for n in 1..=50u8 {
        let d = DeviceId([n; 32]);
        assert_eq!(db.get_peer(&d).unwrap().unwrap().addrs.len(), 1);
        assert_eq!(db.get_master_for_device(&d).unwrap(), Some(master));
    }
}

#[test]
fn update_peers_that_change_nothing_do_not_commit() {
    let (db, probe) = test_db_with_sync_probe();
    let r = record(7, vec!["/ip4/127.0.0.1/tcp/7".to_string()]);
    let master = IdentityPub([0x22; 32]);
    db.update_peers(|b| {
        b.put(&r)?;
        b.set_master_for_device(&r.device_id, &master)
    })
    .unwrap();
    let before = probe.syncs();
    let (seen, committed) = db
        .update_peers(|b| {
            let current = b.get(&r.device_id)?;
            assert!(!b.put(&r)?, "same bytes: not written");
            assert!(!b.set_master_for_device(&r.device_id, &master)?);
            Ok(current)
        })
        .unwrap();
    assert_eq!(seen.expect("stored").addrs, r.addrs);
    assert!(!committed);
    assert_eq!(probe.syncs(), before, "nothing changed: no commit, no sync");
}

#[test]
fn update_peers_error_aborts_the_whole_batch() {
    let (db, _probe) = test_db_with_sync_probe();
    let out = db.update_peers(|b| -> Result<(), crate::db::DbError> {
        b.put(&record(1, vec![]))?;
        Err(crate::db::DbError::NotFound("test".to_string()))
    });
    assert!(out.is_err());
    assert!(
        db.get_peer(&DeviceId([1; 32])).unwrap().is_none(),
        "aborted: nothing stored"
    );
}

#[test]
fn update_peers_reads_its_own_writes() {
    let (db, _probe) = test_db_with_sync_probe();
    let ((), _) = db
        .update_peers(|b| {
            b.put(&record(3, vec![]))?;
            let mut r = b.get(&DeviceId([3; 32]))?.expect("own write visible");
            r.addrs = vec!["/ip4/127.0.0.1/tcp/3".to_string()];
            b.put(&r)?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        db.get_peer(&DeviceId([3; 32]))
            .unwrap()
            .unwrap()
            .addrs
            .len(),
        1
    );
}
