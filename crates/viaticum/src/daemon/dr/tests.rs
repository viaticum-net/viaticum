// Tests for the DR orchestration: SS blob round-trip, the Kademlia lookup key (F12),
// and the stop-signal guard of the network phase (dr-i23).
//
// The full happy path of run_dr needs a network of daemons with a published pointer:
// covered by experiments/local_dr_test.sh.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::daemon::system_state::{
    SYSTEM_STATE_VERSION, decrypt_and_restore, snapshot_and_encrypt,
};
use viaticum_core::types::IdentityPub;

use super::preflight::preflight;
use super::{DrError, dr_lookup_key, guarded_network_phase};

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon art";

#[test]
fn dr_decrypt_and_restore_roundtrip() {
    let db1 = viaticum_core::db::Db::open_in_memory().unwrap();
    let seed = [42u8; 64];
    let blob = snapshot_and_encrypt(&db1, &seed).unwrap();
    let db2 = viaticum_core::db::Db::open_in_memory().unwrap();
    let state = decrypt_and_restore(&db2, &blob, &seed).unwrap();
    assert_eq!(state.version, SYSTEM_STATE_VERSION);
}

#[test]
fn dr_fails_on_empty_blob() {
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    assert!(decrypt_and_restore(&db, &[], &[42u8; 64]).is_err());
}

#[test]
fn dr_fails_on_wrong_seed() {
    let db1 = viaticum_core::db::Db::open_in_memory().unwrap();
    let blob = snapshot_and_encrypt(&db1, &[42u8; 64]).unwrap();
    let db2 = viaticum_core::db::Db::open_in_memory().unwrap();
    assert!(decrypt_and_restore(&db2, &blob, &[99u8; 64]).is_err());
}

// ─── F12: the Kademlia lookup key is the preimage ─────────────────────────────

/// libp2p-kad hashes the key given to `get_closest_peers` (`kbucket::Key::new` =
/// SHA256 of the preimage). Postmen are ranked by `SHA256(master_pub)`
/// (`KademliaRoutingView::target_key`). So DR must pass `master_pub` itself: libp2p's
/// hash of `dr_lookup_key(m)` must land exactly on the postmen's key. The mutation
/// "pass target_key (double hash)" makes the assertions fail.
#[test]
fn dr_kad_lookup_key_is_address_preimage() {
    use crate::daemon::mailbox::candidate::KademliaRoutingView;
    let m = IdentityPub([0x5cu8; 32]);
    let key = dr_lookup_key(&m);
    let libp2p_key = libp2p::kad::KBucketKey::new(key.clone());
    assert_eq!(
        libp2p_key.hashed_bytes(),
        KademliaRoutingView::target_key(&m).as_slice(),
        "libp2p's hash of the lookup key must be where the postmen are ranked"
    );
    assert_eq!(key, m.0.to_vec(), "DR passes the preimage");
}

// ─── dr-i23: stop signal during the network phase ─────────────────────────────

/// A network phase that never ends, holding the staging DB open like the real one.
struct HangingWork {
    _db: viaticum_core::db::Db,
}

impl Future for HangingWork {
    type Output = Result<(), DrError>;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

/// `guarded_network_phase` with an artificial "signal": the key draft is written, the
/// staging DB is open, the signal arrives → `Interrupted`, and the folder holds no
/// `*.dr-new`, no `identity.key`, no `db.redb` (only the empty data dir DR created).
#[tokio::test]
async fn network_phase_interrupt_aborts_and_removes_own_staging() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("dr");
    let mut plan = preflight(&dir, PHRASE).expect("preflight on an empty folder");
    let file = plan.staging.file.take().expect("staging claimed");
    let work = async move {
        let db = viaticum_core::db::Db::create_from_file(file).unwrap();
        HangingWork { _db: db }.await
    };
    let (sig_tx, sig_rx) = tokio::sync::oneshot::channel::<&'static str>();
    let interrupt = async move { sig_rx.await.unwrap_or("closed") };

    let key_draft = dir.join("identity.key.dr-new");
    let guarded = guarded_network_phase(&mut plan, work, interrupt);
    tokio::pin!(guarded);
    // Let the phase start: the key draft is written before the work runs.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut guarded)
            .await
            .is_err(),
        "the phase must still be running"
    );
    assert!(key_draft.exists(), "key draft written in the network phase");
    assert!(dir.join("db.redb.dr-new").exists());

    sig_tx.send("SIGINT").unwrap();
    let result = guarded.await;
    assert!(matches!(result, Err(DrError::Interrupted)), "{result:?}");
    assert_eq!(
        DrError::Interrupted.to_string(),
        "DR interrupted. Nothing was changed."
    );

    let left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(left.is_empty(), "the folder must be empty, found {left:?}");
}

/// A failure of the network phase (not a signal) aborts the same way.
#[tokio::test]
async fn network_phase_error_aborts_and_removes_own_staging() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("dr");
    let mut plan = preflight(&dir, PHRASE).unwrap();
    let file = plan.staging.file.take().unwrap();
    let work = async move {
        let _db = viaticum_core::db::Db::create_from_file(file).unwrap();
        Err::<(), _>(DrError::NoCandidates)
    };
    let result = guarded_network_phase(&mut plan, work, std::future::pending()).await;
    assert!(matches!(result, Err(DrError::NoCandidates)));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

/// `commit` runs after the guarded phase and is synchronous: a signal queued during
/// the commit cannot cut it (review item of spec B2 §2.13, checked by the compiler).
#[test]
fn commit_is_a_synchronous_fn() {
    let _f: fn(super::preflight::DrPlan) -> Result<super::commit::CommitOutcome, DrError> =
        super::commit::commit;
}

// ─── dr-i35: an older pointer of the same history when the newest fails ───────

fn test_pointer(created_at: u64) -> viaticum_core::system_state::SelfPointer {
    let master = viaticum_core::cluster::derive_master_key(&[7u8; 32]).unwrap();
    viaticum_core::system_state::sign_self_pointer(
        &master,
        1,
        viaticum_core::system_state::BlockRef {
            block_id: viaticum_core::types::SourceBlockId([created_at as u8; 32]),
            holders: vec![],
            encrypted_size: 10,
        },
        vec![],
        viaticum_core::types::Timestamp(created_at),
        viaticum_core::system_state::CatalogSummary {
            lineage: viaticum_core::system_state::CatalogLineageId([1; 16]),
            publisher: viaticum_core::types::DeviceId([2; 32]),
            files: 1,
        },
    )
}

#[tokio::test]
async fn first_fetchable_falls_back_to_an_older_pointer_when_the_newest_fails() {
    let pointers = vec![test_pointer(300), test_pointer(200), test_pointer(100)];
    let mut tried = Vec::new();
    let got = super::first_fetchable(
        &pointers,
        async |p: &viaticum_core::system_state::SelfPointer| {
            tried.push(p.created_at.0);
            if p.created_at.0 == 300 {
                Err("holders gone".to_string())
            } else {
                Ok(p.created_at.0)
            }
        },
    )
    .await;
    assert_eq!(got, Ok((1, 200)), "the next older pointer is used");
    assert_eq!(tried, vec![300, 200], "stops at the first that works");
}

#[tokio::test]
async fn first_fetchable_reports_every_error_when_all_fail() {
    let pointers = vec![test_pointer(300), test_pointer(200)];
    let got = super::first_fetchable(
        &pointers,
        async |p: &viaticum_core::system_state::SelfPointer| {
            Err::<(), _>(format!("fail {}", p.created_at.0))
        },
    )
    .await;
    assert_eq!(
        got,
        Err(vec!["fail 300".to_string(), "fail 200".to_string()])
    );
}

#[tokio::test]
async fn malformed_catalog_prefix_is_refused_before_anything_is_touched() {
    // N4: a bad --catalog stops run_dr before preflight: not even the data dir appears,
    // and no network is started (no --peer needed).
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("dr");
    let err = super::run_dr(super::DrOptions {
        mnemonic: PHRASE.to_string(),
        peers: vec![],
        data_dir: dir.clone(),
        catalog: Some("abc".to_string()),
    })
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            DrError::Catalog(
                viaticum_core::system_state::catalog::CatalogSelectError::BadPrefix { .. }
            )
        ),
        "{err:?}"
    );
    assert!(err.to_string().ends_with("Nothing was changed."), "{err}");
    assert!(!dir.exists());
}
