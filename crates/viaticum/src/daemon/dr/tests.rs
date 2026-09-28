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
use viaticum_core::mailbox::MailboxAddress;
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
    let m = MailboxAddress::for_master(&IdentityPub([0x5cu8; 32]));
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

// ─── V.17.3 / dr-i48: attempts reach the head of every place ──────────────────

/// Five versions of place A (three different old bases among them, from lagging
/// postmen) are all fresher than the head of place B. The head of B is still the
/// second attempt, so a strong base in B is tried before any stale version of A.
#[test]
fn dr_tries_both_place_heads_before_stale_bases_from_lagging_postmen() {
    use std::collections::HashMap;
    use viaticum_core::system_state::catalog::select_catalog;

    let slot_a = [0xA0u8; 16];
    let slot_b = [0xB0u8; 16];
    // Place A: created_at 900, 800, 700, 600, 500 (bases differ by created_at).
    let a_versions: Vec<_> = [900u64, 800, 700, 600, 500]
        .iter()
        .map(|&t| test_pointer(t))
        .collect();
    let b_head = test_pointer(100);
    let b_old = test_pointer(50);
    let mut slot_of: HashMap<[u8; 64], [u8; 16]> = HashMap::new();
    for p in &a_versions {
        slot_of.insert(p.signature, slot_a);
    }
    slot_of.insert(b_head.signature, slot_b);
    slot_of.insert(b_old.signature, slot_b);

    let mut all = a_versions.clone();
    all.push(b_old.clone());
    all.push(b_head.clone());
    let choice = select_catalog(all, None).unwrap();
    let attempts = super::order_attempts(
        choice.selected,
        choice.fallbacks,
        &slot_of,
        [slot_a, slot_b],
    );
    let times: Vec<u64> = attempts.iter().map(|p| p.created_at.0).collect();
    assert_eq!(
        times,
        vec![900, 100, 800, 700],
        "head of A, head of B, then the rest freshest first; 4 attempts"
    );
}

/// The per-attempt DR log names the place each pointer was opened from (`-` when its
/// `msg_id` is neither slot of the history).
#[test]
fn attempt_place_names_the_slot_each_pointer_came_from() {
    use std::collections::HashMap;
    let slot_a = [0xA0u8; 16];
    let slot_b = [0xB0u8; 16];
    let (a, b, moved, unknown) = (
        test_pointer(900),
        test_pointer(800),
        test_pointer(700),
        test_pointer(600),
    );
    let slot_of: HashMap<[u8; 64], [u8; 16]> = HashMap::from([
        (a.signature, slot_a),
        (b.signature, slot_b),
        (moved.signature, [0xCC; 16]),
    ]);
    let slots = [slot_a, slot_b];
    assert_eq!(super::attempt_place(&a, &slot_of, slots), "A");
    assert_eq!(super::attempt_place(&b, &slot_of, slots), "B");
    assert_eq!(super::attempt_place(&moved, &slot_of, slots), "-");
    assert_eq!(super::attempt_place(&unknown, &slot_of, slots), "-");
}

/// A pointer under a `msg_id` that is neither place (a postman moved it) is never a
/// head; with one place only, the order is plain freshness.
#[test]
fn dr_attempts_ignore_pointers_under_unknown_slots_as_heads() {
    use std::collections::HashMap;
    let slot_a = [0xA0u8; 16];
    let moved = test_pointer(900);
    let a_head = test_pointer(500);
    let a_old = test_pointer(400);
    let mut slot_of: HashMap<[u8; 64], [u8; 16]> = HashMap::new();
    slot_of.insert(moved.signature, [0xEE; 16]);
    slot_of.insert(a_head.signature, slot_a);
    slot_of.insert(a_old.signature, slot_a);
    let attempts =
        super::order_attempts(moved, vec![a_head, a_old], &slot_of, [slot_a, [0xB0; 16]]);
    let times: Vec<u64> = attempts.iter().map(|p| p.created_at.0).collect();
    assert_eq!(times, vec![500, 900, 400]);
}

/// V.16.1 п.5: the two places of one history are ONE catalog for DR (grouped by the
/// signed lineage, not by `msg_id`) — no NeedsChoice.
#[test]
fn dr_two_places_of_one_lineage_are_one_catalog() {
    use viaticum_core::system_state::catalog::{ChoiceReason, select_catalog};
    let choice = select_catalog(vec![test_pointer(200), test_pointer(100)], None).unwrap();
    assert_eq!(choice.reason, ChoiceReason::OnlyCatalog);
    assert_eq!(choice.rows.len(), 1);
    assert_eq!(choice.rows[0].pointers_seen, 2);
    assert_eq!(choice.fallbacks.len(), 1);
}
