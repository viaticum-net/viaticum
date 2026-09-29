// СТ-0c (pos-i6, pos-i7): the owner's pending index, the O(1) response lookup, the
// trust read once per holder, the issue-tick line.

use std::cell::Cell;
use std::sync::Arc;

use tokio::sync::mpsc;
use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, IdentityPub, SourceBlockId, Timestamp, hex_encode};

use super::{
    RecordingMailboxSender, TEST_EPOCH_KEY, dummy_master_pub, make_identity, make_peer_record,
    make_pending_challenges, make_placement, make_scheduler_for_hook, make_test_encoder,
    seed_retained_pos_block,
};
use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};
use crate::daemon::repair::RepairTrigger;
use crate::daemon::scheduler::{
    PendingHashChallenge, PendingIndex, Scheduler, SchedulerConfig, holder_trust_map,
};

fn challenge(block: SourceBlockId, holder: DeviceId, cid: [u8; 16]) -> PendingHashChallenge {
    PendingHashChallenge {
        source_block_id: block,
        holder_id: holder,
        esi_ranges: vec![(0, 1)],
        expected_chain_hash: [0u8; 32],
        issued_at: Timestamp::now(),
        challenge_id: cid,
        holder_master: IdentityPub(holder.0),
    }
}

/// Block `i` / challenge id `i`: distinct for every u32.
fn block_of(i: u32) -> SourceBlockId {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&i.to_le_bytes());
    SourceBlockId(id)
}

fn cid_of(i: u32) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..4].copy_from_slice(&i.to_le_bytes());
    id
}

// ─── PendingIndex (INV-9) ─────────────────────────────────────────────────────

#[test]
fn pending_index_insert_replaces_and_unindexes_old_challenge() {
    let (block, holder) = (block_of(1), make_identity(2));
    let key = (block, holder);
    let mut index = PendingIndex::default();

    assert!(
        index
            .insert(key, challenge(block, holder, [0xA1; 16]))
            .is_none()
    );
    let old = index
        .insert(key, challenge(block, holder, [0xB2; 16]))
        .expect("the older challenge of the key is returned");

    assert_eq!(old.challenge_id, [0xA1; 16]);
    assert_eq!(index.len(), 1);
    assert_eq!(index.key_of(&[0xA1; 16]), None, "the old id is unindexed");
    assert!(!index.contains_challenge(&[0xA1; 16]));
    assert_eq!(index.key_of(&[0xB2; 16]), Some(key));
    assert_eq!(index.get(&key).unwrap().challenge_id, [0xB2; 16]);
}

#[test]
fn pending_index_remove_unindexes_challenge() {
    let (block, holder) = (block_of(1), make_identity(2));
    let key = (block, holder);
    let other = (block_of(2), holder);
    let mut index = PendingIndex::default();
    index.insert(key, challenge(block, holder, [0xA1; 16]));
    index.insert(other, challenge(other.0, holder, [0xC3; 16]));

    let removed = index.remove(&key).expect("pending");

    assert_eq!(removed.challenge_id, [0xA1; 16]);
    assert!(!index.contains_key(&key));
    assert!(!index.contains_challenge(&[0xA1; 16]));
    assert_eq!(index.key_of(&[0xA1; 16]), None);
    assert_eq!(
        index.key_of(&[0xC3; 16]),
        Some(other),
        "the other entry stays"
    );
    assert_eq!(index.len(), 1);
    assert!(index.remove(&key).is_none());
}

/// pos-i7: the scheduler finds the pending challenge of a response through the
/// challenge_id index. 50 000 pending challenges, 50 000 responses: a linear scan per
/// response is ~2.5·10⁹ comparisons (seconds); the index is milliseconds. The responses
/// are to challenges not pending (the worst case of a scan: it reads everything) and
/// leave the pending untouched.
#[tokio::test]
async fn pending_lookup_by_challenge_id_is_indexed() {
    const N: u32 = 50_000;
    let holder = make_identity(7);
    let pending = make_pending_challenges();
    {
        let mut index = pending.lock().await;
        for i in 0..N {
            index.insert(
                (block_of(i), holder),
                challenge(block_of(i), holder, cid_of(i)),
            );
        }
        assert_eq!(
            index.key_of(&cid_of(12_345)),
            Some((block_of(12_345), holder))
        );
    }
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let scheduler = make_scheduler_for_hook(
        Db::open_in_memory().expect("db"),
        repair_tx,
        pending.clone(),
    );

    let started = std::time::Instant::now();
    for i in N..2 * N {
        let response = viaticum_core::messages::PosHashResponseMsg {
            v: 1,
            challenge_id: cid_of(i),
            source_block_id: block_of(i),
            chain_hash: [0u8; 32],
            timestamp: Timestamp::now(),
            device_id: None,
            sig: [0u8; 64],
        };
        scheduler
            .handle_pos_response_from_mailbox(response)
            .await
            .expect("an unknown challenge is not an error");
    }
    let elapsed = started.elapsed();

    assert_eq!(pending.lock().await.len(), N as usize, "pending untouched");
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "{N} lookups among {N} pending took {elapsed:?} (must be indexed)"
    );
}

// ─── Trust once per holder (5b) ───────────────────────────────────────────────

#[test]
fn holder_trust_map_calls_f_once_per_holder() {
    let holders = [make_identity(1), make_identity(2), make_identity(3)];
    let placements: Vec<_> = (0..4u32)
        .flat_map(|b| holders.iter().map(move |h| make_placement(block_of(b), *h)))
        .collect();
    let calls = Cell::new(0u32);

    let trust = holder_trust_map(&placements, |h| {
        calls.set(calls.get() + 1);
        f64::from(h.0[0]) / 10.0
    });

    assert_eq!(
        calls.get(),
        3,
        "one trust read per holder, not per placement"
    );
    assert_eq!(trust.len(), 3);
    assert_eq!(trust[&make_identity(2)], 0.2);
}

// ─── The issue-tick line (pos-i7 observable) ──────────────────────────────────

#[derive(Clone, Default)]
struct LogBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// The integer value of `field=` in `line`.
fn field(line: &str, name: &str) -> Option<u64> {
    line.split_whitespace()
        .find_map(|w| w.strip_prefix(&format!("{name}=")))
        .and_then(|v| v.parse().ok())
}

/// pos-i7: a tick with due challenges ends with `scheduler: PoS issue tick` carrying
/// due / issued / skipped_pending / zero_ack / elapsed_ms / cpw_min / cpw_max; the line
/// of each issued challenge carries its challenge_id (the one put in pending) and cpw.
#[tokio::test]
async fn issue_tick_line_reports_due_issued_and_cpw() {
    let db = Db::open_in_memory().expect("db open");
    let data_dir = tempfile::TempDir::new().unwrap();
    let block_id = seed_retained_pos_block(data_dir.path(), &db, 0xB1);
    let (h1, h2) = (make_identity(0xB2), make_identity(0xB3));
    for h in [h1, h2] {
        db.upsert_placement(&make_placement(block_id, h)).unwrap();
        db.upsert_peer(&make_peer_record(h)).unwrap();
    }
    // A postman with a real Ed25519 id, so the challenge publish gets an Ack.
    let postman = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
    db.upsert_peer(&make_peer_record(DeviceId(
        postman.verifying_key().to_bytes(),
    )))
    .unwrap();
    let pending = make_pending_challenges();
    pending
        .lock()
        .await
        .insert((block_id, h2), challenge(block_id, h2, [0xC2; 16]));

    let router = Arc::new(MailboxRouter::with_sender(
        Arc::new(RecordingMailboxSender::new()) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let scheduler = Scheduler::new(
        db.clone(),
        SchedulerConfig {
            pos_interval_secs: 3600,
            timeout_check_secs: 3600,
            time_scale: 1,
            event_log_retain_rows: 100_000,
            pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
        },
        repair_tx,
        pending.clone(),
        router,
        dummy_master_pub(),
        ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        data_dir.path().to_path_buf(),
    );

    let buf = LogBuf::default();
    let writer = buf.clone();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish(),
    );
    tracing::instrument::WithSubscriber::with_subscriber(
        scheduler.issue_due_challenges(),
        dispatch,
    )
    .await
    .expect("issue_due_challenges");

    let logs = buf.text();
    let tick = logs
        .lines()
        .find(|l| l.contains("scheduler: PoS issue tick"))
        .unwrap_or_else(|| panic!("no issue tick line; logs:\n{logs}"));
    assert_eq!(field(tick, "due"), Some(2), "{tick}");
    assert_eq!(field(tick, "issued"), Some(1), "{tick}");
    assert_eq!(field(tick, "skipped_pending"), Some(1), "{tick}");
    assert_eq!(field(tick, "zero_ack"), Some(0), "{tick}");
    assert!(field(tick, "elapsed_ms").is_some(), "{tick}");
    let cpw = field(tick, "cpw_min").expect("cpw_min");
    assert!(cpw >= 1, "{tick}");
    assert_eq!(
        field(tick, "cpw_max"),
        Some(cpw),
        "both placements alike: {tick}"
    );

    let h1_cid = pending
        .lock()
        .await
        .get(&(block_id, h1))
        .expect("h1 challenged")
        .challenge_id;
    let issued = logs
        .lines()
        .find(|l| l.contains("PoS hash challenge issued via mailbox"))
        .unwrap_or_else(|| panic!("no issued line; logs:\n{logs}"));
    assert!(
        issued.contains(&format!("challenge_id={}", hex_encode(&h1_cid))),
        "{issued}"
    );
    assert_eq!(field(issued, "cpw"), Some(cpw), "{issued}");
}
