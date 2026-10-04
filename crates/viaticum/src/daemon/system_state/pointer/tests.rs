// Pointer publisher: two places per history (CROWN-1 V.15.3, V.15.5, V.16.5, V.17;
// mailbox-i46, i47, i50..i56, dr-i48). Real redb for the owner and for every postman
// (`InProcessPostmanNet` runs the real postman handlers); a gate decides which postmen
// answer.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use viaticum_core::db::Db;
use viaticum_core::db::testutil::{test_db, test_db_with_write_switch};
use viaticum_core::mailbox::MailboxEntry;
use viaticum_core::mailbox::seal::{PointerPlace, RendezvousKeys, open_self_pointer};
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::system_state::catalog::{
    PlacePublication, PointerPublications, RefusalKind, WaitingReason,
};
use viaticum_core::system_state::{CatalogLineageId, SelfPointer};
use viaticum_core::types::{
    DeviceId, FileId, IdentityPub, PeerRecord, PlacementStatus, SourceBlockId, SourceBlockRecord,
    SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp, from_cbor_bytes, to_cbor_bytes,
};

use super::{PointerPublisher, RunningState};
use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};
use crate::daemon::mailbox::test_postman::InProcessPostmanNet;
use crate::daemon::system_state::pointer_refresh_interval_secs;
use crate::daemon::system_state::publish::PointerCatalog;

const SEED: [u8; 64] = [0x5E; 64];
const LINEAGE: CatalogLineageId = CatalogLineageId([0x4C; 16]);

// ─── Fixture ───────────────────────────────────────────────────────────────────

/// Real postmen behind a gate: `answering = None` → all answer; `Some(set)` → only
/// those (others fail at the network level). Records every store and whether the
/// owner's META already held this exact envelope as `current` when it was sent.
/// `delays`: a postman listed answers after `Some(secs)` of virtual time, or sleeps
/// (`None`: no answer for 10 minutes); unlisted postmen answer at once.
struct Gate {
    inner: InProcessPostmanNet,
    owner_db: Db,
    answering: Mutex<Option<HashSet<DeviceId>>>,
    delays: Mutex<HashMap<DeviceId, Option<u64>>>,
    sent: Mutex<Vec<(DeviceId, MailboxEntry)>>,
    meta_before_send: Mutex<Vec<bool>>,
}

#[async_trait]
impl MailboxNetworkSender for Gate {
    async fn send_store(
        &self,
        device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        let in_meta = self
            .owner_db
            .pointer_publications()
            .unwrap()
            .is_some_and(|m| {
                [m.current, m.other]
                    .into_iter()
                    .flatten()
                    .any(|r| r.entry_cbor == to_cbor_bytes(&req.entry))
            });
        self.meta_before_send.lock().unwrap().push(in_meta);
        self.sent.lock().unwrap().push((device, req.entry.clone()));
        let open = match self.answering.lock().unwrap().as_ref() {
            None => true,
            Some(set) => set.contains(&device),
        };
        if !open {
            anyhow::bail!("postman {device} unreachable");
        }
        let delay = self.delays.lock().unwrap().get(&device).copied();
        match delay {
            None => {}
            Some(Some(s)) => tokio::time::sleep(std::time::Duration::from_secs(s)).await,
            Some(None) => {
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                anyhow::bail!("postman {device} asleep");
            }
        }
        self.inner.send_store(device, req).await
    }

    async fn send_fetch(
        &self,
        device: DeviceId,
        req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        self.inner.send_fetch(device, req).await
    }
}

struct Fx {
    db: Db,
    dir: tempfile::TempDir,
    gate: Arc<Gate>,
    router: MailboxRouter,
    master: ed25519_dalek::SigningKey,
    rv: RendezvousKeys,
    devices: Vec<DeviceId>,
}

fn gen_device_id() -> DeviceId {
    use libp2p::identity::Keypair;
    let ed = Keypair::generate_ed25519().try_into_ed25519().unwrap();
    DeviceId(ed.public().to_bytes())
}

fn peer(device: DeviceId, seen: u64) -> PeerRecord {
    PeerRecord {
        device_id: device,
        master_identity: IdentityPub(device.0),
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1),
        last_seen: Timestamp(seen),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    }
}

/// `n` postmen (also the holders of SS blocks), all known peers of the owner.
fn fx(n: usize) -> Fx {
    fx_on(test_db(), n)
}

fn fx_on(db: Db, n: usize) -> Fx {
    let master = viaticum_core::cluster::derive_master_key(&SEED).unwrap();
    let me = viaticum_core::cluster::master_identity(&master);
    let devices: Vec<DeviceId> = (0..n).map(|_| gen_device_id()).collect();
    for d in &devices {
        db.upsert_peer(&peer(*d, Timestamp::now().0)).unwrap();
    }
    let gate = Arc::new(Gate {
        inner: InProcessPostmanNet::new(&devices, me, devices[0]),
        owner_db: db.clone(),
        answering: Mutex::new(None),
        delays: Mutex::new(HashMap::new()),
        sent: Mutex::new(vec![]),
        meta_before_send: Mutex::new(vec![]),
    });
    let router = MailboxRouter::with_sender(
        Arc::clone(&gate) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    );
    Fx {
        db,
        dir: tempfile::tempdir().unwrap(),
        gate,
        router,
        master,
        rv: RendezvousKeys::derive(&SEED),
        devices,
    }
}

impl Fx {
    fn publisher(&self) -> PointerPublisher<'_> {
        PointerPublisher {
            db: &self.db,
            router: &self.router,
            master_key: &self.master,
            rv: &self.rv,
            data_dir: self.dir.path(),
            time_scale: 1,
        }
    }

    /// An SS block (in the ledger) held by the first `holders` postmen, one copy each.
    fn block(&self, id: u8, holders: usize) -> SourceBlockId {
        let block_id = SourceBlockId([id; 32]);
        self.db
            .upsert_source_block(&SourceBlockRecord {
                seal_generation: 0,
                block_id,
                k: 1,
                t: 64,
                block_type: SourceBlockType::Single,
                status: SourceBlockStatus::Active,
                created_at: Timestamp(1),
                encrypted_size: Some(64),
                n: Some(12),
                overhead: Some(3.0),
                drop_notice_sent_at: None,
                importance: 1.0,
                current_alive: 0,
                current_reliability: 0.0,
                target_reliability: 0.99,
            })
            .unwrap();
        self.db.mark_ss_block(&block_id, 1).unwrap();
        for (i, d) in self.devices.iter().take(holders).enumerate() {
            self.db
                .upsert_placement(&SymbolPlacement {
                    source_block_id: block_id,
                    holder_id: *d,
                    file_id: FileId(0),
                    esi_ranges: vec![(i as u32 * 4, 4)],
                    binding_seed: [0; 32],
                    status: PlacementStatus::Alive,
                    last_verified: None,
                    placed_at: Timestamp(1),
                    consecutive_misses: 0,
                })
                .unwrap();
        }
        block_id
    }

    /// Only the first `k` postmen answer (`None` = all).
    fn answering(&self, k: Option<usize>) {
        *self.gate.answering.lock().unwrap() =
            k.map(|k| self.devices.iter().take(k).copied().collect());
    }

    async fn tick(&self, generation: u32, base: &SourceBlockId, diffs: &[SourceBlockId], now: u64) {
        self.tick_with(&self.publisher(), generation, base, diffs, now)
            .await;
    }

    async fn tick_with(
        &self,
        p: &PointerPublisher<'_>,
        generation: u32,
        base: &SourceBlockId,
        diffs: &[SourceBlockId],
        now: u64,
    ) {
        let files: Vec<u32> = vec![1; diffs.len() + 1];
        p.tick(
            RunningState {
                generation,
                base,
                diffs,
                catalog: PointerCatalog {
                    lineage: LINEAGE,
                    publisher: DeviceId([0xD1; 32]),
                    files_after: &files,
                },
            },
            now,
        )
        .await;
    }

    fn meta(&self) -> PointerPublications {
        self.db
            .pointer_publications()
            .unwrap()
            .expect("META written")
    }

    fn sent(&self) -> Vec<(DeviceId, MailboxEntry)> {
        self.gate.sent.lock().unwrap().clone()
    }

    fn in_ledger(&self, b: &SourceBlockId) -> bool {
        self.db.is_ss_block(b).unwrap()
    }

    /// The SelfPointer entries a postman holds for the rendezvous box.
    fn held_at(&self, i: usize) -> Vec<MailboxEntry> {
        self.gate
            .inner
            .postman(&self.devices[i])
            .db
            .mailbox_list_for_target(&self.rv.address, 0)
            .unwrap()
    }

    fn slot(&self, place: PointerPlace) -> [u8; 16] {
        self.rv.pointer_slot(&LINEAGE.0, place)
    }

    fn opened(&self, e: &MailboxEntry) -> SelfPointer {
        from_cbor_bytes(&open_self_pointer(&self.rv, e).unwrap()).unwrap()
    }
}

fn now() -> u64 {
    Timestamp::now().0
}

fn place_of(r: &Option<PlacePublication>) -> Option<PointerPlace> {
    r.as_ref().map(|r| r.place)
}

// ─── Places ──────────────────────────────────────────────────────────────────

/// V.6 publisher row: sealed, in the rendezvous box, `msg_id` = the place slot.
#[tokio::test]
async fn published_pointer_goes_to_rendezvous_box_with_slot_msg_id() {
    let f = fx(3);
    let b1 = f.block(1, 3);
    f.tick(1, &b1, &[], now()).await;
    let held = f.held_at(0);
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].msg_id, f.slot(PointerPlace::A));
    assert_eq!(held[0].sender, None);
    assert_eq!(f.opened(&held[0]).base.block_id, b1);
    let m = f.meta();
    assert_eq!(place_of(&m.current), Some(PointerPlace::A));
    assert_eq!(m.current.as_ref().unwrap().acks.len(), 3);
}

#[tokio::test]
async fn diff_pointer_of_same_base_replaces_its_own_place() {
    let f = fx(3);
    let b1 = f.block(1, 3);
    let t = now();
    f.tick(1, &b1, &[], t).await;
    let d1 = f.block(2, 3);
    f.tick(1, &b1, &[d1], t + 1).await;
    let m = f.meta();
    let cur = m.current.unwrap();
    assert_eq!(
        (cur.place, cur.base, cur.diffs.clone()),
        (PointerPlace::A, b1, vec![d1])
    );
    assert!(m.other.is_none(), "a diff never takes the other place");
    let held = f.held_at(1);
    assert_eq!(held.len(), 1, "one entry: the place was replaced");
    assert_eq!(f.opened(&held[0]).diffs.len(), 1);
}

/// A new base (compaction) takes the empty place; the old base stays in the other.
#[tokio::test]
async fn new_base_goes_to_the_empty_place_first() {
    let f = fx(3);
    let b1 = f.block(1, 3);
    let t = now();
    f.tick(1, &b1, &[], t).await;
    let b2 = f.block(2, 1);
    f.tick(2, &b2, &[], t + 1).await;
    let m = f.meta();
    assert_eq!(place_of(&m.current), Some(PointerPlace::B));
    assert_eq!(m.current.as_ref().unwrap().base, b2);
    assert_eq!(m.other.as_ref().unwrap().base, b1);
    assert_eq!(f.held_at(0).len(), 2, "both places at the postman");
    assert!(
        f.in_ledger(&b1),
        "the old base is kept while a place refers to it"
    );
}

#[tokio::test]
async fn two_weak_bases_in_a_row_keep_the_strong_one() {
    let f = fx(5);
    let strong = f.block(1, 5);
    let t = now();
    f.tick(1, &strong, &[], t).await;
    let weak1 = f.block(2, 1);
    f.tick(2, &weak1, &[], t + 1).await;
    let weak2 = f.block(3, 1);
    f.tick(3, &weak2, &[], t + 2).await;
    let m = f.meta();
    assert_eq!(m.current.as_ref().unwrap().base, weak2);
    assert_eq!(
        m.other.as_ref().unwrap().base,
        strong,
        "the strong base survives"
    );
    assert_eq!(m.current.as_ref().unwrap().place, PointerPlace::B);
    let bases: HashSet<SourceBlockId> = f
        .held_at(0)
        .iter()
        .map(|e| f.opened(e).base.block_id)
        .collect();
    assert_eq!(bases, HashSet::from([strong, weak2]));
}

/// V.16.1 п.1: a restart resets `generation` to 1; the place is chosen by strength,
/// never by generation, so the new base goes to the weaker place.
#[tokio::test]
async fn restart_new_base_never_replaces_the_stronger_place() {
    let f = fx(5);
    let weak = f.block(1, 1);
    let t = now();
    f.tick(2, &weak, &[], t).await; // A
    let strong = f.block(2, 5);
    f.tick(3, &strong, &[], t + 1).await; // B
    // Restart: a new process (new publisher), generation 1, a new base.
    let restarted = f.publisher();
    let fresh = f.block(3, 1);
    f.tick_with(&restarted, 1, &fresh, &[], t + 2).await;
    let m = f.meta();
    assert_eq!(m.current.as_ref().unwrap().base, fresh);
    assert_eq!(
        m.current.as_ref().unwrap().place,
        PointerPlace::A,
        "the weak place"
    );
    assert_eq!(m.other.as_ref().unwrap().base, strong);
}

/// V.16.4 п.2: META (the record with its envelope) is written BEFORE the send, so a
/// crash after the send never leaves an envelope in the network that META does not know.
#[tokio::test]
async fn meta_place_recorded_before_publish() {
    let f = fx(3);
    let b1 = f.block(1, 3);
    f.tick(1, &b1, &[], now()).await;
    let seen = f.gate.meta_before_send.lock().unwrap().clone();
    assert!(!seen.is_empty());
    assert!(
        seen.iter().all(|x| *x),
        "every send found its envelope in META first"
    );
}

/// mailbox-i59: META that cannot be written means nothing leaves the tick — neither the
/// new envelope nor a re-offer of the one waiting for acks.
#[tokio::test]
async fn meta_write_failure_skips_the_whole_tick() {
    let (db, fail) = test_db_with_write_switch();
    let f = fx_on(db, 6); // threshold 3
    let b1 = f.block(1, 6);
    f.answering(Some(1));
    let t = now();
    f.tick(1, &b1, &[], t).await;
    let b2 = f.block(2, 6); // a compaction; written while the disk still works
    assert_eq!(
        f.meta().current.as_ref().unwrap().acks.len(),
        1,
        "b1 waits for re-offers"
    );
    let before = f.meta();
    let sent = f.sent().len();
    fail.store(true, std::sync::atomic::Ordering::SeqCst);
    f.answering(None);
    f.tick(2, &b2, &[], t + 1).await;
    assert_eq!(
        f.sent().len(),
        sent,
        "META not written: no new envelope, no re-offer"
    );
    fail.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(f.meta(), before, "META on disk is what it was");
}

/// mailbox-i58: the record of the other place is not refreshed by new catalog states;
/// before its envelope expires the SAME signed pointer (same created_at) is sealed
/// again with a new stored_at / expires_at and sent to the postmen.
#[tokio::test]
async fn other_place_is_resealed_with_the_same_pointer_before_expiry() {
    use viaticum_core::mailbox::MailboxEntry;
    let f = fx(3);
    let ts = 100_000;
    let p = PointerPublisher {
        time_scale: ts,
        ..f.publisher()
    };
    let refresh = pointer_refresh_interval_secs(ts);
    let b1 = f.block(1, 3);
    let t = now();
    f.tick_with(&p, 1, &b1, &[], t).await; // A
    let b2 = f.block(2, 3);
    f.tick_with(&p, 2, &b2, &[], t + 1).await; // B; b1 stays in A as `other`
    let before = f.meta().other.expect("b1 in the other place");
    assert_eq!((before.place, before.base), (PointerPlace::A, b1));
    let old: MailboxEntry = from_cbor_bytes(&before.entry_cbor).unwrap();
    let old_pointer = to_cbor_bytes(&f.opened(&old));

    f.tick_with(&p, 2, &b2, &[], t + refresh - 1).await;
    assert_eq!(
        f.meta().other.unwrap().entry_cbor,
        before.entry_cbor,
        "not due yet: the envelope is untouched"
    );

    f.tick_with(&p, 2, &b2, &[], t + refresh).await;
    let other = f.meta().other.expect("still in META");
    assert_eq!((other.place, other.base), (PointerPlace::A, b1));
    assert_eq!(
        other.created_at, before.created_at,
        "the pointer is not rebuilt"
    );
    let new: MailboxEntry = from_cbor_bytes(&other.entry_cbor).unwrap();
    assert_eq!(new.stored_at, t + refresh);
    assert!(new.expires_at > old.expires_at, "a later expiry");
    assert_eq!(new.msg_id, f.slot(PointerPlace::A));
    assert_eq!(
        to_cbor_bytes(&f.opened(&new)),
        old_pointer,
        "the same signed pointer inside"
    );
    assert_eq!(other.acks.len(), 3, "the new envelope was sent this tick");
    let held: Vec<MailboxEntry> = f
        .held_at(2)
        .into_iter()
        .filter(|e| e.msg_id == f.slot(PointerPlace::A))
        .collect();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].stored_at, t + refresh, "the postman replaced it");
    assert_eq!(to_cbor_bytes(&f.opened(&held[0])), old_pointer);
}

/// dr-i39, mailbox-i60: the fresh envelope's send returns only once the threshold of
/// postmen acked, and META records exactly those acks — not the first one.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn pointer_publish_waits_for_threshold_acks_before_writing_meta() {
    use crate::daemon::system_state::strength::readiness_ack_threshold;
    let f = fx(5);
    assert_eq!(readiness_ack_threshold(f.devices.len()), 3);
    let b1 = f.block(1, 5);
    *f.gate.delays.lock().unwrap() = HashMap::from([
        (f.devices[0], Some(0)),
        (f.devices[1], Some(1)),
        (f.devices[2], Some(2)),
        (f.devices[3], None),
        (f.devices[4], None),
    ]);
    let start = tokio::time::Instant::now();
    f.tick(1, &b1, &[], now()).await;
    assert_eq!(
        start.elapsed(),
        std::time::Duration::from_secs(2),
        "returns at the third ack"
    );
    let cur = f.meta().current.expect("current written");
    assert_eq!(cur.acks.len(), 3, "the threshold of acks, not the first");
    let acked: HashSet<DeviceId> = cur.acks.iter().copied().collect();
    assert_eq!(acked, f.devices.iter().take(3).copied().collect());
}

// ─── Retirement (V.17.2, V.16.4 п.5-6) ────────────────────────────────────────

/// META by hand: A = `a` (acked by 3), B = strong `b0` (acked by 3).
fn two_places(f: &Fx, a: SourceBlockId, b0: SourceBlockId) {
    let rec = |place, base, at| PlacePublication {
        place,
        base,
        diffs: vec![],
        generation: 1,
        created_at: Timestamp(at),
        files: 1,
        acks: f.devices.iter().take(3).copied().collect(),
        entry_cbor: vec![],
        target_sig: [0; 64],
        last_refusal: None,
        to_retire: vec![],
        reached: None,
    };
    let mut m = PointerPublications::new(LINEAGE);
    m.current = Some(rec(PointerPlace::A, a, 20));
    m.other = Some(rec(PointerPlace::B, b0, 10));
    f.db.put_pointer_publications(&m).unwrap();
}

#[tokio::test]
async fn replaced_base_retired_only_after_threshold_acks() {
    let f = fx(6); // threshold 3
    let b0 = f.block(1, 6);
    let base1 = f.block(2, 1);
    two_places(&f, base1, b0);
    let base2 = f.block(3, 1);
    f.answering(Some(1));
    let t = now();
    f.tick(1, &base2, &[], t).await;
    let m = f.meta();
    assert_eq!(
        m.current.as_ref().unwrap().place,
        PointerPlace::A,
        "base1 was the weaker"
    );
    assert_eq!(m.current.as_ref().unwrap().acks.len(), 1);
    assert!(
        f.in_ledger(&base1),
        "1 ack < threshold: the displaced base stays"
    );
    f.answering(None);
    f.tick(1, &base2, &[], t + 1).await;
    assert!(f.meta().current.as_ref().unwrap().acks.len() >= 3);
    assert!(
        !f.in_ledger(&base1),
        "threshold reached: the displaced base is retired"
    );
    assert!(f.in_ledger(&b0) && f.in_ledger(&base2));
}

#[tokio::test]
async fn third_base_in_a_place_before_threshold_retires_both_predecessors_once_threshold_reached() {
    let f = fx(6);
    let b0 = f.block(1, 6);
    let base1 = f.block(2, 1);
    two_places(&f, base1, b0);
    f.answering(Some(1));
    let t = now();
    let base2 = f.block(3, 1);
    f.tick(1, &base2, &[], t).await; // A: base1 displaced, waits
    let base3 = f.block(4, 1);
    f.tick(2, &base3, &[], t + 1).await; // A again: base2 displaced
    let m = f.meta();
    assert_eq!(m.current.as_ref().unwrap().base, base3);
    assert_eq!(m.current.as_ref().unwrap().place, PointerPlace::A);
    assert_eq!(m.other.as_ref().unwrap().base, b0);
    assert!(
        !f.in_ledger(&base1),
        "the place was replaced twice: the oldest goes at once"
    );
    assert!(
        f.in_ledger(&base2),
        "the younger displaced base waits for the threshold"
    );
    assert_eq!(m.current.as_ref().unwrap().to_retire.len(), 1);
    f.answering(None);
    f.tick(2, &base3, &[], t + 2).await;
    assert!(
        !f.in_ledger(&base2),
        "threshold reached: both predecessors are gone"
    );
    assert!(f.meta().current.as_ref().unwrap().to_retire.is_empty());
}

/// V.16.4 п.5: a base of this process that never became a pointer (no live holder) is
/// retired at the next compaction.
#[tokio::test]
async fn unpublished_candidate_retired_at_next_compaction() {
    let f = fx(3);
    let b1 = f.block(1, 3);
    let t = now();
    f.tick(1, &b1, &[], t).await;
    let unplaced = f.block(2, 0);
    f.tick(2, &unplaced, &[], t + 1).await;
    assert!(f.in_ledger(&unplaced), "the running candidate is kept");
    let next = f.block(3, 3);
    f.tick(3, &next, &[], t + 2).await;
    assert!(!f.in_ledger(&unplaced), "never published: retired");
    assert!(f.in_ledger(&b1) && f.in_ledger(&next));
}

/// V.16.4 п.6 (dr-i48): on start everything in the SS ledger that no pointer place (nor
/// a waiting retirement) refers to is retired; the accepted pointers' blocks stay.
#[tokio::test]
async fn startup_retires_ss_blocks_not_in_accepted_pointer() {
    let f = fx(3);
    let b1 = f.block(1, 3);
    let d1 = f.block(2, 3);
    f.tick(1, &b1, &[d1], now()).await;
    assert!(f.in_ledger(&d1));
    let orphan_base = f.block(3, 3);
    let orphan_diff = f.block(4, 0);
    f.publisher().startup_sweep();
    assert!(f.in_ledger(&b1) && f.in_ledger(&d1));
    assert!(!f.in_ledger(&orphan_base) && !f.in_ledger(&orphan_diff));
    assert!(f.db.get_source_block(&orphan_base).unwrap().is_none());
}

// ─── Re-offer (i47, i53) ───────────────────────────────────────────────────────

#[tokio::test]
async fn reoffer_uses_identical_sealed_bytes_until_threshold() {
    let f = fx(6);
    let b1 = f.block(1, 6);
    f.answering(Some(1));
    let t = now();
    f.tick(1, &b1, &[], t).await;
    let first: Vec<MailboxEntry> = f.sent().into_iter().map(|(_, e)| e).collect();
    f.answering(Some(2));
    f.tick(1, &b1, &[], t + 1).await;
    let second: Vec<MailboxEntry> = f
        .sent()
        .into_iter()
        .skip(first.len())
        .map(|(_, e)| e)
        .collect();
    assert!(
        !second.is_empty(),
        "acks 1 < 3: the envelope is offered again"
    );
    assert!(
        second.iter().all(|e| *e == first[0]),
        "byte-identical re-offer"
    );
    assert_eq!(
        f.meta().current.as_ref().unwrap().acks.len(),
        2,
        "distinct postmen"
    );
    f.answering(Some(3));
    f.tick(1, &b1, &[], t + 2).await;
    assert_eq!(f.meta().current.as_ref().unwrap().acks.len(), 3);
    let before = f.sent().len();
    f.tick(1, &b1, &[], t + 3).await;
    assert_eq!(
        f.sent().len(),
        before,
        "threshold reached: no more re-offers"
    );
}

#[tokio::test]
async fn reoffer_after_restart_uses_meta_envelope_bytes() {
    let f = fx(6);
    let b1 = f.block(1, 6);
    f.answering(Some(1));
    let t = now();
    f.tick(1, &b1, &[], t).await;
    let envelope = f.sent()[0].1.clone();
    // Restart: the new process's base is not placed yet (no pointer to build).
    let restarted = f.publisher();
    let unplaced = f.block(2, 0);
    let n = f.sent().len();
    f.answering(None);
    f.tick_with(&restarted, 1, &unplaced, &[], t + 1).await;
    let after: Vec<MailboxEntry> = f.sent().into_iter().skip(n).map(|(_, e)| e).collect();
    assert!(!after.is_empty());
    assert!(
        after.iter().all(|e| *e == envelope),
        "the envelope from META, byte-identical"
    );
    assert!(f.meta().current.as_ref().unwrap().acks.len() >= 3);
}

// ─── Refusals and waiting (V.15.3, V.16.4 п.7) ────────────────────────────────

#[tokio::test]
async fn refusal_is_recorded_per_place_and_cleared_by_an_ack() {
    let f = fx(3);
    let b1 = f.block(1, 3);
    f.answering(Some(0));
    let t = now();
    f.tick(1, &b1, &[], t).await;
    let m = f.meta();
    let cur = m.current.as_ref().unwrap();
    assert!(cur.acks.is_empty());
    assert_eq!(cur.last_refusal.map(|r| r.kind), Some(RefusalKind::NoAck));
    assert_eq!(
        m.newest_accepted(),
        None,
        "dr-i9: a pointer nobody accepted is not a publication"
    );
    assert_eq!(
        m.waiting.map(|w| (w.since, w.reason)),
        Some((t, WaitingReason::NoAck))
    );
    f.answering(None);
    f.tick(1, &b1, &[], t + 5).await;
    let m = f.meta();
    assert_eq!(
        m.current.as_ref().unwrap().last_refusal,
        None,
        "successful_publication_clears_last_refusal"
    );
    assert_eq!(m.waiting, None);
}

#[tokio::test]
async fn waiting_since_set_while_newest_state_unpublished_and_cleared_on_accept() {
    let f = fx(3);
    let b1 = f.block(1, 3);
    let t = now();
    f.tick(1, &b1, &[], t).await;
    assert_eq!(f.meta().waiting, None);
    // A new diff that no holder has yet: the newest state is not in the network.
    let d1 = f.block(2, 0);
    f.tick(1, &b1, &[d1], t + 10).await;
    assert_eq!(
        f.meta().waiting.map(|w| (w.since, w.reason)),
        Some((t + 10, WaitingReason::BlocksNotPlaced))
    );
    f.tick(1, &b1, &[d1], t + 20).await;
    assert_eq!(
        f.meta().waiting.map(|w| w.since),
        Some(t + 10),
        "since is kept"
    );
    // The diff places: published and acked → the wait ends.
    let placed = f.block(2, 3);
    assert_eq!(placed, d1);
    f.tick(1, &b1, &[d1], t + 30).await;
    assert_eq!(f.meta().waiting, None);
}

/// Edge (reported): an envelope every postman refused as clock skew is not re-offered
/// forever — the next tick seals a new one with the current clock.
#[tokio::test]
async fn clock_refused_envelope_is_resealed_not_reoffered() {
    let f = fx(3);
    let b1 = f.block(1, 3);
    // A clock 2 days ahead: stored_at > postman now + 24 h → ClockSkew everywhere.
    let ahead = now() + 2 * 24 * 3600;
    f.tick(1, &b1, &[], ahead).await;
    let m = f.meta();
    assert_eq!(
        m.current.as_ref().unwrap().last_refusal.map(|r| r.kind),
        Some(RefusalKind::ClockSkew)
    );
    let t = now();
    f.tick(1, &b1, &[], t).await;
    let cur = f.meta().current.unwrap();
    assert_eq!(cur.created_at.0, t, "re-sealed with the corrected clock");
    assert_eq!(cur.acks.len(), 3);
}

/// mailbox-i61: an envelope that every postman refused as expired in transit is not a
/// clock verdict (status must not say "this computer's clock looks wrong"), and it is
/// sealed anew next tick like a clock-skew refusal, not re-offered as is.
#[tokio::test]
async fn publisher_does_not_blame_clock_for_expired() {
    use viaticum_core::mailbox::class_config;
    let f = fx(3);
    let b1 = f.block(1, 3);
    let ttl = class_config::SELF_POINTER_TTL.as_secs();
    // The envelope's 5-year life ends 10 s before the postmen's now: inside the
    // transit window (60 s), so every postman answers `Expired`.
    let p = now() - ttl - 10;
    f.tick(1, &b1, &[], p).await;
    let cur = f.meta().current.unwrap();
    assert!(cur.acks.is_empty());
    let refusal = cur.last_refusal.expect("refused");
    assert_ne!(
        refusal.kind,
        RefusalKind::ClockSkew,
        "the clock is not blamed"
    );
    assert_eq!(refusal.kind, RefusalKind::NoAck);
    assert!(refusal.expired);
    let first = cur.entry_cbor.clone();
    let n = f.sent().len();
    // Next tick, nothing changed and no refresh due: a new envelope, not a re-offer.
    f.tick(1, &b1, &[], p + 1).await;
    let cur = f.meta().current.unwrap();
    assert_ne!(cur.entry_cbor, first, "sealed anew");
    assert_eq!(cur.created_at.0, p + 1);
    assert!(
        f.sent()
            .iter()
            .skip(n)
            .all(|(_, e)| to_cbor_bytes(e) != first),
        "the dead envelope is not re-offered"
    );
}

/// mailbox-i62: two changes of the pointer within one second (a burst of ticks after
/// SIGCONT) must not put two different envelopes with one `stored_at` into a place —
/// the postmen keep the first and refuse the second as `Superseded` (equal time), the
/// refused one is re-offered as is, and status says "the clock went back". The second
/// change waits for the next second and is then accepted by every postman.
#[tokio::test]
async fn second_change_in_the_same_second_waits_for_the_next_second() {
    let f = fx(3);
    let b1 = f.block(1, 3);
    let t = now();
    f.tick(1, &b1, &[], t).await;
    let first = f.meta().current.unwrap();
    assert_eq!(first.acks.len(), 3);
    let d1 = f.block(2, 3);
    let n = f.sent().len();
    f.tick(1, &b1, &[d1], t).await; // the same second
    let cur = f.meta().current.unwrap();
    assert!(
        f.sent()
            .iter()
            .skip(n)
            .all(|(_, e)| to_cbor_bytes(e) == first.entry_cbor),
        "no second envelope sealed at the same stored_at"
    );
    assert_eq!(
        cur.entry_cbor, first.entry_cbor,
        "the place keeps its envelope"
    );
    assert_eq!(
        cur.last_refusal, None,
        "no Superseded, no 'the clock went back'"
    );
    f.tick(1, &b1, &[d1], t + 1).await;
    let cur = f.meta().current.unwrap();
    assert_eq!(cur.diffs, vec![d1]);
    assert_eq!(cur.acks.len(), 3, "every postman took the change");
    assert_eq!(cur.last_refusal, None);
    for i in 0..3 {
        let held = f.held_at(i);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].stored_at, t + 1);
        assert_eq!(f.opened(&held[0]).diffs.len(), 1);
    }
}

/// P1-3 / PL-3: the envelope's TTL is scaled by time_scale (5 years / ts).
#[tokio::test]
async fn published_pointer_ttl_scales_with_time_scale() {
    use viaticum_core::mailbox::class_config;
    let f = fx(3);
    let b1 = f.block(1, 3);
    let scaled = PointerPublisher {
        time_scale: 60,
        ..f.publisher()
    };
    f.tick_with(&scaled, 1, &b1, &[], now()).await;
    let e = &f.sent()[0].1;
    assert_eq!(
        e.expires_at - e.stored_at,
        class_config::SELF_POINTER_TTL.as_secs() / 60
    );
}

// ─── Readiness does not blink (dr-i52) ─────────────────────────────────────────

/// A new envelope of the same place and base starts with no acks; readiness stands on
/// the last envelope of the place that reached the threshold until the new one does.
#[tokio::test]
async fn readiness_does_not_flicker_while_a_new_envelope_collects_acks() {
    use crate::daemon::system_state::strength::pointer_readiness;
    let f = fx(6); // threshold 3
    let b1 = f.block(1, 6);
    let t = now();
    let readiness = |at| pointer_readiness(&f.db, 6, at, 1).unwrap();
    f.tick(1, &b1, &[], t).await;
    let first = f.meta().current.unwrap();
    assert!(first.acks.len() >= 3);
    assert!(readiness(t).ready);

    // A diff: a new envelope in place A; nobody answers.
    let d1 = f.block(2, 6);
    f.answering(Some(0));
    f.tick(1, &b1, &[d1], t + 1).await;
    let cur = f.meta().current.unwrap();
    assert!(cur.acks.is_empty(), "the new envelope has no acks yet");
    let r = readiness(t + 1);
    assert!(
        r.ready,
        "no blink: the earlier envelope still has the threshold"
    );
    assert_eq!(r.accepted.unwrap().0, first.created_at.0);

    // Two postmen accept the new one: still short of 3, still ready on the earlier.
    f.answering(Some(2));
    f.tick(1, &b1, &[d1], t + 2).await;
    assert_eq!(f.meta().current.unwrap().acks.len(), 2);
    let r = readiness(t + 2);
    assert!(r.ready);
    assert_eq!(r.accepted.unwrap().0, first.created_at.0);

    // The new envelope reaches the threshold: readiness moves to it.
    f.answering(None);
    f.tick(1, &b1, &[d1], t + 3).await;
    let cur = f.meta().current.unwrap();
    assert!(cur.acks.len() >= 3);
    assert_eq!(cur.reached, None, "no longer needed");
    let r = readiness(t + 3);
    assert!(r.ready);
    assert_eq!(r.accepted.unwrap().0, cur.created_at.0);
    assert_eq!(r.blocks_total, 2, "base + the new diff");
}

/// A new base displacing a place does not inherit the readiness of the base it
/// displaced: readiness stands on the other place (or on nothing).
#[tokio::test]
async fn new_base_in_a_place_does_not_keep_the_displaced_base_ready() {
    use crate::daemon::system_state::strength::pointer_readiness;
    let f = fx(6);
    let t = now();
    let b1 = f.block(1, 6);
    f.tick(1, &b1, &[], t).await; // A
    let b2 = f.block(2, 6);
    f.tick(2, &b2, &[], t + 1).await; // B
    let b3 = f.block(3, 1);
    f.answering(Some(0));
    f.tick(3, &b3, &[], t + 2).await; // displaces the weaker (older on a tie) place: A
    let m = f.meta();
    let cur = m.current.as_ref().unwrap();
    assert_eq!((cur.place, cur.base), (PointerPlace::A, b3));
    assert_eq!(
        cur.reached, None,
        "a new base starts without a kept envelope"
    );
    let r = pointer_readiness(&f.db, 6, t + 2, 1).unwrap();
    assert_eq!(
        r.accepted.unwrap().0,
        m.other.as_ref().unwrap().created_at.0,
        "readiness stands on the other place (b2), not on the displaced b1"
    );
}

/// dr-i52, mailbox-i58: a re-seal of the other place keeps the envelope that reached
/// the threshold as `reached`; readiness stands on it while the re-sealed envelope has
/// no acks yet.
#[tokio::test]
async fn reseal_keeps_reached_while_the_resealed_envelope_collects_acks() {
    use crate::daemon::system_state::strength::pointer_readiness;
    let f = fx(6); // threshold 3
    let ts = 100_000;
    let p = PointerPublisher {
        time_scale: ts,
        ..f.publisher()
    };
    let refresh = pointer_refresh_interval_secs(ts);
    let t = now();
    let b1 = f.block(1, 6);
    f.tick_with(&p, 1, &b1, &[], t).await; // A, every postman acks
    let b2 = f.block(2, 6);
    f.answering(Some(2));
    f.tick_with(&p, 2, &b2, &[], t + 1).await; // B, short of the threshold
    let m = f.meta();
    let a = m.other.clone().expect("b1 in the other place");
    assert_eq!((a.place, a.base), (PointerPlace::A, b1));
    assert!(a.acks.len() >= 3);
    assert_eq!(m.current.as_ref().unwrap().acks.len(), 2);
    let readiness = |at| pointer_readiness(&f.db, 6, at, ts).unwrap();
    assert_eq!(readiness(t + 1).restores_state_of, Some(a.created_at.0));

    f.answering(Some(0));
    let at = t + refresh;
    for d in &f.devices {
        f.db.upsert_peer(&peer(*d, at)).unwrap(); // holders seen lately
    }
    f.tick_with(&p, 2, &b2, &[], at).await;
    let other = f.meta().other.expect("still in META");
    let resealed: MailboxEntry = from_cbor_bytes(&other.entry_cbor).unwrap();
    assert_eq!(resealed.stored_at, at, "re-sealed this tick");
    assert!(
        other.acks.is_empty(),
        "nobody acked the re-sealed envelope yet"
    );
    let reached = other
        .reached
        .as_ref()
        .expect("the envelope at the threshold kept");
    assert_eq!(reached.created_at, a.created_at);
    assert!(reached.acks >= 3);
    let r = readiness(at);
    assert!(r.ready, "readiness holds on place A");
    assert_eq!(r.restores_state_of, Some(a.created_at.0));
}
