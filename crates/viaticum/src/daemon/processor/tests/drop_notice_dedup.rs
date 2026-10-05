// DN-1: one DropNotice — one application (spec `f1_stale_drop_notice.md`, intent 4r-i47,
// 4r-i48, 4r-i49, 4r-i51, mechanism of 4r-i32). The mailbox hands the same entry out on every
// poll for its whole TTL; only the FIRST delivery of a notice may move a placement to Lost,
// record a pair-ledger event or wake repair. A child of `processor/tests.rs` (reuses its
// `drop_fixture`); `mailbox/poll/tests.rs` (line B) is not touched.

use tokio::sync::mpsc;
use viaticum_core::cluster::master_identity;
use viaticum_core::db::Db;
use viaticum_core::messages::{SymbolDropNoticeMsg, build_signed_symbol_drop_notice};
use viaticum_core::types::{PlacementStatus, Timestamp};

use super::{
    DropFixture, drop_fixture, make_block_id, make_device_id, make_signing_key, make_source_block,
    make_symbol_placement, register_holder,
};
use crate::daemon::mailbox::poll::DropNoticeHandler;
use crate::daemon::processor::symbol::seen_drop_notice_retention_secs;
use crate::daemon::repair::RepairTrigger;

impl DropFixture {
    /// Repair put the block back on the same holder: the placement is Alive again with a new
    /// episode start (the worker's `Offered → Alive` rewrite).
    fn replace_alive(&self, placed_at: Timestamp) {
        let mut p = self
            .db
            .get_placement(&self.block, &self.device)
            .unwrap()
            .unwrap();
        p.status = PlacementStatus::Alive;
        p.placed_at = placed_at;
        p.consecutive_misses = 0;
        self.db.upsert_placement(&p).unwrap();
    }
    pub(super) fn seen_rows(&self) -> usize {
        self.db.list_seen_signed_letters().unwrap().len()
    }
}

#[tokio::test]
async fn a_redelivered_drop_notice_does_not_mark_a_fresh_placement_lost() {
    // DN1-1 (4r-i47, AC-DN1-1). First delivery: Alive → Lost, one Announced. Repair re-places
    // the block on the same holder; the same notice comes again: nothing changes.
    let f = drop_fixture(0x61, PlacementStatus::Alive, None);
    let notice = f.fresh_notice(10);

    assert!(f.apply(notice.clone()), "first delivery applies");
    assert_eq!(f.status(), PlacementStatus::Lost);

    f.replace_alive(Timestamp(f.placed_at.0 + 20));
    assert!(
        !f.apply(notice.clone()),
        "a re-delivery is not an application"
    );
    assert!(!f.apply(notice), "nor is the next one");

    assert_eq!(
        f.status(),
        PlacementStatus::Alive,
        "the fresh placement stays"
    );
    assert_eq!(f.announced_for(f.ledger_master), 1);
    assert_eq!(f.seen_rows(), 1);
}

#[tokio::test]
async fn the_seen_notice_survives_reopening_the_database_file() {
    // DN1-2 (4r-i47, AC-DN1-2). The owner restarts inside the notice's TTL: the memory is on
    // disk, so the re-delivery after the restart is still recognised.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("db.redb");
    let key = make_signing_key(0x63);
    let signer = master_identity(&key);
    let device = make_device_id(0x63);
    let block = make_block_id(0x64);
    let placed_at = Timestamp(Timestamp::now().0 - 3600);
    let ts = Timestamp(placed_at.0 + 10);
    let notice = build_signed_symbol_drop_notice(block, vec![(0, 10)], ts, ts, &key);
    {
        let db = Db::open(&path).unwrap();
        register_holder(&db, signer, device);
        db.upsert_source_block(&make_source_block(block)).unwrap();
        let mut p = make_symbol_placement(block, device, vec![(0, 10)], PlacementStatus::Alive);
        p.placed_at = placed_at;
        db.upsert_placement(&p).unwrap();
        assert!(super::super::SymbolDropHandler::new(db.clone()).apply(signer, notice.clone()));
    }

    let db = Db::open(&path).unwrap();
    let mut p = db.get_placement(&block, &device).unwrap().unwrap();
    assert_eq!(
        p.status,
        PlacementStatus::Lost,
        "premise: applied before the restart"
    );
    p.status = PlacementStatus::Alive;
    p.placed_at = Timestamp(placed_at.0 + 20);
    db.upsert_placement(&p).unwrap();

    assert!(!super::super::SymbolDropHandler::new(db.clone()).apply(signer, notice));
    assert_eq!(
        db.get_placement(&block, &device).unwrap().unwrap().status,
        PlacementStatus::Alive
    );
}

#[tokio::test]
async fn a_new_notice_for_the_same_block_from_the_same_holder_is_applied() {
    // DN1-3 (4r-i48, AC-DN1-3). The holder genuinely drops the re-placed block again: a new
    // notice (new timestamp → new signature) is a new application, a second Announced.
    let f = drop_fixture(0x65, PlacementStatus::Alive, None);
    let first = f.fresh_notice(10);
    assert!(f.apply(first.clone()));
    f.replace_alive(Timestamp(f.placed_at.0 + 20));

    let second = f.fresh_notice(30);
    assert_ne!(
        first.sig, second.sig,
        "premise: a new notice has a new signature"
    );
    assert!(
        f.apply(second.clone()),
        "the second genuine drop is applied"
    );

    assert_eq!(f.status(), PlacementStatus::Lost);
    assert_eq!(f.announced_for(f.ledger_master), 2);
    assert!(!f.apply(first), "the old one stays spent");
    assert!(
        !f.apply(second),
        "and so does the new one after its first delivery"
    );
    assert_eq!(f.seen_rows(), 2);
}

#[tokio::test]
async fn a_notice_first_seen_on_an_already_lost_placement_is_still_remembered() {
    // DN1-4 (AC-DN1-4). PoS got there first — the placement is already Lost when the notice
    // arrives. The notice is applied (nothing to transition) and remembered, so after repair
    // re-places the block its re-delivery changes nothing.
    let f = drop_fixture(0x67, PlacementStatus::Lost, None);
    let notice = f.fresh_notice(10);

    assert!(
        f.apply(notice.clone()),
        "applied: signature fine, placement ours"
    );
    assert_eq!(f.seen_rows(), 1, "remembered although nothing changed");

    f.replace_alive(Timestamp(f.placed_at.0 + 20));
    assert!(!f.apply(notice));
    assert_eq!(f.status(), PlacementStatus::Alive);
    assert!(f.pending().is_empty(), "no event: Lost → Lost is none");
}

#[tokio::test]
async fn a_holder_clock_ahead_does_not_turn_one_drop_into_two() {
    // DN1-5 (4r-i32, AC-DN1-5). The holder's clock runs a day ahead: its notice is stamped
    // after every re-placement of ours, so the У-4 episode check alone would count each loop
    // iteration as a new Announced. The seen set stops the loop before the transition.
    let f = drop_fixture(0x69, PlacementStatus::Alive, None);
    let ts = Timestamp(f.placed_at.0 + 86_400);
    let notice = f.notice(ts, ts);

    assert!(f.apply(notice.clone()));
    assert_eq!(f.status(), PlacementStatus::Lost);
    assert_eq!(f.announced_for(f.ledger_master), 1);

    let replaced_at = Timestamp(f.placed_at.0 + 20);
    assert!(
        replaced_at.0 < ts.0,
        "premise: the re-placement predates the notice"
    );
    f.replace_alive(replaced_at);
    assert!(!f.apply(notice));

    assert_eq!(f.status(), PlacementStatus::Alive);
    assert_eq!(f.announced_for(f.ledger_master), 1, "still one drop");
}

#[tokio::test]
async fn a_notice_from_an_unknown_master_is_not_remembered_and_applies_once_known() {
    // DN1-6 (4r-i31, AC-DN1-4). Right after DR the holder's device is not yet mapped to its
    // master: the notice is dropped and NOT remembered, so its re-delivery after
    // re-authentication applies it.
    let db = Db::open_in_memory().unwrap();
    let key = make_signing_key(0x6B);
    let signer = master_identity(&key);
    let device = make_device_id(0x6B);
    let block = make_block_id(0x6C);
    db.upsert_source_block(&make_source_block(block)).unwrap();
    let mut p = make_symbol_placement(block, device, vec![(0, 10)], PlacementStatus::Alive);
    p.placed_at = Timestamp(Timestamp::now().0 - 3600);
    db.upsert_placement(&p).unwrap();
    let ts = Timestamp(p.placed_at.0 + 10);
    let notice = build_signed_symbol_drop_notice(block, vec![(0, 10)], ts, ts, &key);
    let handler = super::super::SymbolDropHandler::new(db.clone());

    assert!(!handler.apply(signer, notice.clone()), "unknown master");
    assert!(db.list_seen_signed_letters().unwrap().is_empty());

    register_holder(&db, signer, device);
    assert!(
        handler.apply(signer, notice),
        "applies once the master is known"
    );
    assert_eq!(
        db.get_placement(&block, &device).unwrap().unwrap().status,
        PlacementStatus::Lost
    );
    assert_eq!(db.list_seen_signed_letters().unwrap().len(), 1);
}

#[tokio::test]
async fn a_notice_with_a_bad_signature_is_not_remembered() {
    // DN1-7 (W-3, AC-DN1-4). A forgery never enters the seen set — otherwise an attacker could
    // pre-spend a signature. The genuine notice with the same fields still applies.
    let f = drop_fixture(0x6D, PlacementStatus::Alive, None);
    let genuine = f.fresh_notice(10);
    let mut forged = genuine.clone();
    forged.sig[0] ^= 0x01;

    assert!(!f.apply(forged));
    assert_eq!(f.seen_rows(), 0);
    assert_eq!(f.status(), PlacementStatus::Alive);

    assert!(f.apply(genuine));
    assert_eq!(f.status(), PlacementStatus::Lost);
}

/// `S + L` (L = the ed25519 group order), little-endian: the same signature in a
/// non-canonical encoding. `S < L`, so `S + L < 2^254` fits the 32 bytes.
fn non_canonical_s(sig: &[u8; 64]) -> [u8; 64] {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut out = *sig;
    let mut carry = 0u16;
    for i in 0..32 {
        let v = sig[32 + i] as u16 + L[i] as u16 + carry;
        out[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0, "S + L fits in 256 bits");
    out
}

#[tokio::test]
async fn a_non_canonical_twin_of_an_applied_signature_is_rejected_by_the_signature_check() {
    // DN1-7b (line B, verify_strict). The dedup key is a signature that passed `verify_strict`.
    // The same signature with a non-canonical S (S + L) would be a different 64-byte key; it
    // must be refused by the signature check, not applied as a "new" letter — before and after
    // the canonical one was applied, and without entering the seen set.
    let f = drop_fixture(0x81, PlacementStatus::Alive, None);
    let notice = f.fresh_notice(10);
    let mut twin = notice.clone();
    twin.sig = non_canonical_s(&notice.sig);
    assert_ne!(twin.sig, notice.sig, "premise: a different key");

    assert!(!f.apply(twin.clone()), "refused before the genuine one");
    assert_eq!(f.status(), PlacementStatus::Alive);
    assert_eq!(f.seen_rows(), 0);

    assert!(f.apply(notice.clone()));
    f.replace_alive(Timestamp(f.placed_at.0 + 20));

    assert!(!f.apply(twin), "refused after it — not a new letter");
    assert_eq!(
        f.status(),
        PlacementStatus::Alive,
        "the fresh placement stays"
    );
    assert_eq!(f.announced_for(f.ledger_master), 1);
    assert_eq!(f.seen_rows(), 1, "only the canonical signature is a key");
}

#[tokio::test]
async fn a_notice_without_our_placement_is_not_remembered_and_costs_at_most_one_extra_cycle() {
    // DN1-8 (4r-i49, 4r-i51 mechanism). No placement (our own deletion already cleaned up, or a
    // DR base without it): nothing is written. If the same content comes back and gets placed
    // on that holder inside the TTL, the first delivery marks it Lost once — one extra repair —
    // and from then on the notice is remembered.
    let f = drop_fixture(0x6F, PlacementStatus::Alive, None);
    let notice = f.fresh_notice(10);
    f.db.write_txn()
        .and_then(|mut t| {
            t.delete_placement(&f.block, &f.device)?;
            t.commit()
        })
        .unwrap();

    assert!(!f.apply(notice.clone()));
    assert_eq!(f.seen_rows(), 0);
    assert_eq!(f.db.seen_signed_letter_index_len().unwrap(), 0);

    let mut p = make_symbol_placement(f.block, f.device, vec![(0, 10)], PlacementStatus::Alive);
    p.placed_at = Timestamp(f.placed_at.0 + 20);
    f.db.upsert_placement(&p).unwrap();
    assert!(f.apply(notice.clone()), "one spurious application");
    assert_eq!(f.status(), PlacementStatus::Lost);
    assert_eq!(f.seen_rows(), 1);

    f.replace_alive(Timestamp(f.placed_at.0 + 30));
    assert!(!f.apply(notice), "then deduplicated");
    assert_eq!(f.status(), PlacementStatus::Alive);
}

#[tokio::test]
async fn redelivery_of_an_applied_immediate_notice_does_not_wake_repair() {
    // DN1-9 (AC-DN1-1). An immediate notice (deadline = now) wakes repair on its first
    // delivery; its re-delivery wakes nothing.
    let f = drop_fixture(0x71, PlacementStatus::Alive, None);
    let now = Timestamp::now();
    let notice = f.notice(now, now);
    let (tx, mut rx) = mpsc::channel::<RepairTrigger>(16);
    let handler = super::super::ProcessorDropHandler::new(f.db.clone(), tx);

    handler.handle_drop_notice(f.signer, notice.clone());
    assert!(matches!(rx.try_recv(), Ok(RepairTrigger::Wake)));
    assert!(rx.try_recv().is_err(), "exactly one wake");

    f.replace_alive(Timestamp(now.0 + 1));
    handler.handle_drop_notice(f.signer, notice);
    assert!(rx.try_recv().is_err(), "the re-delivery wakes nothing");
}

#[test]
fn the_seen_retention_is_twice_the_scaled_drop_notice_ttl() {
    // DN1-11 (AC-DN1-6). 28 days in production, 120 s at the E2E scale 20 000, floor 2 s.
    assert_eq!(seen_drop_notice_retention_secs(1), 2 * 1_209_600);
    assert_eq!(seen_drop_notice_retention_secs(20_000), 2 * 60);
    assert_eq!(seen_drop_notice_retention_secs(u64::MAX), 2);
    assert_eq!(
        seen_drop_notice_retention_secs(0),
        2 * 1_209_600,
        "0 is treated as 1"
    );
}

#[tokio::test]
async fn the_seen_retention_follows_the_handlers_time_scale() {
    // DN1-11 (wiring half): the row written by a handler built `with_time_scale` expires after
    // the scaled retention, not after 28 real days.
    let f = drop_fixture(0x73, PlacementStatus::Alive, None);
    let before = Timestamp::now();
    assert!(
        super::super::SymbolDropHandler::new(f.db.clone())
            .with_time_scale(20_000)
            .apply(f.signer, f.fresh_notice(10))
    );
    let rows = f.db.list_seen_signed_letters().unwrap();
    assert_eq!(rows.len(), 1);
    let rec = &rows[0].1;
    assert_eq!(rec.forget_after.0 - rec.first_seen.0, 120);
    assert!(rec.first_seen.0 >= before.0);
    assert_eq!(
        rec.class,
        viaticum_core::types::SignedLetterClass::DropNotice
    );
}

#[tokio::test]
async fn the_first_delivery_of_an_old_notice_still_marks_a_fresh_placement_lost() {
    // DN1-12 (AC-DN1-7, Д-DN1-2). Time is not part of the rule: a notice stamped BEFORE the
    // current episode still marks it Lost on its first delivery (not counted by У-4:
    // EvidenceBeforeEpisode); the second delivery changes nothing.
    let f = drop_fixture(0x75, PlacementStatus::Alive, None);
    let ts = Timestamp(f.placed_at.0 - 5);
    let notice = f.notice(ts, ts);

    assert!(f.apply(notice.clone()));
    assert_eq!(f.status(), PlacementStatus::Lost);
    assert!(f.pending().is_empty(), "not a new drop for the ledger");

    f.replace_alive(Timestamp(f.placed_at.0 + 20));
    assert!(!f.apply(notice));
    assert_eq!(f.status(), PlacementStatus::Alive);
}

#[tokio::test]
async fn final_notices_for_our_own_deletions_write_nothing() {
    // DN1-15 (4r-i49, FW-1). A month after deleting a big folder the holders' final notices
    // arrive by the thousand. Deleting (or already cleaned-up) placements: no transition, no
    // seen row, no index key, no application — only the signature check and reads.
    let db = Db::open_in_memory().unwrap();
    let key = make_signing_key(0x77);
    let signer = master_identity(&key);
    let device = make_device_id(0x77);
    register_holder(&db, signer, device);
    let block_of = |i: u32| {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_be_bytes());
        b[4] = 0x77;
        viaticum_core::types::SourceBlockId(b)
    };
    const DELETING: u32 = 10_000;
    const MISSING: u32 = 100;
    {
        let mut txn = db.write_txn().unwrap();
        for i in 0..DELETING {
            let p = make_symbol_placement(
                block_of(i),
                device,
                vec![(0, 10)],
                PlacementStatus::Deleting,
            );
            txn.upsert_placement(&p).unwrap();
        }
        txn.commit().unwrap();
    }
    let handler = super::super::SymbolDropHandler::new(db.clone());
    let now = Timestamp::now();

    let mut applied = 0u32;
    for i in 0..(DELETING + MISSING) {
        let notice = build_signed_symbol_drop_notice(block_of(i), vec![(0, 10)], now, now, &key);
        if handler.apply(signer, notice) {
            applied += 1;
        }
    }

    assert_eq!(applied, 0, "none of them is an application");
    assert!(db.list_seen_signed_letters().unwrap().is_empty());
    assert_eq!(db.seen_signed_letter_index_len().unwrap(), 0);
    assert_eq!(
        db.get_placement(&block_of(0), &device)
            .unwrap()
            .unwrap()
            .status,
        PlacementStatus::Deleting,
        "premise: our deletion is untouched"
    );
}

#[tokio::test]
async fn a_placement_read_error_is_not_remembered() {
    // DN1-16 (FW-3). A damaged placement row is not "no placement": the notice is neither
    // applied nor remembered — its next delivery gets the same chance again instead of being
    // swallowed as "already applied". (The row itself cannot be repaired through
    // `upsert_placement`, which decodes the old row first — pre-existing, not DN-1.)
    let f = drop_fixture(0x79, PlacementStatus::Alive, None);
    let notice = f.fresh_notice(10);
    f.db.corrupt_placement_row_for_test(&f.block, &f.device)
        .unwrap();
    assert!(
        f.db.get_placement(&f.block, &f.device).is_err(),
        "premise: the read fails"
    );

    assert!(!f.apply(notice.clone()));
    assert!(
        !f.apply(notice.clone()),
        "the next delivery is not 'already applied' either"
    );
    assert_eq!(f.seen_rows(), 0);
    assert_eq!(f.db.seen_signed_letter_index_len().unwrap(), 0);
    assert!(
        !f.db
            .signed_letter_seen(&notice.sig, Timestamp::now())
            .unwrap()
    );
    assert!(f.pending().is_empty(), "no event either");
}

impl DropFixture {
    /// A second device `d2` of the same holder master holding the same block with ESIs
    /// `(10, 10)` (the fixture's device holds `(0, 10)`), in `status`, with a PeerRecord keyed to
    /// the same ledger master (so a wrong Lost on it would show as a second Announced).
    pub(super) fn add_second_device(
        &self,
        status: PlacementStatus,
    ) -> viaticum_core::types::DeviceId {
        let d2 = make_device_id(self.device.0[0].wrapping_add(1));
        assert!(
            self.device.0 < d2.0,
            "premise: the fixture's device comes first"
        );
        register_holder(&self.db, self.signer, d2);
        let mut peer = super::make_peer_record(d2);
        peer.master_identity = self.ledger_master;
        self.db.upsert_peer(&peer).unwrap();
        let mut p2 = make_symbol_placement(self.block, d2, vec![(10, 10)], status);
        p2.placed_at = self.placed_at;
        self.db.upsert_placement(&p2).unwrap();
        d2
    }
    pub(super) fn status_of(&self, d: viaticum_core::types::DeviceId) -> PlacementStatus {
        self.db
            .get_placement(&self.block, &d)
            .unwrap()
            .unwrap()
            .status
    }
    /// A notice for ESIs `esi`, stamped `after` seconds after the placement, deadline `deadline_after`.
    pub(super) fn notice_for(
        &self,
        esi: (u32, u32),
        after: u64,
        deadline_after: u64,
    ) -> SymbolDropNoticeMsg {
        build_signed_symbol_drop_notice(
            self.block,
            vec![esi],
            Timestamp(self.placed_at.0 + deadline_after),
            Timestamp(self.placed_at.0 + after),
            &self.key,
        )
    }
}

#[tokio::test]
async fn a_two_device_holder_master_gets_the_placement_whose_esis_the_notice_names() {
    // DN1-17 (Д-DN1-8 after review W-1, AC-DN1-8). One holder master, two devices holding the
    // block: d1 (0..10) is already Lost, d2 (10..20) Alive. The notice names no device, but its
    // signed ESIs do: a notice for d1's ESIs stays on d1 (already Lost — nothing changes, d2 is
    // NOT taken instead); a notice for d2's ESIs marks d2 Lost.
    let f = drop_fixture(0x7B, PlacementStatus::Lost, None);
    let d2 = f.add_second_device(PlacementStatus::Alive);

    assert!(
        f.apply(f.notice_for((0, 10), 10, 10)),
        "applied to d1 (already Lost)"
    );
    assert_eq!(
        f.status_of(d2),
        PlacementStatus::Alive,
        "d2 is not d1's notice"
    );
    assert_eq!(f.status(), PlacementStatus::Lost);

    assert!(f.apply(f.notice_for((10, 10), 20, 20)));
    assert_eq!(f.status_of(d2), PlacementStatus::Lost, "d2's own ESIs");
    assert_eq!(f.announced_for(f.ledger_master), 1, "one drop: d2's");
    assert_eq!(f.seen_rows(), 2);
}

#[tokio::test]
async fn an_advance_then_final_notice_on_two_devices_is_one_event_and_leaves_the_sibling_alone() {
    // DN1-17b (review W-1). d1 (0..10) and d2 (10..20), both Alive, of one holder master. The
    // holder sends the advance notice for d1's ESIs (deadline in a week) and, a week later, the
    // FINAL notice for the same ESIs (a new letter: new deadline and timestamp). The final one
    // finds d1 already Lost; it must stay on d1 — not fall through to the Alive sibling d2 (a
    // false Lost there, a second Announced and a needless repair).
    let f = drop_fixture(0x83, PlacementStatus::Alive, None);
    let d2 = f.add_second_device(PlacementStatus::Alive);
    let week = 7 * 86_400;

    assert!(
        f.apply(f.notice_for((0, 10), 10, 10 + week)),
        "advance notice"
    );
    assert_eq!(f.status(), PlacementStatus::Lost);
    assert!(
        f.apply(f.notice_for((0, 10), 10 + week, 10 + week)),
        "final notice"
    );

    assert_eq!(
        f.status_of(d2),
        PlacementStatus::Alive,
        "the sibling is untouched"
    );
    assert_eq!(f.announced_for(f.ledger_master), 1, "one loss, one event");
}

// DN1-17c (a notice naming no held ESI) changed with Р-3 (C-SP K1c): it is ignored now —
// `drop_notice_device.rs`, `drop_notice_without_intersection_changes_nothing`.

#[tokio::test]
async fn the_transition_and_the_seen_row_commit_together() {
    // DN1-18 (Д-DN1-5, AC-DN1-4). After `apply` on an Alive placement, the transition, the
    // У-4 event, the seen row and its index key are all there. The "none of them if it never
    // commits" half is the DD-2 seam at the DB level (`db/seen_signed_letters/tests.rs`,
    // `a_dropped_transaction_records_no_seen_row`, plus DD-2 itself for the placement + event):
    // there is no failure injection inside one transaction without a test-only production API.
    let f = drop_fixture(0x7D, PlacementStatus::Alive, None);
    let notice = f.fresh_notice(10);

    assert!(f.apply(notice.clone()));

    assert_eq!(f.status(), PlacementStatus::Lost);
    assert_eq!(f.announced_for(f.ledger_master), 1);
    assert!(
        f.db.signed_letter_seen(&notice.sig, Timestamp::now())
            .unwrap()
    );
    assert_eq!(f.db.seen_signed_letter_index_len().unwrap(), 1);

    // The same through the helper with a transaction that is dropped: nothing of it lands.
    let before = f.db.get_placement(&f.block, &f.device).unwrap().unwrap();
    {
        let mut alive = before.clone();
        alive.status = PlacementStatus::Alive;
        let other_sig = [0x7Eu8; 64];
        let mut txn = f.db.write_txn().unwrap();
        txn.upsert_placement(&alive).unwrap();
        txn.record_signed_letter_seen(
            &other_sig,
            viaticum_core::types::SignedLetterClass::DropNotice,
            Timestamp::now(),
            Timestamp(Timestamp::now().0 + 100),
        )
        .unwrap();
        // dropped without commit
    }
    assert_eq!(f.status(), PlacementStatus::Lost);
    assert!(
        !f.db
            .signed_letter_seen(&[0x7Eu8; 64], Timestamp::now())
            .unwrap()
    );
}
