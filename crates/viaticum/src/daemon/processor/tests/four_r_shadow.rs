// В-0b: the offer path after the "snapshot + rule" refactor, and the 4R offer shadow that
// runs off the reply path (D-3a, D-3b, D-5; intent 4r-i44, 4r-i50). A child of
// `processor/tests.rs` (reuses `make_processor_with_quota`).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::TempDir;
use viaticum_core::budget::{compute_effective_quota, should_reject_offers};
use viaticum_core::constants::SYMBOL_SIZE;
use viaticum_core::db::Db;
use viaticum_core::four_r_holder::{FourRParams, HolderAdmit, HolderReject, OfferIn};
use viaticum_core::messages::{Message, RejectReason, build_symbol_offer};
use viaticum_core::types::{
    DeviceId, FourRPhaseRecord, HoldingRecord, HoldingStatus, IdentityPub, PairLedger, Timestamp,
};

use super::super::offer_shadow::{OfferShadowJob, OfferSnapshot, run_offer_shadow};
use super::{make_block_id, make_processor_with_quota};

/// The pre-В-0b three-stage rule, restated verbatim as the reference (hard ceiling → soft
/// pressure → final fill), with the snapshot's numbers in place of the reads it used to do.
fn old_rule(soft: u64, hard: u64, reserve: u64, held: u64, disk_free: u64, offer: u64) -> bool {
    if hard > 0 && held >= hard {
        return false;
    }
    let effective = compute_effective_quota(soft, disk_free, reserve);
    if should_reject_offers(effective, held) {
        return false;
    }
    if held + offer > effective {
        return false;
    }
    true
}

/// D-3a: over a grid of quota cases, the rule on a snapshot answers exactly as the old
/// three-stage rule.
#[tokio::test]
async fn decide_on_a_snapshot_equals_decide_symbol_offer_for_every_quota_case() {
    let dir = TempDir::new().unwrap();
    let mut p = make_processor_with_quota(Db::open_in_memory().unwrap(), &dir, 0, 0).await;
    let mut n = 0;
    let mut accepts = 0;
    for soft in [0u64, 1000, 10_000] {
        for hard in [0u64, 500, 900] {
            for reserve in [0u64, 100] {
                for held in [0u64, 400, 849, 850, 900, 960, 1000, 5000] {
                    for disk_free in [0u64, 50, 1100, 1 << 30] {
                        for offer in [1u64, 100, 151, 65_535] {
                            p.soft_quota_bytes = soft;
                            p.hard_quota_bytes = hard;
                            p.disk_reserve_bytes = reserve;
                            let s = OfferSnapshot {
                                held_bytes: held,
                                disk_free,
                            };
                            let got = p.decide_symbol_offer_on(offer, &s);
                            let want = old_rule(soft, hard, reserve, held, disk_free, offer);
                            assert_eq!(
                                got, want,
                                "soft={soft} hard={hard} reserve={reserve} held={held} free={disk_free} offer={offer}"
                            );
                            n += 1;
                            accepts += usize::from(got);
                        }
                    }
                }
            }
        }
    }
    assert!(
        accepts > 0 && accepts < n,
        "the grid must exercise both answers"
    );
    // The wrapper reads the same DB state: an empty holder with a huge quota accepts.
    p.soft_quota_bytes = u64::MAX / 2;
    p.hard_quota_bytes = 0;
    assert!(p.decide_symbol_offer(65_535).unwrap());
}

fn reply_shape(m: &Message) -> (bool, Option<RejectReason>) {
    match m {
        Message::SymbolAccept(_) => (true, None),
        Message::SymbolReject(r) => (false, Some(r.reason)),
        other => panic!("unexpected reply {:?}", std::mem::discriminant(other)),
    }
}

fn holding(owner: IdentityPub, blk: u8, bytes: u64) -> HoldingRecord {
    HoldingRecord {
        source_block_id: make_block_id(blk),
        owner_id: owner,
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: bytes,
        status: HoldingStatus::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

/// D-3b: whatever the 4R dials, the latch and the ledger say, the reply is the old rule's.
#[tokio::test]
async fn the_offer_shadow_never_changes_the_reply() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let owner = IdentityPub(key.verifying_key().to_bytes());
    let whale = IdentityPub([0x57; 32]);
    // A whale fills 90 % of the quota; the offerer serves us a lot (4R would preempt for it)
    // and 4R's latch is ON.
    let quota = 20 * SYMBOL_SIZE as u64;
    db.upsert_holding(&holding(whale, 0x70, quota * 9 / 10))
        .unwrap();
    db.upsert_pair_ledger(
        &owner,
        &PairLedger {
            gb_days_they_store_for_us: 50.0,
            v_dem: 0.01,
            last_update: Some(Timestamp(1)),
            ..Default::default()
        },
    )
    .unwrap();
    db.set_four_r_phase(&FourRPhaseRecord {
        evicting: true,
        since: Some(Timestamp(1)),
    })
    .unwrap();
    let mut p = make_processor_with_quota(db.clone(), &dir, quota, 0).await;
    let aggressive = FourRParams {
        c_recip_days: 1e-9,
        theta_p: 0.0,
        v_min_gb: 0.0,
        ..FourRParams::default()
    };
    let mut seen = std::collections::HashSet::new();
    for (i, count) in [1u32, 2, 4].iter().enumerate() {
        let offer_bytes = *count as u64 * SYMBOL_SIZE as u64;
        let mk = |msg: u8| {
            build_symbol_offer(
                [msg; 16],
                make_block_id(0x10 + i as u8),
                vec![(0, *count)],
                0.9,
                Timestamp::now(),
                &key,
            )
        };
        p.set_four_r(FourRParams::default());
        let a = reply_shape(&p.handle_symbol_offer_inner(DeviceId(owner.0), owner, mk(1)));
        p.set_four_r(aggressive.clone());
        let b = reply_shape(&p.handle_symbol_offer_inner(DeviceId(owner.0), owner, mk(2)));
        let want = p.decide_symbol_offer(offer_bytes).unwrap();
        assert_eq!(
            a, b,
            "offer of {count} symbol(s): the dials changed the reply"
        );
        assert_eq!(
            a.0, want,
            "offer of {count} symbol(s): not the old rule's answer"
        );
        seen.insert(a.0);
    }
    // 90 % used: the old rule refuses (soft zone) — the shadow would preempt, and did not.
    assert_eq!(seen, [false].into_iter().collect());
    // An accepted case too: room again.
    db.delete_holding(&make_block_id(0x70), &whale).unwrap();
    let r = p.handle_symbol_offer_inner(
        DeviceId(owner.0),
        owner,
        build_symbol_offer(
            [9; 16],
            make_block_id(0x31),
            vec![(0, 1)],
            0.9,
            Timestamp::now(),
            &key,
        ),
    );
    assert_eq!(reply_shape(&r), (true, None));
}

/// D-5 (4r-i50): with the shadow slot held, the reply comes back at once and the skip is
/// counted; with the slot free the shadow runs in the background and consumes the count.
#[tokio::test(flavor = "multi_thread")]
async fn a_busy_shadow_slot_does_not_delay_the_reply_and_counts_a_skip() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor_with_quota(db, &dir, u64::MAX / 2, 0).await;
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let owner = IdentityPub(key.verifying_key().to_bytes());
    let held = p.shadow_offer_slot.clone().try_acquire_owned().unwrap();
    let t0 = std::time::Instant::now();
    let r = p.handle_symbol_offer_inner(
        DeviceId(owner.0),
        owner,
        build_symbol_offer(
            [1; 16],
            make_block_id(0x41),
            vec![(0, 1)],
            0.5,
            Timestamp::now(),
            &key,
        ),
    );
    assert_eq!(reply_shape(&r), (true, None));
    assert!(t0.elapsed() < std::time::Duration::from_secs(2));
    assert_eq!(p.shadow_offers_skipped.load(Ordering::Relaxed), 1);
    drop(held);

    let _ = p.handle_symbol_offer_inner(
        DeviceId(owner.0),
        owner,
        build_symbol_offer(
            [2; 16],
            make_block_id(0x42),
            vec![(0, 1)],
            0.5,
            Timestamp::now(),
            &key,
        ),
    );
    // The shadow logged and reset the skip counter (swap(0)), then freed the slot.
    let mut ok = false;
    for _ in 0..200 {
        if p.shadow_offers_skipped.load(Ordering::Relaxed) == 0
            && p.shadow_offer_slot.available_permits() == 1
        {
            ok = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(ok, "the background shadow must run and release the slot");
}

fn shadow_job(db: &Db, owner: IdentityPub, key_before: Option<HoldingRecord>) -> OfferShadowJob {
    OfferShadowJob {
        db: db.clone(),
        own_master: IdentityPub([0xEE; 32]),
        p: FourRParams::default(),
        offer: OfferIn {
            owner,
            block: make_block_id(0x60),
            offer_bytes: 2 * SYMBOL_SIZE as u64,
        },
        snap: OfferSnapshot {
            held_bytes: 0,
            disk_free: 1 << 40,
        },
        key_before,
        soft: 1 << 30,
        reserve: 0,
        hard: 0,
        old_accept: true,
        skipped: Arc::new(AtomicU64::new(0)),
    }
}

/// D-3c (review N3): the shadow re-reads HOLDINGS after the reply. A transfer that already
/// landed in the offer's own (owner, block) record is not counted on top of the offer: that
/// record is taken as it was at the decision — absent ⇒ not there; present and notified ⇒ still
/// notified at its decision-time size (Р-26 fires; a plain removal would have hidden it).
#[test]
fn the_offer_shadow_takes_the_offers_own_record_as_it_was_at_the_decision() {
    let db = Db::open_in_memory().unwrap();
    let owner = IdentityPub([0x0F; 32]);
    let sym = SYMBOL_SIZE as u64;
    // Another block of the same owner, parked before the offer.
    db.upsert_holding(&holding(owner, 0x61, 3 * sym)).unwrap();
    // The transfer of the offer landed before the shadow's re-read: 2 symbols in (owner, 0x60).
    db.upsert_holding(&holding(owner, 0x60, 2 * sym)).unwrap();

    let out = run_offer_shadow(&shadow_job(&db, owner, None)).unwrap();
    assert_eq!(
        out.offerer_parked_bytes,
        3 * sym,
        "the landed transfer must not be counted with the offer (V_parked + V_offer twice)"
    );
    assert_eq!(out.quota.free_now_bytes, (1u64 << 30) - 3 * sym);
    assert!(out.admit.admits());

    // The record existed at the decision, NOTIFIED, with 1 symbol; the transfer merged 2 more
    // into it (status Active, notice kept) before the re-read.
    let mut before = holding(owner, 0x60, sym);
    before.drop_notice_sent_at = Some(Timestamp(5));
    let mut merged = before.clone();
    merged.total_bytes = 3 * sym;
    db.upsert_holding(&merged).unwrap();
    let out = run_offer_shadow(&shadow_job(&db, owner, Some(before))).unwrap();
    assert_eq!(
        out.admit,
        HolderAdmit::Reject(HolderReject::NotifiedBlock),
        "Р-26 must still see the notified record"
    );
    assert_eq!(out.offerer_notified_bytes, sym, "decision-time size");
    assert_eq!(out.offerer_parked_bytes, 3 * sym);
}
