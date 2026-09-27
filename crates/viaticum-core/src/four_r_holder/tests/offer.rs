// H-11, H-12 (В-0b): the offer shadow's holder layer and its record.

use super::*;
use crate::four_r::{AdmitReject, EvictPhase};

const MIB: u64 = 1 << 20;

/// L holds for F (serves L), P (serves L) and W (κ 0, asked, 20 MiB).
struct Laptop {
    own: IdentityPub,
    f: IdentityPub,
    w: IdentityPub,
    holdings: Vec<HoldingRecord>,
    ledgers: Vec<(IdentityPub, PairLedger)>,
}

fn laptop() -> Laptop {
    let own = master(0x4C);
    let f = master(0x46);
    let p = master(0x50);
    let w = master(0x57);
    let mut holdings = vec![
        holding(f, block(0x46, 0), 2 * MIB, 0.6),
        holding(p, block(0x50, 0), 2 * MIB, 0.5),
    ];
    for i in 0..4 {
        holdings.push(holding(w, block(0x57, i), 5 * MIB, 0.4 - 0.05 * i as f64));
    }
    Laptop {
        own,
        f,
        w,
        holdings,
        ledgers: vec![
            (f, ledger(0.08, 0.0, 0.0, 0.004, 1.0)),
            (p, ledger(0.05, 0.0, 0.0, 0.004, 1.0)),
        ],
    }
}

fn offer(owner: IdentityPub, blk: SourceBlockId, bytes: u64) -> OfferIn {
    OfferIn {
        owner,
        block: blk,
        offer_bytes: bytes,
    }
}

/// Q = soft with a big disk; `free` bytes above H.
fn quota_with_free(l: &Laptop, free: u64) -> QuotaInputs {
    let h: u64 = l.holdings.iter().map(|r| r.total_bytes).sum();
    soft_quota(&l.holdings, h + free, 0)
}

/// H-11: Q ≤ 0, Р-26 (a notified block) and Р-17 (the guard on the free path while the
/// offerer has notified holdings) are decided in the holder layer; the rest by the kernel.
#[test]
fn shadow_offer_applies_quota_notified_block_and_notified_guard_before_the_kernel() {
    let p = s1_params();
    let latch_off = EvictPhase::default();
    let mut l = laptop();

    // Q ≤ 0: explicit refusal.
    let q0 = QuotaInputs::from_holdings(&l.holdings, 0, 0, 1 << 30, 0);
    let s = shadow_offer(
        &l.holdings,
        &l.ledgers,
        l.own,
        q0,
        latch_off,
        &offer(l.f, block(0x46, 9), MIB),
        &p,
    );
    assert_eq!(s.admit, HolderAdmit::Reject(HolderReject::QuotaNonPositive));

    // Contended (φ ≈ 0.1 < s_soft): the serving friend F preempts the whale, lowest ι first.
    let s = shadow_offer(
        &l.holdings,
        &l.ledgers,
        l.own,
        quota_with_free(&l, 3 * MIB),
        latch_off,
        &offer(l.f, block(0x46, 9), MIB),
        &p,
    );
    match &s.admit {
        HolderAdmit::Preempt {
            victim,
            victims,
            victim_bytes,
        } => {
            assert_eq!(*victim, l.w);
            assert_eq!(victims.len(), 1);
            assert_eq!(victims[0].source_block_id, block(0x57, 3), "lowest ι of W");
            assert_eq!(*victim_bytes, 5 * MIB);
        }
        other => panic!("want Preempt, got {other:?}"),
    }
    assert_eq!(s.victim, Some(l.w));
    assert_eq!(s.victim_kappa, Some(0.0));
    assert!((s.margin - 0.024).abs() < 1e-12, "margin {}", s.margin);
    // The whale's own offer: V_ret(W) = 0 with 20 MiB parked ⇒ the kernel's guard.
    let s = shadow_offer(
        &l.holdings,
        &l.ledgers,
        l.own,
        quota_with_free(&l, 3 * MIB),
        latch_off,
        &offer(l.w, block(0x57, 9), 4 * MIB),
        &p,
    );
    assert_eq!(
        s.admit,
        HolderAdmit::Reject(HolderReject::Kernel(AdmitReject::Guard))
    );

    // Abundance: the kernel says Free for the whale too (the free path is not capped) …
    let big = 1 << 30;
    let s = shadow_offer(
        &l.holdings,
        &l.ledgers,
        l.own,
        quota_with_free(&l, big),
        latch_off,
        &offer(l.w, block(0x57, 9), MIB),
        &p,
    );
    assert_eq!(s.admit, HolderAdmit::Free);
    // … but once the whale has a notified holding here, Р-17 guards the free path, and a
    // re-offer of the notified block itself is Р-26.
    l.holdings[2] = notified(l.holdings[2].clone());
    let s = shadow_offer(
        &l.holdings,
        &l.ledgers,
        l.own,
        quota_with_free(&l, big),
        latch_off,
        &offer(l.w, block(0x57, 9), MIB),
        &p,
    );
    assert_eq!(
        s.admit,
        HolderAdmit::Reject(HolderReject::GuardWhileNotified)
    );
    assert_eq!(s.offerer_notified_bytes, 5 * MIB);
    let s = shadow_offer(
        &l.holdings,
        &l.ledgers,
        l.own,
        quota_with_free(&l, big),
        latch_off,
        &offer(l.w, block(0x57, 0), MIB),
        &p,
    );
    assert_eq!(s.admit, HolderAdmit::Reject(HolderReject::NotifiedBlock));
    // A friend without notified holdings still goes free.
    let s = shadow_offer(
        &l.holdings,
        &l.ledgers,
        l.own,
        quota_with_free(&l, big),
        latch_off,
        &offer(l.f, block(0x46, 9), MIB),
        &p,
    );
    assert_eq!(s.admit, HolderAdmit::Free);
    assert_eq!(s.admit.tag(), "free");
    assert!(s.admit.admits());
}

/// H-12 (W-6): an offer record carries owner aggregates (no holdings) and the view holdings
/// of the candidate victim only.
#[test]
fn the_offer_record_carries_owner_aggregates_and_only_the_victims_holdings() {
    let p = s1_params();
    let l = laptop();
    let q = quota_with_free(&l, 3 * MIB);
    let o = offer(l.f, block(0x46, 9), MIB);
    let s = shadow_offer(
        &l.holdings,
        &l.ledgers,
        l.own,
        q,
        EvictPhase::default(),
        &o,
        &p,
    );
    let rec = raw_offer_record(
        &l.holdings,
        &l.ledgers,
        l.own,
        q,
        &o,
        &p,
        &s,
        false,
        123,
        77,
    );
    assert_eq!(rec.kind, "offer");
    assert!(rec.owners.iter().all(|x| x.holdings.is_empty()));
    let hex = |x: &IdentityPub| crate::types::hex_encode(&x.0);
    let w = rec.owners.iter().find(|x| x.master == hex(&l.w)).unwrap();
    assert_eq!(w.parked_bytes, 20 * MIB);
    let vh = rec.victim_holdings.as_ref().expect("victim holdings");
    assert_eq!(vh.len(), 4);
    assert_eq!(vh.iter().map(|h| h.bytes).sum::<u64>(), 20 * MIB);
    let off = rec.offer.as_ref().unwrap();
    assert_eq!(
        (
            off.owner.clone(),
            off.offer_bytes,
            off.old_accept,
            off.old_held_bytes
        ),
        (hex(&l.f), MIB, false, 123)
    );
    assert!(!off.offer_block_notified);
    let a = rec.out.admit.as_ref().unwrap();
    assert_eq!(a.tag, "Preempt");
    assert_eq!(a.victim, Some(hex(&l.w)));
    assert_eq!(a.candidate, Some(hex(&l.w)));
    assert_eq!(a.victims.len(), 1);
    assert_eq!(a.victim_bytes, 5 * MIB);
    assert!(rec.presence.is_empty() && rec.old_plan.is_none());
}
