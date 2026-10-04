// repair-i8 / repair-i10 (C-SP K1b): fresh ESIs come from a cursor that never goes back —
// max(`esi_high_water`, end of every row, namespace start) — and stop at 2^24 whatever the
// cluster namespace.

use std::time::Instant;

use viaticum_core::constants::MAX_ESI_EXCLUSIVE;
use viaticum_core::placement::HolderCandidate;
use viaticum_core::types::{PlacementStatus, SourceBlockRecord, SourceBlockStatus, Timestamp};

use super::super::{OfferPlan, PlannedOffer, plan_offers, record_offers};
use super::{NS, block, candidate, device, intersects, make_db, owner, row, tick_all_reject};
use crate::daemon::work_pipeline::EsiSpace;

fn stored_high_water(db: &viaticum_core::db::Db, block: &SourceBlockRecord) -> u32 {
    db.get_source_block(&block.block_id)
        .unwrap()
        .unwrap()
        .esi_high_water
}

fn set_high_water(db: &viaticum_core::db::Db, block: &SourceBlockRecord, high_water: u32) {
    let mut record = db.get_source_block(&block.block_id).unwrap().unwrap();
    record.esi_high_water = high_water;
    db.upsert_source_block(&record).unwrap();
}

fn plan(
    db: &viaticum_core::db::Db,
    block: &SourceBlockRecord,
    pool: &[HolderCandidate],
    namespace_start: u32,
) -> OfferPlan {
    plan_offers(db, block, pool, namespace_start).unwrap()
}

fn ends(offers: &[PlannedOffer]) -> u32 {
    offers
        .iter()
        .flat_map(|o| o.esi_ranges.iter())
        .map(|&(start, count)| start + count)
        .max()
        .unwrap_or(0)
}

/// Device 1 is offered the block (the top range); returns its range.
fn offer_to_device_1(db: &viaticum_core::db::Db, block: &SourceBlockRecord) -> Vec<(u32, u32)> {
    let offers = tick_all_reject(db, block, &[candidate(1, 0.9)]);
    assert_eq!(offers.len(), 1, "setup: one offer");
    offers[0].esi_ranges.clone()
}

/// The next plan, for device 2 only.
fn offer_to_device_2(db: &viaticum_core::db::Db, block: &SourceBlockRecord) -> Vec<(u32, u32)> {
    match plan(db, block, &[candidate(2, 0.9)], NS) {
        OfferPlan::Planned { offers, .. } => offers[0].esi_ranges.clone(),
        other => panic!("expected a plan, got {other:?}"),
    }
}

// ─── esi_high_water: written with the Offered rows, never goes back ────────────

/// repair-i8. The offer txn raises `esi_high_water` to the end of the highest range offered;
/// a block that left service gets neither rows nor a raised cursor (same txn).
#[test]
fn high_water_is_written_in_the_offered_transaction() {
    let db = make_db();
    let block = block(&db, 5);
    assert_eq!(stored_high_water(&db, &block), 0);

    let offers = tick_all_reject(&db, &block, &[candidate(1, 0.9), candidate(2, 0.9)]);

    assert_eq!(stored_high_water(&db, &block), ends(&offers));
    assert!(stored_high_water(&db, &block) > NS);

    // Control: the block left service between plan and write — nothing is raised.
    let next = match plan(&db, &block, &[candidate(3, 0.9)], NS) {
        OfferPlan::Planned { offers, .. } => offers,
        other => panic!("expected a plan, got {other:?}"),
    };
    let before = stored_high_water(&db, &block);
    let mut deleting = db.get_source_block(&block.block_id).unwrap().unwrap();
    deleting.status = SourceBlockStatus::Deleting;
    db.upsert_source_block(&deleting).unwrap();
    assert!(
        record_offers(&db, owner(), &block, &next, Timestamp::now())
            .unwrap()
            .is_empty()
    );
    assert_eq!(stored_high_water(&db, &block), before);
}

/// repair-i8. Mutation M9: the cursor without `esi_high_water` → after the top row is
/// overwritten with a lower range, device 2 is offered numbers device 1 was given; reddens.
#[test]
fn cursor_does_not_go_back_after_top_row_is_overwritten() {
    let db = make_db();
    let block = block(&db, 5);
    let given = offer_to_device_1(&db, &block);
    // The top row now names a range below what was given out.
    db.upsert_placement(&row(&block, device(1), PlacementStatus::Lost, vec![(0, 1)]))
        .unwrap();

    let fresh = offer_to_device_2(&db, &block);

    assert!(
        !intersects(&fresh, &given),
        "device 2 got {fresh:?}, device 1 was given {given:?}"
    );
}

/// repair-i8. Mutation M9: the cursor without `esi_high_water` → after the top row is
/// deleted, device 2 is offered numbers device 1 was given; reddens.
#[test]
fn cursor_does_not_go_back_after_top_row_is_deleted() {
    let db = make_db();
    let block = block(&db, 5);
    let given = offer_to_device_1(&db, &block);
    db.delete_placement(&block.block_id, &device(1)).unwrap();

    let fresh = offer_to_device_2(&db, &block);

    assert!(
        !intersects(&fresh, &given),
        "device 2 got {fresh:?}, device 1 was given {given:?}"
    );
}

/// The stored cursor never goes down: a writer with an older copy of the record (cached
/// fields, the deletion executor) keeps the larger value.
#[test]
fn high_water_survives_a_write_of_an_older_record_copy() {
    let db = make_db();
    let block = block(&db, 5);
    let stale_copy = db.get_source_block(&block.block_id).unwrap().unwrap();
    tick_all_reject(&db, &block, &[candidate(1, 0.9)]);
    let raised = stored_high_water(&db, &block);
    assert!(raised > 0, "setup: the offer raised the cursor");

    db.upsert_source_block(&stale_copy).unwrap();

    assert_eq!(stored_high_water(&db, &block), raised);
}

// ─── repair-i10: a Lost device and a sibling get fresh numbers ─────────────────

/// repair-i10. Device 1's row (bottom of the block) is `Lost`; repair plans device 1 again.
/// Mutation M10 (a `Lost` device gets its old range back) → the offer reuses 0..7; reddens.
#[test]
fn lost_device_gets_a_fresh_range() {
    let db = make_db();
    let block = block(&db, 5);
    let lost_range = vec![(NS, 7)];
    db.upsert_placement(&row(
        &block,
        device(1),
        PlacementStatus::Lost,
        lost_range.clone(),
    ))
    .unwrap();
    for i in 1..4u8 {
        let start = NS + 7 * u32::from(i);
        db.upsert_placement(&row(
            &block,
            device(1 + i),
            PlacementStatus::Alive,
            vec![(start, 7)],
        ))
        .unwrap();
    }

    let offers = tick_all_reject(&db, &block, &[candidate(1, 0.9)]);

    assert_eq!(offers.len(), 1);
    assert!(
        !intersects(&offers[0].esi_ranges, &lost_range),
        "the Lost device got {:?}, its old range is {lost_range:?}",
        offers[0].esi_ranges
    );
    assert!(
        offers[0]
            .esi_ranges
            .iter()
            .all(|&(start, _)| start >= NS + 28)
    );
}

/// repair-i8, cluster-i2. H1 announced an advance DropNotice (row `Lost`, the symbols stay
/// on its disk until the deadline); repair places the block on H2, a sibling of H1. H2 must
/// get numbers H1 does not hold — otherwise H1's final DropNotice or a PoS of H2 could touch
/// the other device's placement. Mutation M8 (cursor skips `Lost` rows) → H2 gets H1's range.
#[test]
fn repair_after_advance_drop_notice_gives_fresh_range_to_sibling() {
    let db = make_db();
    let block = block(&db, 5);
    let h1_range = vec![(NS + 7, 7)];
    db.upsert_placement(&row(
        &block,
        device(1),
        PlacementStatus::Alive,
        vec![(NS, 7)],
    ))
    .unwrap();
    db.upsert_placement(&row(
        &block,
        device(2),
        PlacementStatus::Lost,
        h1_range.clone(),
    ))
    .unwrap();
    let h2 = device(3);

    let offers = match plan(&db, &block, &[candidate(3, 0.9)], NS) {
        OfferPlan::Planned { offers, .. } => offers,
        other => panic!("expected a plan, got {other:?}"),
    };

    assert_eq!(offers[0].device_id, h2);
    assert!(
        !intersects(&offers[0].esi_ranges, &h1_range),
        "the sibling got {:?}, H1 still holds {h1_range:?}",
        offers[0].esi_ranges
    );
}

// ─── the 2^24 ceiling ──────────────────────────────────────────────────────────

/// C-SP §2.6: the ceiling is 2^24 for every device; the cluster namespace is only where the
/// cursor starts. Mutation M11 (ceiling = end of the namespace, NS + 2^20) → this plan is cut
/// at 4·2^20; reddens.
#[test]
fn ceiling_is_2_pow_24_regardless_of_cluster_namespace() {
    let db = make_db();
    let block = block(&db, 5);
    let namespace_end = NS + (1 << 20);
    set_high_water(&db, &block, namespace_end - 2);

    let (offers, esi_cut) = match plan(&db, &block, &[candidate(1, 0.9), candidate(2, 0.9)], NS) {
        OfferPlan::Planned {
            offers, esi_cut, ..
        } => (offers, esi_cut),
        other => panic!("expected a plan, got {other:?}"),
    };

    assert!(!esi_cut);
    assert!(
        offers
            .iter()
            .all(|o| { o.esi_ranges.iter().map(|&(_, c)| c).sum::<u32>() == o.share })
    );
    assert!(
        ends(&offers) > namespace_end,
        "fresh numbers continue past the namespace"
    );
}

/// C-SP §2.6: at the ceiling the plan offers only what is left below 2^24 (defer-not-refuse)
/// and the block is reported "not repairable"; with nothing left the plan is `EsiExhausted`.
/// Mutation M12 (no cut) → a range reaches past 2^24 (raptorq would panic); reddens.
#[test]
fn plan_is_cut_at_2_pow_24_and_block_reported_not_repairable() {
    let db = make_db();
    let block = block(&db, 5);
    set_high_water(&db, &block, MAX_ESI_EXCLUSIVE - 3);
    let pool = [candidate(1, 0.9), candidate(2, 0.9), candidate(3, 0.9)];
    let space = EsiSpace::default();

    let (cursor, offers, esi_cut) = match plan(&db, &block, &pool, NS) {
        OfferPlan::Planned {
            cursor,
            offers,
            esi_cut,
        } => (cursor, offers, esi_cut),
        other => panic!("expected a plan, got {other:?}"),
    };
    // What the worker does with the plan.
    space.note_plan(
        block.block_id,
        esi_cut,
        super::super::high_water_after(&offers, cursor),
        Instant::now(),
    );

    assert!(esi_cut);
    assert_eq!(ends(&offers), MAX_ESI_EXCLUSIVE);
    let offered: u32 = offers
        .iter()
        .flat_map(|o| o.esi_ranges.iter())
        .map(|&(_, c)| c)
        .sum();
    assert_eq!(offered, 3, "only the three numbers left are offered");
    assert_eq!(space.exhausted_blocks(), vec![block.block_id]);

    // Nothing left: no offer at all.
    record_offers(&db, owner(), &block, &offers, Timestamp::now()).unwrap();
    assert_eq!(stored_high_water(&db, &block), MAX_ESI_EXCLUSIVE);
    let more = [candidate(4, 0.9), candidate(5, 0.9)];
    assert!(matches!(
        plan(&db, &block, &more, NS),
        OfferPlan::EsiExhausted { cursor } if cursor == MAX_ESI_EXCLUSIVE
    ));
}
