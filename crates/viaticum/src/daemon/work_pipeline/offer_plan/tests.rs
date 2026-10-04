// Offer plan tests — repair-i9 (reject part): a re-offer after `SymbolReject` reuses the
// holder's own ESI range; the cursor does not grow on repeated rejects.
//
// A reject leaves the `Offered` row exactly as `record_offers` wrote it (the worker bails out
// of the delivery, nothing touches the row), so "all peers reject" = plan + record, repeated.

use std::collections::HashMap;

use tempfile::tempdir;
use viaticum_core::db::Db;
use viaticum_core::erasure::binding_seed;
use viaticum_core::placement::{HolderAllocation, HolderCandidate};
use viaticum_core::types::{
    DeviceId, FileId, PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus,
    SourceBlockType, SymbolPlacement, Timestamp,
};

use super::{
    OfferPlan, PlannedOffer, assign_esi_ranges, esi_cursor, plan_offers, record_offers,
    union_ranges,
};

const SYMBOL: u64 = 65_535;
/// Device index 3 in a cluster: fresh numbers start at 3·2^20.
const NS: u32 = 3 << 20;

fn make_db() -> Db {
    let dir = tempdir().unwrap();
    Db::open(&dir.keep().join("test.redb")).unwrap()
}

fn device(byte: u8) -> DeviceId {
    let mut b = [0u8; 32];
    b[0] = byte;
    DeviceId(b)
}

fn owner() -> DeviceId {
    device(0)
}

/// A block of `k` source symbols, stored in the DB.
fn block(db: &Db, k: u32) -> SourceBlockRecord {
    let mut id = [0u8; 32];
    id[0] = 0xB1;
    let record = SourceBlockRecord {
        seal_generation: 0,
        block_id: SourceBlockId(id),
        k,
        t: SYMBOL as u16,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp::now(),
        encrypted_size: Some(u64::from(k) * SYMBOL),
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.5,
        target_reliability: 0.99,
        current_alive: 0,
        current_reliability: 0.0,
    };
    db.upsert_source_block(&record).unwrap();
    record
}

fn candidate(byte: u8, trust: f64) -> HolderCandidate {
    HolderCandidate {
        device_id: device(byte),
        trust,
    }
}

fn row(
    block: &SourceBlockRecord,
    holder: DeviceId,
    status: PlacementStatus,
    ranges: Vec<(u32, u32)>,
) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block.block_id,
        holder_id: holder,
        file_id: FileId(0),
        esi_ranges: ranges,
        binding_seed: binding_seed(&block.block_id, &holder),
        status,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    }
}

/// One worker tick up to delivery: plan and write the `Offered` rows. Every holder then
/// rejects, which leaves the rows as written.
fn tick_all_reject(
    db: &Db,
    block: &SourceBlockRecord,
    pool: &[HolderCandidate],
) -> Vec<PlannedOffer> {
    match plan_offers(db, block, pool, NS).unwrap() {
        OfferPlan::Planned { offers, .. } => {
            record_offers(db, owner(), block, &offers, Timestamp::now()).unwrap();
            offers
        }
        other => panic!("expected a plan, got {other:?}"),
    }
}

fn cursor(db: &Db, block: &SourceBlockRecord) -> u32 {
    esi_cursor(&db.list_placements_for_block(&block.block_id).unwrap(), NS)
}

fn intersects(a: &[(u32, u32)], b: &[(u32, u32)]) -> bool {
    a.iter().any(|&(s1, c1)| {
        b.iter()
            .any(|&(s2, c2)| s1 < s2.saturating_add(c2) && s2 < s1.saturating_add(c1))
    })
}

// ─── repair-i9: pool of only rejects, 1000 ticks ────────────────────────────────

/// repair-i9, repair-i9-b. Mutations: fresh range on every retry (`assign_esi_ranges` ignores
/// the own `Offered` row) → the cursor grows by the whole plan each tick; the cursor without
/// `Offered` rows (`esi_cursor`) → fresh numbers land on reserved ranges and rows of two
/// devices overlap. Either reddens this test.
#[test]
fn reject_only_pool_1000_iterations_keeps_cursor_within_distinct_shares() {
    let db = make_db();
    let block = block(&db, 40);
    // Ten devices; each tick the pool is a rotating window of 2..=7 of them with drifting
    // trust, so shares change (full copies on a narrow pool, thinner shares on a wide one),
    // devices drop out of the plan and come back.
    let mut largest_share: HashMap<DeviceId, u32> = HashMap::new();
    let mut offered_symbols: u64 = 0;
    let mut distinct_shares_seen: HashMap<DeviceId, std::collections::HashSet<u32>> =
        HashMap::new();

    for tick in 0..1000u32 {
        let width = 2 + (tick % 6);
        let pool: Vec<HolderCandidate> = (0..width)
            .map(|j| {
                let byte = 1 + ((tick / 3 + j) % 10) as u8;
                let trust = 0.85 + 0.02 * f64::from((tick / 7 + j) % 7);
                candidate(byte, trust)
            })
            .collect();

        for offer in tick_all_reject(&db, &block, &pool) {
            let largest = largest_share.entry(offer.device_id).or_insert(0);
            *largest = (*largest).max(offer.share);
            distinct_shares_seen
                .entry(offer.device_id)
                .or_default()
                .insert(offer.share);
            offered_symbols += u64::from(offer.share);
        }

        // repair-i9-b: the rows of different devices never share an ESI.
        let rows = db.list_placements_for_block(&block.block_id).unwrap();
        for (i, r1) in rows.iter().enumerate() {
            for r2 in &rows[i + 1..] {
                assert!(
                    !intersects(&r1.esi_ranges, &r2.esi_ranges),
                    "tick {tick}: rows of two devices overlap: {:?} vs {:?}",
                    r1.esi_ranges,
                    r2.esi_ranges
                );
            }
        }

        let bound = NS + largest_share.values().sum::<u32>();
        let now = cursor(&db, &block);
        assert!(
            now <= bound,
            "tick {tick}: cursor {now} beyond namespace start + Σ largest shares = {bound}"
        );
    }

    // Not vacuous: the plans offered far more than the bound allows, shares did change,
    // and every device of the window was planned.
    let bound = u64::from(largest_share.values().sum::<u32>());
    assert!(
        offered_symbols > 10 * bound,
        "fixture: {offered_symbols} offered vs bound {bound}"
    );
    assert_eq!(largest_share.len(), 10, "fixture: all ten devices planned");
    assert!(
        distinct_shares_seen.values().any(|s| s.len() > 1),
        "fixture: some device's share must change between plans"
    );
}

// ─── repair-i9: re-offer after reject = same range, same binding ───────────────

/// repair-i9. Mutation: fresh range on every retry → the second offer's ranges differ and
/// the cursor moves; this test reddens.
#[test]
fn reoffer_after_reject_carries_same_esi_range_and_binding() {
    let db = make_db();
    let block = block(&db, 5);
    let pool = [candidate(1, 0.6), candidate(2, 0.5), candidate(3, 0.4)];

    let first = tick_all_reject(&db, &block, &pool);
    let rows_after_reject = db.list_placements_for_block(&block.block_id).unwrap();
    let cursor_after_reject = cursor(&db, &block);
    let second = tick_all_reject(&db, &block, &pool);
    let rows_after_reoffer = db.list_placements_for_block(&block.block_id).unwrap();

    assert!(!first.is_empty());
    assert_eq!(second, first, "the re-offer carries the same ranges");
    assert_eq!(union_ranges(&second), union_ranges(&first));
    assert_eq!(
        cursor(&db, &block),
        cursor_after_reject,
        "cursor did not move"
    );
    assert_eq!(rows_after_reoffer.len(), rows_after_reject.len());
    for before in &rows_after_reject {
        let after = rows_after_reoffer
            .iter()
            .find(|r| r.holder_id == before.holder_id)
            .expect("same holders");
        assert_eq!(after.status, PlacementStatus::Offered);
        assert_eq!(after.esi_ranges, before.esi_ranges, "same ESI range");
        assert_eq!(after.binding_seed, before.binding_seed, "same binding");
        assert_eq!(
            after.binding_seed,
            binding_seed(&block.block_id, &after.holder_id),
            "binding of (block, this holder) → the holder gets the same bytes"
        );
    }
}

// ─── repair-i9 condition: another device's row over the own range ──────────────

/// repair-i9 condition. Mutation: drop the "no row of another device overlaps" check in
/// `reusable_own_ranges` → A's offer keeps the range Z's row overlaps; this test reddens.
#[test]
fn reoffer_gets_fresh_numbers_when_another_device_row_overlaps_own_range() {
    let db = make_db();
    let block = block(&db, 5);
    let a = candidate(1, 0.6);
    let first = tick_all_reject(&db, &block, std::slice::from_ref(&a));
    let own = first[0].esi_ranges.clone();
    // Another device's row over A's range (a Lost row — rows like this exist from before
    // repair-i8, when the cursor skipped Lost rows and a fresh range could land on one).
    let z = row(
        &block,
        device(0x2A),
        PlacementStatus::Lost,
        vec![(own[0].0 + 1, 2)],
    );
    db.upsert_placement(&z).unwrap();
    let cursor_before = cursor(&db, &block);

    let second = tick_all_reject(&db, &block, std::slice::from_ref(&a));

    let offered = &second[0].esi_ranges;
    assert!(
        !intersects(offered, &z.esi_ranges),
        "A's new offer {offered:?} must not touch Z's row {:?}",
        z.esi_ranges
    );
    assert!(
        !intersects(offered, &own),
        "no part of the overlapped own range is reused: {offered:?} vs {own:?}"
    );
    assert!(offered.iter().all(|&(start, _)| start >= cursor_before));
}

// ─── assign_esi_ranges: share vs own range ──────────────────────────────────────

fn alloc(byte: u8, count: u32) -> HolderAllocation {
    HolderAllocation {
        device_id: device(byte),
        symbol_count: count,
        start_esi: 0,
    }
}

#[test]
fn assign_esi_ranges_when_share_grows_keeps_own_range_and_adds_only_the_difference_fresh() {
    let db = make_db();
    let block = block(&db, 5);
    let rows = [row(
        &block,
        device(1),
        PlacementStatus::Offered,
        vec![(NS, 4)],
    )];

    let offers = assign_esi_ranges(&[alloc(1, 6), alloc(2, 3)], &rows, NS + 10);

    assert_eq!(offers[0].esi_ranges, vec![(NS, 4), (NS + 10, 2)]);
    assert_eq!(offers[0].share, 6);
    assert_eq!(
        offers[1].esi_ranges,
        vec![(NS + 12, 3)],
        "fresh after A's fresh"
    );
}

/// Decision (mini-fix): an own range larger than the share is not narrowed — a narrowed row
/// could lower the cursor and hand its tail to another device (narrowing waits for
/// `esi_high_water`, C-SP K1b).
#[test]
fn assign_esi_ranges_when_share_shrinks_keeps_whole_own_range_without_fresh_numbers() {
    let db = make_db();
    let block = block(&db, 5);
    let rows = [row(
        &block,
        device(1),
        PlacementStatus::Offered,
        vec![(NS, 6)],
    )];

    let offers = assign_esi_ranges(&[alloc(1, 2), alloc(2, 3)], &rows, NS + 6);

    assert_eq!(offers[0].esi_ranges, vec![(NS, 6)]);
    assert_eq!(offers[0].share, 2);
    assert_eq!(
        offers[1].esi_ranges,
        vec![(NS + 6, 3)],
        "cursor untouched by A"
    );
}

/// Out of the mini-fix (C-SP K1b generalises): only an `Offered` row is reused.
#[test]
fn assign_esi_ranges_when_own_row_is_lost_gives_fresh_numbers() {
    let db = make_db();
    let block = block(&db, 5);
    let rows = [row(&block, device(1), PlacementStatus::Lost, vec![(NS, 4)])];

    let offers = assign_esi_ranges(&[alloc(1, 4)], &rows, NS + 4);

    assert_eq!(offers[0].esi_ranges, vec![(NS + 4, 4)]);
}

#[test]
fn union_ranges_merges_adjacent_and_sorts_across_offers() {
    let offers = [
        PlannedOffer {
            device_id: device(1),
            share: 3,
            esi_ranges: vec![(10, 3)],
        },
        PlannedOffer {
            device_id: device(2),
            share: 4,
            esi_ranges: vec![(0, 2), (13, 2)],
        },
    ];

    assert_eq!(union_ranges(&offers), vec![(0, 2), (10, 5)]);
}

// ─── repair-i8 / repair-i10: Lost and Deleting rows keep their numbers ─────────

/// Five holders of 7 ESIs each over NS..NS+35, all `Alive` except the top one (28..35).
fn five_rows_top(block: &SourceBlockRecord, top_status: PlacementStatus) -> Vec<SymbolPlacement> {
    (0..5u8)
        .map(|i| {
            let status = if i == 4 {
                top_status
            } else {
                PlacementStatus::Alive
            };
            row(
                block,
                device(1 + i),
                status,
                vec![(NS + 7 * u32::from(i), 7)],
            )
        })
        .collect()
}

/// repair-i8. Mutation: the cursor skips `Lost`/`Deleting` rows again → the cursor falls to
/// NS+28, onto numbers the top holder may still have on disk; this test reddens.
#[test]
fn esi_cursor_counts_lost_and_deleting_placements() {
    let db = make_db();
    let block = block(&db, 5);
    for status in [PlacementStatus::Lost, PlacementStatus::Deleting] {
        let rows = five_rows_top(&block, status);

        let next = esi_cursor(&rows, NS);

        assert!(
            next >= NS + 35,
            "{status:?} top row 28..35: cursor {} must stay at or above 35",
            next - NS
        );
    }
}

/// repair-i8, repair-i10 (the Fail→Lost→Alive loop seen in `local_ledger_drop_test`): F's
/// top-range row went `Lost` after a PoS Fail; repair plans F again — F must get fresh numbers,
/// none of 28..35 (the holder would call those "already held" by file length and keep the bad
/// bytes). Mutation: the cursor skips `Lost` rows → F is offered 28..35 again; this test reddens.
/// Holder side (files rewritten for fresh ESIs) is the ordinary offer path, covered in
/// `processor/tests/symbol_transfer_reply.rs`.
#[test]
fn fail_then_repair_to_same_device_gets_fresh_range() {
    let db = make_db();
    let block = block(&db, 5);
    for r in five_rows_top(&block, PlacementStatus::Lost) {
        db.upsert_placement(&r).unwrap();
    }
    let f = device(5);
    let lost_range = vec![(NS + 28, 7)];
    // The whole pool: the four Alive holders are excluded (repair-i2), F is the candidate.
    let pool: Vec<HolderCandidate> = (1..=5u8).map(|b| candidate(b, 0.6)).collect();

    let offers = tick_all_reject(&db, &block, &pool);

    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].device_id, f);
    assert!(
        !intersects(&offers[0].esi_ranges, &lost_range),
        "F's repair offer {:?} must not reuse its Lost range 28..35",
        offers[0].esi_ranges
    );
    assert!(
        offers[0]
            .esi_ranges
            .iter()
            .all(|&(start, _)| start >= NS + 35)
    );
    let rewritten = db.get_placement(&block.block_id, &f).unwrap().unwrap();
    assert_eq!(rewritten.status, PlacementStatus::Offered);
    assert_eq!(rewritten.esi_ranges, offers[0].esi_ranges);
}

// ─── repair-i16 (R1-f2, L1b): no offer for a block that left service ────────────

/// `SymbolsPlaced` events of `block` in the log.
fn placed_events(db: &Db, block: &SourceBlockRecord) -> usize {
    db.events_after(0, 10_000)
        .unwrap()
        .iter()
        .filter(|(_, e)| {
            matches!(
                e.event,
                viaticum_core::types::Event::SymbolsPlaced { source_block_id, .. }
                    if source_block_id == block.block_id
            )
        })
        .count()
}

fn planned(db: &Db, block: &SourceBlockRecord) -> Vec<PlannedOffer> {
    let pool = [candidate(1, 0.9), candidate(2, 0.9), candidate(3, 0.9)];
    match plan_offers(db, block, &pool, NS).unwrap() {
        OfferPlan::Planned { offers, .. } => offers,
        other => panic!("expected a plan, got {other:?}"),
    }
}

/// M9: the deletion executor turns the block `Deleting` between the plan and the write —
/// 0 `Offered` rows, 0 `SymbolsPlaced` events, nothing to deliver.
#[test]
fn record_offers_writes_nothing_when_block_left_service() {
    let db = make_db();
    let block = block(&db, 5);
    let offers = planned(&db, &block);
    assert!(!offers.is_empty(), "setup: a plan");
    let mut deleting = block.clone();
    deleting.status = SourceBlockStatus::Deleting;
    db.upsert_source_block(&deleting).unwrap();

    let recorded = record_offers(&db, owner(), &block, &offers, Timestamp::now()).unwrap();

    assert!(recorded.is_empty());
    assert!(
        db.list_placements_for_block(&block.block_id)
            .unwrap()
            .is_empty()
    );
    assert_eq!(placed_events(&db, &block), 0);
}

/// M9: a `Deleting` placement (a Delete published for one holder) is the same answer; the
/// other rows are untouched.
#[test]
fn record_offers_writes_nothing_when_a_placement_is_deleting() {
    let db = make_db();
    let block = block(&db, 5);
    let offers = planned(&db, &block);
    let deleting = row(&block, device(9), PlacementStatus::Deleting, vec![(0, 5)]);
    db.upsert_placement(&deleting).unwrap();

    let recorded = record_offers(&db, owner(), &block, &offers, Timestamp::now()).unwrap();

    assert!(recorded.is_empty());
    let rows = db.list_placements_for_block(&block.block_id).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, PlacementStatus::Deleting);
    assert_eq!(placed_events(&db, &block), 0);

    // Control: in service, every planned offer is written and returned.
    let other = {
        let mut b = block.clone();
        b.block_id = SourceBlockId([0xB2; 32]);
        db.upsert_source_block(&b).unwrap();
        b
    };
    let offers = planned(&db, &other);
    let recorded = record_offers(&db, owner(), &other, &offers, Timestamp::now()).unwrap();
    assert_eq!(recorded, offers);
    assert_eq!(
        placed_events(&db, &other),
        offers.iter().map(|o| o.esi_ranges.len()).sum::<usize>()
    );
}
