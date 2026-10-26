// backup-i28-b / i28-d: the order within the SS blocks. (b) The oldest SS block that is not
// restorable yet (strength < 1) goes first; a block displaced out of its pointer place and
// waiting to be retired (`to_retire`) is not in (b). (c) Else the plain order. The rig is the
// one of `tests_ss_fairness.rs`.

use std::time::Duration;

use viaticum_core::mailbox::seal::PointerPlace;
use viaticum_core::system_state::CatalogLineageId;
use viaticum_core::system_state::catalog::{PlacePublication, PointerPublications, RetiredPointer};
use viaticum_core::types::{DeviceId, SourceBlockId, Timestamp};

use super::WorkPipeline;
use super::tests_ss_fairness::{K_EFF, Rig, attempt, next};

/// backup-i28-b. Mutation «no step (b)» → the restorable base (higher priority) goes first;
/// mutation «(b) without strength < 1» (the oldest SS block at all) → the older base goes
/// first; mutation «(b) only for never-attempted blocks without a holder» (the old i28-a rule)
/// → after one attempt the restorable base goes; each reddens.
#[tokio::test]
async fn unrestorable_ss_block_goes_before_a_re_pick_of_a_restorable_one_also_when_tried() {
    let rig = Rig::new();
    rig.ss(0x40, 3, 1000);
    let diff = rig.ss(0x41, 0, 2000);
    let mut p = rig.pipeline(Some(0x61)).await;
    assert_eq!(attempt(&rig, &mut p).await, diff, "the new diff first");
    assert_eq!(
        next(&p),
        diff,
        "tried and still not restorable: it keeps its place before the re-pick"
    );
}

/// backup-i28-b, review W1. A base half placed (one holder, half a copy: strength 0.5) goes
/// before a newer diff without holders. Mutation «(b) = no live holder and never attempted»
/// (the old i28-a rule) → the diff goes first; reddens.
#[tokio::test]
async fn partially_placed_base_goes_before_a_new_diff() {
    let rig = Rig::new();
    let base = rig.ss_with(0x50, 1, K_EFF / 2, 1000, 1);
    rig.ss(0x51, 0, 2000);
    let mut p = rig.pipeline(Some(0x62)).await;
    assert_eq!(
        attempt(&rig, &mut p).await,
        base,
        "the older unrestorable block first"
    );
    assert_eq!(next(&p), base, "and again while it is not restorable");
}

/// backup-i28-b: age is the record's `created_at`, not the ledger generation — the generation
/// restarts at 1 with every process. Mutation «order (b) by generation first» → the new base
/// (generation 1) goes before the base of the earlier process (generation 5); reddens.
#[tokio::test]
async fn base_of_an_earlier_process_goes_before_the_new_base() {
    let rig = Rig::new();
    let old_base = rig.ss_with(0x60, 1, K_EFF / 2, 1000, 5);
    rig.ss_with(0x61, 0, K_EFF, 2000, 1);
    let p = rig.pipeline(None).await;
    assert_eq!(next(&p), old_base);
}

/// backup-i28-b, review W2: the order within SS does not depend on the RAM cooldown. A tried
/// block that is not restorable goes first once out of its cooldown, as after a cooldown
/// reset. Mutation «(b) only for never-attempted blocks» → the restorable base goes first
/// before the reset; reddens.
#[tokio::test]
async fn unrestorable_ss_block_goes_first_whether_or_not_cooldowns_were_reset() {
    let rig = Rig::new();
    let base = rig.ss(0x70, 3, 1000);
    let diff = rig.ss(0x71, 0, 2000);
    let p = rig.pipeline(None).await;
    let now = Timestamp::now();
    let (cd, parked, sig) = (Duration::from_secs(30), Duration::from_secs(3600), 7);
    // Tried 60 s ago with the same pool: out of its 30 s cooldown.
    rig.db
        .set_block_cooldown(&diff, Some(Timestamp(now.0 - 60)), sig, false);
    let pick = |p: &WorkPipeline| {
        p.next_block(cd, parked, now, sig)
            .unwrap()
            .map(|r| r.block_id)
    };
    assert_eq!(pick(&p), Some(diff), "tried, out of cooldown: first");
    p.reset_all_cooldowns();
    assert_eq!(pick(&p), Some(diff), "after a reset: the same");
    // In its cooldown it is not eligible: the re-pick of the base goes.
    rig.db.set_block_cooldown(&diff, Some(now), sig, false);
    assert_eq!(pick(&p), Some(base));
}

fn place(place: PointerPlace, base: SourceBlockId) -> PlacePublication {
    PlacePublication {
        place,
        base,
        diffs: vec![],
        generation: 1,
        created_at: Timestamp(2000),
        files: 1,
        acks: vec![],
        entry_cbor: vec![],
        target_sig: [0; 64],
        last_refusal: None,
        to_retire: vec![],
        reached: None,
    }
}

/// backup-i28-d: a weak base displaced out of its place (in the new record's `to_retire`,
/// retired once the new base reaches the threshold; DR readiness does not count it) does not
/// go before the new base, though it is older. With nothing else to work it is still worked
/// (the plain order). Mutation «no `to_retire` exclusion in (b)» → the displaced base goes
/// first; reddens.
#[tokio::test]
async fn displaced_base_waiting_to_be_retired_does_not_go_before_the_new_base() {
    let rig = Rig::new();
    let displaced = rig.ss_with(0x80, 1, K_EFF / 2, 1000, 1);
    let new_base = rig.ss(0x81, 0, 2000);
    let mut current = place(PointerPlace::A, new_base);
    current.to_retire = vec![RetiredPointer {
        base: displaced,
        diffs: vec![],
    }];
    rig.db
        .put_pointer_publications(&PointerPublications {
            current: Some(current),
            kad_near: vec![DeviceId([0xE0; 32])],
            ..PointerPublications::new(CatalogLineageId([1; 16]))
        })
        .unwrap();
    let p = rig.pipeline(None).await;
    assert_eq!(
        next(&p),
        new_base,
        "the new base first, the displaced one waits"
    );

    // The new base reaches its target (no longer worked): the displaced one is worked, in the
    // plain order.
    let mut rec = rig.db.get_source_block(&new_base).unwrap().unwrap();
    rec.current_reliability = rec.target_reliability;
    rig.db.upsert_source_block(&rec).unwrap();
    assert_eq!(next(&p), displaced);
}
