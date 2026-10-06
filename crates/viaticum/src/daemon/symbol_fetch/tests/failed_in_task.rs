// restore-i44: a holder whose request failed in a task (a restore job, a DR run) is asked
// after every other holder for the rest of the task, so a connected holder that keeps
// silent costs the task one failed request, not one per block. Child of
// `symbol_fetch/tests.rs` (reuses `ScriptedHolders`).

use viaticum_core::types::{DeviceId, SourceBlockId};

use super::super::rounds::holder_order_key;
use super::{Behavior, BlockFetch, FailedInTask, ScriptedHolders, encoder, params, placement};

const T: usize = 4;
const BLOCKS: u8 = 16;

fn dev(b: u8) -> DeviceId {
    DeviceId([b; 32])
}

fn blk(i: u8) -> SourceBlockId {
    SourceBlockId([i; 32])
}

/// Three connected holders of every block, 5 ESIs each, k_eff = 5: any one that answers
/// completes the block. `silent` fails every request.
fn holders(silent: DeviceId, ids: &[DeviceId]) -> ScriptedHolders {
    let mut h = ScriptedHolders::new(
        T,
        ids.iter()
            .map(|d| {
                let b = if *d == silent {
                    Behavior::AlwaysFail
                } else {
                    Behavior::Serve
                };
                (*d, b)
            })
            .collect(),
    );
    h.connected = ids.iter().copied().collect();
    h
}

/// Fetch `BLOCKS` blocks, one round each; with `task` they share the failed holders.
async fn fetch_all(source: &ScriptedHolders, ids: &[DeviceId], task: Option<&FailedInTask>) {
    let placements: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, d)| placement(*d, i as u32 * 5, 5))
        .collect();
    let (enc, p) = (encoder(), params(5, T as u16));
    for i in 0..BLOCKS {
        let b = blk(i);
        let mut fetch = BlockFetch::new(&enc, &b, &placements, &p, 5);
        if let Some(task) = task {
            fetch = fetch.in_task(task);
        }
        fetch.round(source, None).await.unwrap();
    }
}

/// Mutation: the failure not kept in the task, or not used in the order → the silent
/// holder is asked on every block where restore-i43 puts it first; reddens.
#[tokio::test]
async fn a_silent_connected_holder_costs_the_task_one_request_not_one_per_block() {
    let ids = [dev(0x11), dev(0x22), dev(0x33)];
    let silent = ids[0];
    let first_on: usize = (0..BLOCKS)
        .filter(|i| {
            let b = blk(*i);
            ids.iter().min_by_key(|d| holder_order_key(&b, d)) == Some(&silent)
        })
        .count();
    assert!(
        first_on >= 2,
        "the silent holder is first by the per-block order on {first_on} blocks: \
         the test needs at least two"
    );

    // Without the task's memory: asked on every block where it is first (the cost).
    let alone = holders(silent, &ids);
    fetch_all(&alone, &ids, None).await;
    assert_eq!(alone.asked(silent).len(), first_on);

    // With it: asked once, on the first block where it came first.
    let task = FailedInTask::default();
    let shared = holders(silent, &ids);
    fetch_all(&shared, &ids, Some(&task)).await;
    assert_eq!(
        shared.asked(silent).len(),
        1,
        "one failed request for the whole task"
    );
    let served: usize = ids[1..].iter().map(|d| shared.asked(*d).len()).sum();
    assert_eq!(
        served, BLOCKS as usize,
        "every block from the others, once each"
    );
}

/// The tail is an order, not a ban: a block the others cannot complete still asks the
/// holder that failed earlier in the task.
#[tokio::test]
async fn a_holder_that_failed_earlier_is_still_asked_when_the_others_are_not_enough() {
    let (silent, other) = (dev(0x11), dev(0x22));
    let task = FailedInTask::default();
    let mut source = ScriptedHolders::new(
        T,
        vec![(silent, Behavior::AlwaysFail), (other, Behavior::Serve)],
    );
    source.connected = [silent, other].into_iter().collect();
    let (enc, p) = (encoder(), params(5, T as u16));

    // Block 0: only the silent holder holds it — its request fails, the task remembers.
    let b0 = blk(0);
    let only_silent = [placement(silent, 0, 5)];
    let mut f0 = BlockFetch::new(&enc, &b0, &only_silent, &p, 5).in_task(&task);
    f0.round(&source, None).await.unwrap();
    assert_eq!(source.asked(silent).len(), 1);

    // Block 1: the other holder has 3 of the 5 needed; the silent one is asked after it.
    let b1 = blk(1);
    let both = [placement(other, 0, 3), placement(silent, 3, 5)];
    let mut f1 = BlockFetch::new(&enc, &b1, &both, &p, 5).in_task(&task);
    f1.round(&source, None).await.unwrap();
    let log = source.log.lock().unwrap();
    let order: Vec<DeviceId> = log[1..].iter().map(|(h, _)| *h).collect();
    assert_eq!(
        order,
        vec![other, silent],
        "the others first, then the tail"
    );
}
