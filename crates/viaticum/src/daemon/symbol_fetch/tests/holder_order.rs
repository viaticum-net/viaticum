// restore-i43: a round asks the holders we are connected to first; the rest (and the
// connected among themselves) go in an order shuffled per block — never the
// `SYMBOL_PLACEMENTS` key order (block ‖ device_id). Child of `symbol_fetch/tests.rs`
// (reuses `ScriptedHolders`).

use std::collections::HashSet;

use viaticum_core::types::{DeviceId, SourceBlockId};

use super::super::rounds::holder_order_key;
use super::{Behavior, BlockFetch, ScriptedHolders, encoder, params, placement};

const T: usize = 4;

fn dev(b: u8) -> DeviceId {
    DeviceId([b; 32])
}

fn blk(i: u8) -> SourceBlockId {
    SourceBlockId([i; 32])
}

/// Holders `ids`, each with 5 ESIs of its own and serving them; k_eff = 5, so the
/// first holder asked completes the block alone.
fn serving(ids: &[DeviceId], connected: &[DeviceId]) -> ScriptedHolders {
    let mut h = ScriptedHolders::new(T, ids.iter().map(|d| (*d, Behavior::Serve)).collect());
    h.connected = connected.iter().copied().collect();
    h
}

/// The holders of one block in the order the first round asks them, every holder
/// failing so that all of them are asked once.
async fn ask_order(
    block: SourceBlockId,
    ids: &[DeviceId],
    connected: &[DeviceId],
) -> Vec<DeviceId> {
    let mut holders =
        ScriptedHolders::new(T, ids.iter().map(|d| (*d, Behavior::AlwaysFail)).collect());
    holders.connected = connected.iter().copied().collect();
    let placements: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(i, d)| placement(*d, i as u32 * 5, 5))
        .collect();
    let (enc, p) = (encoder(), params(5, T as u16));
    let mut fetch = BlockFetch::new(&enc, &block, &placements, &p, 5);
    fetch.round(&holders, None).await.unwrap();
    let order: Vec<DeviceId> = holders
        .log
        .lock()
        .unwrap()
        .iter()
        .map(|(h, _)| *h)
        .collect();
    order
}

/// Mutation "order back by key" (no sort in `round`) → the cold 0x01 is asked first;
/// mutation "shuffle only, no connected-first" → on some of the blocks a cold holder
/// is first. Both redden.
#[tokio::test]
async fn connected_holder_with_larger_id_is_asked_before_cold_holder_with_smaller_id() {
    let cold = [dev(0x01), dev(0x02), dev(0x03)];
    let hot = dev(0xF0);
    for i in 0..16u8 {
        let ids = [cold[0], cold[1], cold[2], hot];
        let holders = serving(&ids, &[hot]);
        let placements: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(j, d)| placement(*d, j as u32 * 5, 5))
            .collect();
        let (enc, p, b) = (encoder(), params(5, T as u16), blk(i));
        let mut fetch = BlockFetch::new(&enc, &b, &placements, &p, 5);

        fetch.round(&holders, None).await.unwrap();

        let log = holders.log.lock().unwrap();
        assert_eq!(
            log.len(),
            1,
            "block {i}: the connected holder alone completes it"
        );
        assert_eq!(
            log[0].0, hot,
            "block {i}: the connected holder is asked first"
        );
    }
}

/// Mutation "no shuffle" (cold holders in device-id order) → 0x01 is first on every
/// block; reddens.
#[tokio::test]
async fn cold_holders_order_differs_across_blocks() {
    let ids = [dev(0x01), dev(0x02), dev(0x03), dev(0x04)];
    let mut first: HashSet<DeviceId> = HashSet::new();
    for i in 0..32u8 {
        let order = ask_order(blk(i), &ids, &[]).await;
        assert_eq!(order.len(), ids.len(), "block {i}: every holder asked once");
        first.insert(order[0]);
    }
    assert!(
        first.len() > 1,
        "over 32 blocks the first cold holder asked is not always the same one: {first:?}"
    );
}

/// The same block, the same holders, the same connected set: the same order, whatever
/// order the placements come in (DR reads them from the SystemState pointer, restore
/// from the key order). Within the connected group the order is the shuffle too.
#[tokio::test]
async fn holder_order_is_deterministic_for_a_block() {
    let ids = [dev(0x11), dev(0x22), dev(0x33), dev(0x44), dev(0x55)];
    let b = blk(7);
    let by_key = |set: &[DeviceId]| {
        let mut v = set.to_vec();
        v.sort_by_key(|d| holder_order_key(&b, d));
        v
    };
    // The connected pair are the LAST two of the block's shuffle, so the shuffle alone
    // (no connected-first) cannot produce the expected order by chance.
    let shuffled = by_key(&ids);
    let hot = [shuffled[4], shuffled[3]];
    let mut reversed = ids;
    reversed.reverse();

    let a = ask_order(b, &ids, &hot).await;
    let again = ask_order(b, &reversed, &hot).await;

    assert_eq!(a, again);
    let cold: Vec<DeviceId> = ids.iter().copied().filter(|d| !hot.contains(d)).collect();
    let mut expected = by_key(&hot);
    expected.extend(by_key(&cold));
    assert_eq!(
        a, expected,
        "connected first, each group in the block's shuffle"
    );
}
