// NOTE 3 of the spec v3.12b ([cross:A], no wire): the holder's quota counts only the ESIs of an
// offer it does not hold yet for (owner, block). After a yield the owner re-offers the whole range
// of the placement; what the holder already stores is in its held bytes and must not be asked for
// twice. A child of `processor/tests.rs`.

use tempfile::TempDir;
use viaticum_core::constants::SYMBOL_SIZE;
use viaticum_core::db::Db;
use viaticum_core::erasure::Symbol;
use viaticum_core::messages::{Message, SymbolTransferMsg, build_symbol_offer};
use viaticum_core::types::{
    DeviceId, HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp,
};

use super::{make_block_id, make_processor_with_quota};

const SYM: u64 = SYMBOL_SIZE as u64;

fn owner_key() -> (ed25519_dalek::SigningKey, IdentityPub) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x2A; 32]);
    let master = IdentityPub(key.verifying_key().to_bytes());
    (key, master)
}

fn holding(block: SourceBlockId, owner: IdentityPub, esis: Vec<(u32, u32)>) -> HoldingRecord {
    let symbols: u64 = esis.iter().map(|&(_, c)| u64::from(c)).sum();
    HoldingRecord {
        source_block_id: block,
        owner_id: owner,
        esi_ranges: esis,
        importance: 0.5,
        total_bytes: symbols * SYM,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

/// A holder with a soft quota of `quota_symbols` symbols and `other_symbols` held for another
/// block of another owner.
async fn holder(quota_symbols: u64, other_symbols: u32) -> (super::Processor, Db, TempDir) {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor_with_quota(db.clone(), &dir, quota_symbols * SYM, u64::MAX).await;
    db.upsert_holding(&holding(
        make_block_id(0x91),
        IdentityPub([0x92; 32]),
        vec![(0, other_symbols)],
    ))
    .unwrap();
    (p, db, dir)
}

fn offer(
    key: &ed25519_dalek::SigningKey,
    block: SourceBlockId,
    ranges: Vec<(u32, u32)>,
) -> viaticum_core::messages::SymbolOfferMsg {
    build_symbol_offer([7; 16], block, ranges, 0.5, Timestamp::now(), key)
}

fn accepted(reply: &Message) -> bool {
    match reply {
        Message::SymbolAccept(_) => true,
        Message::SymbolReject(_) => false,
        other => panic!("not an answer to an offer: {other:?}"),
    }
}

/// M98 (v3.12b NOTE 3). A re-offer of the whole range counts only the ESIs not held: 20 symbols
/// of others + 5 of this block held, quota 30: the full range of 6 asks for 1 more (26 ≤ 30) and is
/// accepted; counted whole it would be 25 + 6 = 31 and refused. Seven NEW ESIs (24 + 7 = 31) are
/// still refused, and a block the holder has none of counts in full: the rule is not off.
#[tokio::test]
async fn reoffer_counts_only_unheld_esis_against_the_quota() {
    let (key, master) = owner_key();
    let blk = make_block_id(0x93);
    let (p, db, _dir) = holder(30, 20).await;
    // 5 of the 6 held: counted whole the offer is 25 + 6 = 31 > 30.
    db.upsert_holding(&holding(blk, master, vec![(0, 5)]))
        .unwrap();

    let again =
        p.handle_symbol_offer_inner(DeviceId(master.0), master, offer(&key, blk, vec![(0, 6)]));
    assert!(
        accepted(&again),
        "the rest is one symbol: 25 + 1 ≤ 30, accepted: {again:?}"
    );

    let (p2, db2, _dir2) = holder(30, 20).await;
    db2.upsert_holding(&holding(blk, master, vec![(0, 4)]))
        .unwrap();
    let too_much = p2.handle_symbol_offer_inner(
        DeviceId(master.0),
        master,
        offer(&key, blk, vec![(0, 4), (10, 7)]),
    );
    assert!(
        !accepted(&too_much),
        "seven NEW ESIs: 24 + 7 = 31 > 30 refused: {too_much:?}"
    );

    // No holding of this block: the whole range counts (as before).
    let (p3, _db3, _dir3) = holder(30, 20).await;
    let fresh =
        p3.handle_symbol_offer_inner(DeviceId(master.0), master, offer(&key, blk, vec![(0, 11)]));
    assert!(!accepted(&fresh), "20 + 11 = 31 > 30: {fresh:?}");
    let fits =
        p3.handle_symbol_offer_inner(DeviceId(master.0), master, offer(&key, blk, vec![(0, 10)]));
    assert!(accepted(&fits), "20 + 10 = 30 ≤ 30: {fits:?}");
}

/// M98 (v3.12b NOTE 3), liveness (the lesson of v3.12: completion within N, not activity). A
/// holder at the edge of its quota; the owner yields after every chunk (one chunk per turn) and
/// re-offers the whole range at every turn, sending what the holder has not acknowledged. The
/// share of 6 symbols is acknowledged in full within 6 + 1 turns. With the quota counted by the
/// whole range the holder refuses from the fifth turn on: nothing completes.
#[tokio::test]
async fn delivery_completes_to_a_holder_at_the_quota_edge_under_constant_yields() {
    let (key, master) = owner_key();
    let blk = make_block_id(0x94);
    let dev = DeviceId(master.0);
    // Quota 30 symbols, 20 held for others: at the share's 5th symbol the whole-range count
    // (25 + 6) is over the edge, the rest-only count (25 + 1) is not; the soft pressure rule
    // (15 % free) is met up to 25 held.
    let (p, db, _dir) = holder(30, 20).await;
    let share = 6u32;
    let mut acked: Vec<u32> = Vec::new();
    let mut turns = 0;
    while acked.len() < share as usize && turns < 7 {
        turns += 1;
        let reply = p.handle_symbol_offer_inner(dev, master, offer(&key, blk, vec![(0, share)]));
        if !accepted(&reply) {
            continue;
        }
        // The yield after the first chunk of the turn.
        let Some(esi) = (0..share).find(|e| !acked.contains(e)) else {
            break;
        };
        let transfer = SymbolTransferMsg {
            v: 1,
            source_block_id: blk,
            symbols: vec![Symbol {
                esi,
                data: vec![0xAB; SYMBOL_SIZE as usize],
            }],
            timestamp: Timestamp::now(),
        };
        match p.symbol_transfer_reply(dev, master, transfer).await {
            Message::SymbolStored(stored) => {
                for (start, count) in stored.esi_ranges {
                    acked.extend(start..start + count);
                }
            }
            other => panic!("the accepted chunk is stored: {other:?}"),
        }
    }
    assert_eq!(
        acked.len(),
        share as usize,
        "all {share} ESIs acknowledged within {} turns (used {turns}): {acked:?}",
        share + 1
    );
    let held = db.get_holding(&blk, &master).unwrap().unwrap();
    assert_eq!(held.esi_ranges, vec![(0, share)]);
}

#[test]
fn unheld_count_is_the_offer_without_what_is_held() {
    use super::super::symbol::unheld_esi_count;
    assert_eq!(unheld_esi_count(&[(0, 6)], &[]), 6);
    assert_eq!(unheld_esi_count(&[(0, 6)], &[(0, 4)]), 2);
    assert_eq!(unheld_esi_count(&[(0, 4), (10, 7)], &[(0, 4)]), 7);
    assert_eq!(unheld_esi_count(&[(0, 6)], &[(2, 2), (0, 1), (5, 10)]), 2);
    assert_eq!(unheld_esi_count(&[(0, 6)], &[(0, 6)]), 0);
    assert_eq!(unheld_esi_count(&[], &[(0, 6)]), 0);
}
