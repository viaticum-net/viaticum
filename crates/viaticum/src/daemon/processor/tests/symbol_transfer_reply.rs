// backup-i19 (R1-u-H1): the holder answers a SymbolTransfer with `SymbolStored` only for what is on
// its disk afterwards, and two devices of one master keep separate offers for one block. Every
// test goes through `symbol_transfer_reply` (the reply `dispatch_libp2p` sends) and checks the
// reply against the holder's own `holdings/<block>/` directory.

use tempfile::TempDir;
use viaticum_core::constants::SYMBOL_SIZE;
use viaticum_core::db::Db;
use viaticum_core::erasure::Symbol;
use viaticum_core::messages::{Message, SymbolTransferMsg, build_symbol_offer};
use viaticum_core::types::{
    DeviceId, HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp,
};

use super::{
    AcceptedOffer, Processor, insert_accepted_offer, make_block_id, make_identity, make_processor,
    make_processor_with_quota, sender_device,
};

fn chunk(block_id: SourceBlockId, esis: &[u32], byte: u8) -> SymbolTransferMsg {
    SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: esis
            .iter()
            .map(|&esi| Symbol {
                esi,
                data: vec![byte; 64],
            })
            .collect(),
        timestamp: Timestamp::now(),
    }
}

/// ESIs whose `{esi}.bin` is in the holder's `holdings/<block>/`, sorted.
fn bins_on_disk(dir: &TempDir, block_id: SourceBlockId) -> Vec<u32> {
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let Ok(rd) = std::fs::read_dir(dir.path().join(block_hex)) else {
        return Vec::new();
    };
    let mut esis: Vec<u32> = rd
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            name.strip_suffix(".bin")?.parse().ok()
        })
        .collect();
    esis.sort_unstable();
    esis
}

fn read_bin(dir: &TempDir, block_id: SourceBlockId, esi: u32) -> Vec<u8> {
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::read(dir.path().join(block_hex).join(format!("{esi}.bin"))).unwrap()
}

fn assert_ack(reply: &Message) {
    assert!(
        matches!(reply, Message::Ack(_)),
        "expected Ack, got {reply:?}"
    );
}

fn assert_stored(reply: &Message, block_id: SourceBlockId, esi_ranges: Vec<(u32, u32)>) {
    match reply {
        Message::SymbolStored(m) => {
            assert_eq!(m.source_block_id, block_id);
            assert_eq!(m.esi_ranges, esi_ranges);
        }
        other => panic!("expected SymbolStored, got {other:?}"),
    }
}

async fn reply_to(p: &Processor, owner: IdentityPub, t: SymbolTransferMsg) -> Message {
    p.symbol_transfer_reply(sender_device(owner), owner, t)
        .await
}

#[tokio::test]
async fn transfer_without_offer_replies_ack_not_stored() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x11);
    let blk = make_block_id(0x11);

    let reply = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;

    assert_ack(&reply);
    assert!(bins_on_disk(&dir, blk).is_empty());
    assert!(db.get_holding(&blk, &owner).unwrap().is_none());
}

#[tokio::test]
async fn transfer_after_offer_expired_replies_ack_not_stored() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x12);
    let blk = make_block_id(0x12);
    p.accepted_offers.lock().unwrap().insert(
        (sender_device(owner), blk),
        AcceptedOffer {
            owner_id: owner,
            from_device: sender_device(owner),
            source_block_id: blk,
            esi_ranges: vec![(0, 10)],
            importance: 0.5,
            accepted_at: Timestamp(0),
        },
    );

    let reply = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;

    assert_ack(&reply);
    assert!(bins_on_disk(&dir, blk).is_empty());
    assert!(db.get_holding(&blk, &owner).unwrap().is_none());
    assert!(p.accepted_offers.lock().unwrap().is_empty());
}

#[tokio::test]
async fn transfer_with_esi_outside_offer_replies_ack_not_stored() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x13);
    let blk = make_block_id(0x13);
    insert_accepted_offer(&p, owner, blk, vec![(0, 10)], 0.5);

    let reply = reply_to(&p, owner, chunk(blk, &[3, 999], 0xAA)).await;

    assert_ack(&reply);
    assert!(bins_on_disk(&dir, blk).is_empty());
    assert!(db.get_holding(&blk, &owner).unwrap().is_none());
    assert!(p.accepted_offers.lock().unwrap().is_empty());
}

#[tokio::test]
async fn transfer_with_oversized_symbol_replies_ack_not_stored() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x14);
    let blk = make_block_id(0x14);
    insert_accepted_offer(&p, owner, blk, vec![(0, 10)], 0.5);
    let mut t = chunk(blk, &[0, 1], 0xAA);
    t.symbols[1].data = vec![0xAA; SYMBOL_SIZE as usize + 1];

    let reply = reply_to(&p, owner, t).await;

    assert_ack(&reply);
    assert!(bins_on_disk(&dir, blk).is_empty());
    assert!(db.get_holding(&blk, &owner).unwrap().is_none());
}

#[tokio::test]
async fn empty_transfer_replies_ack() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x15);
    let blk = make_block_id(0x15);
    insert_accepted_offer(&p, owner, blk, vec![(0, 10)], 0.5);

    let reply = reply_to(&p, owner, chunk(blk, &[], 0xAA)).await;

    assert_ack(&reply);
    assert!(bins_on_disk(&dir, blk).is_empty());
}

#[tokio::test]
async fn transfer_within_offer_replies_symbol_stored_with_chunk_esis() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x16);
    let blk = make_block_id(0x16);
    insert_accepted_offer(&p, owner, blk, vec![(0, 5)], 0.5);

    let reply = reply_to(&p, owner, chunk(blk, &[3, 1], 0xAA)).await;

    assert_stored(&reply, blk, vec![(1, 1), (3, 1)]);
    assert_eq!(bins_on_disk(&dir, blk), vec![1, 3]);
    assert_eq!(
        db.get_holding(&blk, &owner).unwrap().unwrap().esi_ranges,
        vec![(1, 1), (3, 1)]
    );
}

/// Devices D1 and D2 of one master offer block B with disjoint ESI ranges (sibling ESI
/// namespaces); D2's offer arrives while D1's delivery is still pending. Both deliveries land.
#[tokio::test]
async fn sibling_offers_of_one_block_do_not_overwrite_each_other() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x17; 32]);
    let master = IdentityPub(key.verifying_key().to_bytes());
    let d1 = DeviceId([0xD1; 32]);
    let d2 = DeviceId([0xD2; 32]);
    let blk = make_block_id(0x17);

    let offer = |id: u8, ranges: Vec<(u32, u32)>| {
        build_symbol_offer([id; 16], blk, ranges, 0.5, Timestamp::now(), &key)
    };
    let r1 = p.handle_symbol_offer_inner(d1, master, offer(1, vec![(0, 3)]));
    let r2 = p.handle_symbol_offer_inner(d2, master, offer(2, vec![(100, 3)]));
    assert!(matches!(r1, Message::SymbolAccept(_)), "premise: {r1:?}");
    assert!(matches!(r2, Message::SymbolAccept(_)), "premise: {r2:?}");

    let s1 = p
        .symbol_transfer_reply(d1, master, chunk(blk, &[0, 1, 2], 0x01))
        .await;
    let s2 = p
        .symbol_transfer_reply(d2, master, chunk(blk, &[100, 101, 102], 0x02))
        .await;

    assert_stored(&s1, blk, vec![(0, 3)]);
    assert_stored(&s2, blk, vec![(100, 3)]);
    assert_eq!(bins_on_disk(&dir, blk), vec![0, 1, 2, 100, 101, 102]);
    let rec = db.get_holding(&blk, &master).unwrap().unwrap();
    assert_eq!(rec.esi_ranges, vec![(0, 3), (100, 3)]);
    assert_eq!(rec.total_bytes, 6 * 64);
}

#[tokio::test]
async fn resent_chunk_already_on_disk_replies_stored_without_rewrite() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x18);
    let blk = make_block_id(0x18);
    insert_accepted_offer(&p, owner, blk, vec![(0, 4)], 0.5);
    let first = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&first, blk, vec![(0, 2)]);

    // The reply to the first send was lost; the owner resends the same chunk.
    let resent = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;

    assert_stored(&resent, blk, vec![(0, 2)]);
    assert_eq!(bins_on_disk(&dir, blk), vec![0, 1]);
    assert_eq!(
        read_bin(&dir, blk, 0),
        vec![0xAA; 64],
        "resend must not rewrite"
    );
    let rec = db.get_holding(&blk, &owner).unwrap().unwrap();
    assert_eq!(rec.esi_ranges, vec![(0, 2)]);
    assert_eq!(rec.total_bytes, 2 * 64);
}

/// W5: the last chunk completed the offer (the offer is gone); its reply was lost and the owner
/// resends it. The symbols are on disk, so the truthful answer is `SymbolStored`.
#[tokio::test]
async fn resent_last_chunk_after_offer_completed_replies_stored() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x19);
    let blk = make_block_id(0x19);
    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let last = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&last, blk, vec![(0, 2)]);
    assert!(
        p.accepted_offers.lock().unwrap().is_empty(),
        "premise: the offer is completed and removed"
    );

    let resent = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;

    assert_stored(&resent, blk, vec![(0, 2)]);
    assert_eq!(bins_on_disk(&dir, blk), vec![0, 1]);
}

/// A HoldingRecord that lists ESIs whose files are gone is not "already held": without an offer
/// the chunk is not stored; with an offer it is written again.
#[tokio::test]
async fn held_record_without_file_is_not_already_held() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x1A);
    let blk = make_block_id(0x1A);
    db.upsert_holding(&HoldingRecord {
        source_block_id: blk,
        owner_id: owner,
        esi_ranges: vec![(0, 2)],
        importance: 0.5,
        total_bytes: 2 * 64,
        status: HoldingStatus::Active,
        received_at: Timestamp(1),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    let no_offer = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_ack(&no_offer);
    assert!(bins_on_disk(&dir, blk).is_empty());

    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let with_offer = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&with_offer, blk, vec![(0, 2)]);
    assert_eq!(bins_on_disk(&dir, blk), vec![0, 1]);
}

/// A holding the owner asked to delete (MarkedForDelete, swept after the cooldown) is not
/// "already held", even with its files on disk: a resent chunk goes through the offer path, and
/// the write makes the record Active again, so the holder no longer sweeps what it answered for.
#[tokio::test]
async fn marked_for_delete_holding_resent_chunk_goes_through_offer_and_reactivates() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x1B);
    let blk = make_block_id(0x1B);
    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let first = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&first, blk, vec![(0, 2)]);
    let mut rec = db.get_holding(&blk, &owner).unwrap().unwrap();
    rec.status = HoldingStatus::MarkedForDelete;
    rec.delete_requested_at = Some(Timestamp::now());
    db.upsert_holding(&rec).unwrap();

    let no_offer = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_ack(&no_offer);
    assert_eq!(
        db.get_holding(&blk, &owner).unwrap().unwrap().status,
        HoldingStatus::MarkedForDelete
    );

    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let with_offer = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&with_offer, blk, vec![(0, 2)]);
    let rec = db.get_holding(&blk, &owner).unwrap().unwrap();
    assert_eq!(rec.status, HoldingStatus::Active);
    assert_eq!(rec.delete_requested_at, None);
    assert_eq!(rec.esi_ranges, vec![(0, 2)]);
    assert_eq!(rec.total_bytes, 2 * 64);
    assert_eq!(bins_on_disk(&dir, blk), vec![0, 1]);
}

/// An offer that covers ESIs this holder already has: a chunk of only those ESIs is answered
/// `SymbolStored` without a write, and still leaves the offer (so it does not wait for the sweep).
#[tokio::test]
async fn already_held_chunk_subtracts_from_existing_offer() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x1C);
    let blk = make_block_id(0x1C);
    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let first = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&first, blk, vec![(0, 2)]);

    insert_accepted_offer(&p, owner, blk, vec![(0, 4)], 0.5);
    let held = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&held, blk, vec![(0, 2)]);
    assert_eq!(
        p.accepted_offers.lock().unwrap()[&(sender_device(owner), blk)].esi_ranges,
        vec![(2, 2)]
    );

    let rest = reply_to(&p, owner, chunk(blk, &[2, 3], 0xAA)).await;
    assert_stored(&rest, blk, vec![(2, 2)]);
    assert!(p.accepted_offers.lock().unwrap().is_empty());
    assert_eq!(bins_on_disk(&dir, blk), vec![0, 1, 2, 3]);
}

/// The block directory cannot be created (a plain file sits at its path): the write fails, the
/// reply is `Ack`, nothing is recorded, and the offer stays for a later try.
#[tokio::test]
async fn transfer_write_error_replies_ack_not_stored() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x1D);
    let blk = make_block_id(0x1D);
    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let block_hex: String = blk.0.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join(block_hex), b"not a directory").unwrap();

    let reply = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;

    assert_ack(&reply);
    assert!(db.get_holding(&blk, &owner).unwrap().is_none());
    assert_eq!(
        p.accepted_offers.lock().unwrap()[&(sender_device(owner), blk)].esi_ranges,
        vec![(0, 2)]
    );
}

/// A held symbol whose file is shorter than the resent symbol is not "already held": without an
/// offer the chunk is not stored; with an offer the file is rewritten in full.
#[tokio::test]
async fn truncated_held_file_is_not_already_held() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x1E);
    let blk = make_block_id(0x1E);
    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let first = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&first, blk, vec![(0, 2)]);
    let block_hex: String = blk.0.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join(block_hex).join("0.bin"), [0xAA; 10]).unwrap();

    let no_offer = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_ack(&no_offer);
    assert_eq!(read_bin(&dir, blk, 0).len(), 10);

    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let with_offer = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&with_offer, blk, vec![(0, 2)]);
    assert_eq!(read_bin(&dir, blk, 0), vec![0xAA; 64]);
    let rec = db.get_holding(&blk, &owner).unwrap().unwrap();
    assert_eq!(rec.esi_ranges, vec![(0, 2)]);
    assert_eq!(rec.total_bytes, 2 * 64);
}

/// Same length, other bytes: not "already held". Matching bytes: `Stored` with no offer. Mismatch:
/// without an offer nothing is rewritten; with one the file is rewritten (no `.tmp` left),
/// `Stored`, the record's size unchanged. Mutation: compare off -> this reddens.
#[tokio::test]
async fn held_file_with_other_bytes_is_rewritten_and_matching_one_is_not() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x1F);
    let blk = make_block_id(0x1F);
    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    assert_stored(
        &reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await,
        blk,
        vec![(0, 2)],
    );
    assert_stored(
        &reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await,
        blk,
        vec![(0, 2)],
    );
    let block_hex: String = blk.0.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join(&block_hex).join("1.bin"), [0x55; 64]).unwrap();

    let no_offer = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_ack(&no_offer);
    assert_eq!(read_bin(&dir, blk, 1), vec![0x55; 64]);

    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let with_offer = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&with_offer, blk, vec![(0, 2)]);
    assert_eq!(read_bin(&dir, blk, 1), vec![0xAA; 64]);
    assert_eq!(bins_on_disk(&dir, blk), vec![0, 1]);
    // A mismatching held ESI outside the offer's remaining range is still rewritten.
    std::fs::write(dir.path().join(&block_hex).join("0.bin"), [0x55; 64]).unwrap();
    insert_accepted_offer(&p, owner, blk, vec![(2, 2)], 0.5);
    let outside = reply_to(&p, owner, chunk(blk, &[0], 0xAA)).await;
    assert_stored(&outside, blk, vec![(0, 1)]);
    assert_eq!(read_bin(&dir, blk, 0), vec![0xAA; 64]);
    assert!(!dir.path().join(&block_hex).join("1.bin.tmp").exists());
    let rec = db.get_holding(&blk, &owner).unwrap().unwrap();
    assert_eq!(rec.esi_ranges, vec![(0, 2)]);
    assert_eq!(rec.total_bytes, 2 * 64);
}

/// The file is gone while the DB still holds the ESI: rewritten through the offer.
#[tokio::test]
async fn held_esi_with_missing_file_is_rewritten() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x20);
    let blk = make_block_id(0x20);
    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    let block_hex: String = blk.0.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::remove_file(dir.path().join(block_hex).join("0.bin")).unwrap();

    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let reply = reply_to(&p, owner, chunk(blk, &[0, 1], 0xAA)).await;
    assert_stored(&reply, blk, vec![(0, 2)]);
    assert_eq!(read_bin(&dir, blk, 0), vec![0xAA; 64]);
}

fn sized_chunk(block_id: SourceBlockId, esis: &[u32], byte: u8, len: usize) -> SymbolTransferMsg {
    SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: esis
            .iter()
            .map(|&esi| Symbol {
                esi,
                data: vec![byte; len],
            })
            .collect(),
        timestamp: Timestamp::now(),
    }
}

/// W1 (cross review): 1-byte symbols, then the same ESIs at full size. The record's total follows
/// the files (it grows), and the growth is asked of the quota.
#[tokio::test]
async fn one_byte_symbols_then_full_size_overwrite_grows_total_bytes() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x21);
    let blk = make_block_id(0x21);
    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    reply_to(&p, owner, sized_chunk(blk, &[0, 1], 0xAA, 1)).await;
    assert_eq!(
        db.get_holding(&blk, &owner).unwrap().unwrap().total_bytes,
        2
    );

    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let reply = reply_to(&p, owner, sized_chunk(blk, &[0, 1], 0xBB, 2000)).await;

    assert_stored(&reply, blk, vec![(0, 2)]);
    assert_eq!(
        db.get_holding(&blk, &owner).unwrap().unwrap().total_bytes,
        4000
    );
}

#[tokio::test]
async fn one_byte_symbols_then_full_size_overwrite_is_held_by_the_quota() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor_with_quota(db.clone(), &dir, 1000, u64::MAX).await;
    let owner = make_identity(0x22);
    let blk = make_block_id(0x22);
    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    reply_to(&p, owner, sized_chunk(blk, &[0, 1], 0xAA, 1)).await;

    insert_accepted_offer(&p, owner, blk, vec![(0, 2)], 0.5);
    let reply = reply_to(&p, owner, sized_chunk(blk, &[0, 1], 0xBB, 2000)).await;

    assert_ack(&reply);
    assert_eq!(read_bin(&dir, blk, 0), vec![0xAA; 1]);
    assert_eq!(
        db.get_holding(&blk, &owner).unwrap().unwrap().total_bytes,
        2
    );
}

/// W2: every write replaces the file through a temp name — the old file (inode) stays whole until
/// the rename, also when the holding is on its way out (MarkedForDelete) and the chunk comes
/// through the offer. Mutation M2 "direct write" keeps the inode and reddens this.
#[cfg(unix)]
#[tokio::test]
async fn every_write_replaces_the_file_through_rename_and_leaves_no_tmp() {
    use std::os::unix::fs::MetadataExt;
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let p = make_processor(db.clone(), &dir).await;
    let owner = make_identity(0x23);
    let blk = make_block_id(0x23);
    let block_hex: String = blk.0.iter().map(|b| format!("{b:02x}")).collect();
    let file = dir.path().join(&block_hex).join("0.bin");
    insert_accepted_offer(&p, owner, blk, vec![(0, 1)], 0.5);
    reply_to(&p, owner, chunk(blk, &[0], 0xAA)).await;
    let ino_first = std::fs::metadata(&file).unwrap().ino();
    // Hold the old file by a hard link so a freed inode number cannot be reused by the rename.
    std::fs::hard_link(&file, dir.path().join(&block_hex).join("keep.lnk")).unwrap();

    let mut rec = db.get_holding(&blk, &owner).unwrap().unwrap();
    rec.status = HoldingStatus::MarkedForDelete;
    db.upsert_holding(&rec).unwrap();
    insert_accepted_offer(&p, owner, blk, vec![(0, 1)], 0.5);
    let reply = reply_to(&p, owner, chunk(blk, &[0], 0xCC)).await;

    assert_stored(&reply, blk, vec![(0, 1)]);
    assert_ne!(std::fs::metadata(&file).unwrap().ino(), ino_first);
    assert_eq!(
        std::fs::read(dir.path().join(&block_hex).join("keep.lnk")).unwrap(),
        vec![0xAA; 64],
        "the old file stays whole"
    );
    let names: Vec<String> = std::fs::read_dir(dir.path().join(&block_hex))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(names.iter().all(|n| !n.contains(".tmp")), "{names:?}");
}
