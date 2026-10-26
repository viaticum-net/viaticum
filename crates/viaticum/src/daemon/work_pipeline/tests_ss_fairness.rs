// backup-i28 / i28-b: the service blocks of SystemState and the user's blocks share the
// worker. (a) After an attempt on an SS block a waiting user block goes next; (b) else the
// oldest SS block that is not restorable yet (strength < 1) goes first; (c) else the plain
// order.
//
// No swarm, and the holders of SS blocks are siblings (the own master), so no pool: every
// attempt is one "pool too small" park, one attempt per iteration, and with pool signature 0
// no cooldown applies — every block is eligible again on the next attempt, so only the rule
// decides the order (spec review W3). Strength is real: placements of holders seen now.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use viaticum_core::constants::DECODE_OVERHEAD;
use viaticum_core::db::Db;
use viaticum_core::types::{
    DeviceId, FileId, IdentityPub, PeerRecord, PlacementStatus, SourceBlockId, SourceBlockRecord,
    SymbolPlacement, Timestamp,
};

use super::WorkPipeline;
use super::tests::{block_id, make_block_record, make_config, pipeline_with};

/// k of `make_block_record` (5) + DECODE_OVERHEAD: one holder with this many symbols is a copy.
const K_EFF: u32 = 5 + DECODE_OVERHEAD;

fn db() -> Db {
    Db::open_in_memory().unwrap()
}

/// A below-target block with `alive` live holders (the cached count only).
fn block(db: &Db, byte: u8, importance: f64, alive: u32) -> SourceBlockId {
    let id = block_id(byte);
    let mut rec: SourceBlockRecord = make_block_record(id, importance, 0.99999);
    rec.current_alive = alive;
    rec.current_reliability = if alive > 0 { 0.9 } else { 0.0 };
    db.upsert_source_block(&rec).unwrap();
    id
}

/// An SS block of the ledger at `generation`, created at `created_at`, with `holders` holders
/// seen now holding `symbols` symbols each: strength = holders × symbols / K_EFF. The holders
/// are siblings (master = the own master of `make_config`), so they are not in the pool.
fn ss_block_with(
    db: &Db,
    byte: u8,
    holders: u8,
    symbols: u32,
    created_at: u64,
    generation: u32,
) -> SourceBlockId {
    let id = block_id(byte);
    let mut rec = make_block_record(id, 1.0, 0.99999);
    rec.created_at = Timestamp(created_at);
    rec.current_alive = u32::from(holders);
    rec.current_reliability = if holders > 0 { 0.9 } else { 0.0 };
    db.upsert_source_block(&rec).unwrap();
    db.mark_ss_block(&id, generation).unwrap();
    for h in 0..holders {
        let mut d = [0u8; 32];
        d[0] = byte;
        d[1] = h + 1;
        let device = DeviceId(d);
        db.upsert_peer(&PeerRecord {
            device_id: device,
            master_identity: IdentityPub([0u8; 32]),
            trust_p: 0.5,
            trust_i: 0.0,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: Timestamp(1),
            last_seen: Timestamp::now(),
            revoked_device_pub_keys: vec![],
            addrs: vec![],
            x25519_pub: None,
            avail_ewma: 0.5,
            last_avail_sample: 0,
        })
        .unwrap();
        db.upsert_placement(&SymbolPlacement {
            source_block_id: id,
            holder_id: device,
            file_id: FileId(0),
            esi_ranges: vec![(u32::from(h) * 100, symbols)],
            binding_seed: [0; 32],
            status: PlacementStatus::Alive,
            last_verified: None,
            placed_at: Timestamp(1),
            consecutive_misses: 0,
        })
        .unwrap();
    }
    id
}

/// An SS block with `copies` full copies (restorable when copies ≥ 1), generation 1.
fn ss_block(db: &Db, byte: u8, copies: u8, created_at: u64) -> SourceBlockId {
    ss_block_with(db, byte, copies, K_EFF, created_at, 1)
}

fn next(pipeline: &WorkPipeline) -> SourceBlockId {
    pipeline
        .next_block(Duration::ZERO, Duration::ZERO, Timestamp::now(), 0)
        .unwrap()
        .expect("a block to work on")
        .block_id
}

/// One attempt; whether it was on an SS block.
async fn attempt(pipeline: &mut WorkPipeline) -> bool {
    assert!(
        pipeline.run_iteration().await.unwrap(),
        "a block was picked"
    );
    pipeline.last_was_ss
}

/// Mutation «no step (a)» → the SS block (higher priority) is picked again; reddens.
#[tokio::test]
async fn user_block_is_taken_on_the_attempt_after_an_ss_attempt() {
    let db = db();
    let ss = ss_block(&db, 0x10, 3, 1000);
    let user = block(&db, 0x20, 0.05, 0);
    let mut p = pipeline_with(&db, make_config(), None);

    assert_eq!(next(&p), ss, "the SS block outranks the user block");
    assert!(attempt(&mut p).await, "first attempt: SS");
    assert_eq!(
        next(&p),
        user,
        "after an SS attempt the waiting user block goes next"
    );
    assert!(!attempt(&mut p).await, "second attempt: the user block");
    assert!(
        attempt(&mut p).await,
        "and SS is not starved: third attempt SS again"
    );
}

/// Review B1. Mutation «(b) before (a)» → after the attempt on the new SS block, the new
/// block (still not restorable) is picked again instead of the photo; reddens.
#[tokio::test]
async fn user_block_goes_after_an_ss_attempt_even_when_an_unrestorable_ss_block_waits() {
    let db = db();
    ss_block(&db, 0x10, 3, 1000);
    let user = block(&db, 0x20, 0.05, 0);
    let new_ss = ss_block(&db, 0x11, 0, 2000);
    let mut p = pipeline_with(&db, make_config(), None);

    assert_eq!(next(&p), new_ss, "new SS first");
    assert!(attempt(&mut p).await);
    assert_eq!(
        next(&p),
        user,
        "after the SS attempt the photo, though the new SS block is still not restorable"
    );
}

#[tokio::test]
async fn ss_blocks_follow_each_other_when_no_user_block_waits() {
    let db = db();
    ss_block(&db, 0x10, 3, 1000);
    ss_block(&db, 0x11, 3, 1000);
    let mut p = pipeline_with(&db, make_config(), None);
    assert!(attempt(&mut p).await);
    assert!(attempt(&mut p).await, "no user block waits: SS again");
}

/// A user file of importance 1 is the user's, not service. Mutation «SS = importance ≥ 1»
/// → after the first attempt the 0.05 block is taken; reddens.
#[tokio::test]
async fn user_block_of_importance_one_is_not_treated_as_ss() {
    let db = db();
    let important = block(&db, 0x30, 1.0, 3);
    block(&db, 0x31, 0.05, 0);
    let mut p = pipeline_with(&db, make_config(), None);
    assert!(
        !attempt(&mut p).await,
        "the user block of importance 1 is not SS"
    );
    assert_eq!(
        next(&p),
        important,
        "plain priority order among user blocks"
    );
}

/// Review W4. Mutation «step (a) keeps the blocks of importance < 1 instead of the non-SS
/// ones» (the importance test only in (a)) → the 0.05 photo is taken instead of the user's
/// importance-1 file; reddens.
#[tokio::test]
async fn after_an_ss_attempt_the_best_user_block_goes_even_of_importance_one() {
    let db = db();
    let ss = ss_block(&db, 0x10, 3, 1000);
    let important = block(&db, 0x30, 1.0, 0);
    block(&db, 0x31, 0.05, 0);
    let mut p = pipeline_with(&db, make_config(), None);

    assert_eq!(next(&p), ss, "placed SS first");
    assert!(attempt(&mut p).await);
    assert_eq!(
        next(&p),
        important,
        "the best user block, importance 1 included"
    );
}

/// backup-i28-b. Mutation «no step (b)» → the restorable base (higher priority) goes first;
/// mutation «(b) without strength < 1» (the oldest SS block at all) → the older base goes
/// first; mutation «(b) only for never-attempted blocks without a holder» (the old i28-a rule)
/// → after one attempt the restorable base goes; each reddens.
#[tokio::test]
async fn unrestorable_ss_block_goes_before_a_re_pick_of_a_restorable_one_also_when_tried() {
    let db = db();
    ss_block(&db, 0x40, 3, 1000);
    let diff = ss_block(&db, 0x41, 0, 2000);
    let mut p = pipeline_with(&db, make_config(), None);
    assert_eq!(next(&p), diff, "the new diff first");
    assert!(attempt(&mut p).await);
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
    let db = db();
    let base = ss_block_with(&db, 0x50, 1, K_EFF / 2, 1000, 1);
    ss_block(&db, 0x51, 0, 2000);
    let mut p = pipeline_with(&db, make_config(), None);
    assert_eq!(next(&p), base, "the older unrestorable block first");
    assert!(attempt(&mut p).await);
    assert_eq!(next(&p), base, "and again while it is not restorable");
}

/// backup-i28-b: age is the record's `created_at`, not the ledger generation — the generation
/// restarts at 1 with every process. Mutation «order (b) by generation first» → the new base
/// (generation 1) goes before the base of the earlier process (generation 5); reddens.
#[tokio::test]
async fn base_of_an_earlier_process_goes_before_the_new_base() {
    let db = db();
    let old_base = ss_block_with(&db, 0x60, 1, K_EFF / 2, 1000, 5);
    ss_block_with(&db, 0x61, 0, K_EFF, 2000, 1);
    let p = pipeline_with(&db, make_config(), None);
    assert_eq!(next(&p), old_base);
}

/// backup-i28-b, review W2: the order within SS does not depend on the RAM cooldown. A tried
/// block that is not restorable goes first once out of its cooldown, as after a cooldown
/// reset. Mutation «(b) only for never-attempted blocks» → the restorable base goes first
/// before the reset; reddens.
#[tokio::test]
async fn unrestorable_ss_block_goes_first_whether_or_not_cooldowns_were_reset() {
    let db = db();
    let base = ss_block(&db, 0x70, 3, 1000);
    let diff = ss_block(&db, 0x71, 0, 2000);
    let p = pipeline_with(&db, make_config(), None);
    let now = Timestamp::now();
    let (cd, parked, sig) = (Duration::from_secs(30), Duration::from_secs(3600), 7);
    // Tried 60 s ago with the same pool: out of its 30 s cooldown.
    db.set_block_cooldown(&diff, Some(Timestamp(now.0 - 60)), sig, false);
    let pick = |p: &WorkPipeline| {
        p.next_block(cd, parked, now, sig)
            .unwrap()
            .map(|r| r.block_id)
    };
    assert_eq!(pick(&p), Some(diff), "tried, out of cooldown: first");
    p.reset_all_cooldowns();
    assert_eq!(pick(&p), Some(diff), "after a reset: the same");
    // In its cooldown it is not eligible: the re-pick of the base goes.
    db.set_block_cooldown(&diff, Some(now), sig, false);
    assert_eq!(pick(&p), Some(base));
}

/// The picked line says whether the block is SS (the E2E bar counts these).
#[tokio::test]
async fn picked_line_says_ss() {
    let db = db();
    ss_block(&db, 0x10, 3, 1000);
    block(&db, 0x20, 0.05, 0);
    let mut p = pipeline_with(&db, make_config(), None);

    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = Arc::clone(&buf);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || BufWriter(Arc::clone(&writer)))
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    attempt(&mut p).await;
    attempt(&mut p).await;

    let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    let picked: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("work_pipeline: picked block for work"))
        .collect();
    assert_eq!(picked.len(), 2, "{text}");
    assert!(picked[0].contains("ss=true"), "{}", picked[0]);
    assert!(picked[1].contains("ss=false"), "{}", picked[1]);
}

struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
