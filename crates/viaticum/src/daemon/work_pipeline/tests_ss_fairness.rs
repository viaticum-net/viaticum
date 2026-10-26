// backup-i28 / i28-e: the service blocks of SystemState and the user's blocks share the
// worker. (a) After an attempt with offers on an SS block a waiting user block goes next; an
// attempt without offers does not use up the turn (i28-e). The order within SS (i28-b, i28-d)
// is in `tests_ss_order.rs`.
//
// The rig: a swarm alone and two pool peers it cannot reach, so every attempt with a candidate
// sends offers (they fail: an `Offered` attempt, as with holders that refuse); one attempt per
// iteration. Cooldown 0, so every block is eligible again on the next attempt and only the rule
// decides the order (spec review W3). Every block's blob is retained (the SystemState path):
// the worker encodes the user's blocks from it too, without source files — a test artifact.
// Strength is real: placements of SS holders seen now; those holders are siblings (the own
// master of `make_config`), so they are not in the pool.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use viaticum_core::constants::DECODE_OVERHEAD;
use viaticum_core::db::Db;
use viaticum_core::types::{
    DeviceId, FileId, IdentityPub, PeerRecord, PlacementStatus, SourceBlockId, SymbolPlacement,
    Timestamp,
};

use super::WorkPipeline;
use super::tests::{
    add_pool_peers, device_id, lonely_swarm, make_config, pipeline_with, retained_block,
};

/// k of `retained_block` (3) + DECODE_OVERHEAD: one holder with this many symbols is a copy.
pub(super) const K_EFF: u32 = 3 + DECODE_OVERHEAD;

/// The two pool peers: not siblings, never reachable.
const POOL: [u8; 2] = [0xA1, 0xA2];

pub(super) struct Rig {
    pub(super) db: Db,
    dir: tempfile::TempDir,
}

impl Rig {
    pub(super) fn new() -> Rig {
        let db = Db::open_in_memory().unwrap();
        add_pool_peers(&db, &POOL.map(device_id));
        Rig {
            db,
            dir: tempfile::tempdir().unwrap(),
        }
    }

    /// A pipeline over the rig: with a swarm (attempts send offers) or without one (every
    /// attempt is a «no swarm» park: no offers).
    pub(super) async fn pipeline(&self, swarm_seed: Option<u8>) -> WorkPipeline {
        let mut config = make_config();
        config.cooldown = Duration::ZERO;
        config.data_dir = self.dir.path().to_path_buf();
        let swarm = match swarm_seed {
            Some(seed) => Some(lonely_swarm(seed).await),
            None => None,
        };
        pipeline_with(&self.db, config, swarm)
    }

    /// A below-target user block with `alive` live holders (the cached count only).
    pub(super) fn user(&self, seed: u8, importance: f64, alive: u32) -> SourceBlockId {
        let mut rec = retained_block(self.dir.path(), seed, importance);
        rec.current_alive = alive;
        rec.current_reliability = if alive > 0 { 0.9 } else { 0.0 };
        self.db.upsert_source_block(&rec).unwrap();
        rec.block_id
    }

    /// An SS block of the ledger at `generation`, created at `created_at`, with `holders`
    /// holders seen now holding `symbols` symbols each: strength = holders × symbols / K_EFF.
    pub(super) fn ss_with(
        &self,
        seed: u8,
        holders: u8,
        symbols: u32,
        created_at: u64,
        generation: u32,
    ) -> SourceBlockId {
        let mut rec = retained_block(self.dir.path(), seed, 1.0);
        rec.created_at = Timestamp(created_at);
        rec.current_alive = u32::from(holders);
        rec.current_reliability = if holders > 0 { 0.9 } else { 0.0 };
        self.db.upsert_source_block(&rec).unwrap();
        let id = rec.block_id;
        self.db.mark_ss_block(&id, generation).unwrap();
        for h in 0..holders {
            let mut d = [0u8; 32];
            d[0] = seed;
            d[1] = h + 1;
            let device = DeviceId(d);
            self.db
                .upsert_peer(&PeerRecord {
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
            self.db
                .upsert_placement(&alive_placement(id, device, u32::from(h) * 100, symbols))
                .unwrap();
        }
        id
    }

    /// An SS block with `copies` full copies (restorable when copies ≥ 1), generation 1.
    pub(super) fn ss(&self, seed: u8, copies: u8, created_at: u64) -> SourceBlockId {
        self.ss_with(seed, copies, K_EFF, created_at, 1)
    }

    /// Placements of `block` at the pool peers (written with the offers of an attempt).
    fn offers_of(&self, block: &SourceBlockId) -> usize {
        let pool = POOL.map(device_id);
        self.db
            .list_placements_for_block(block)
            .unwrap()
            .iter()
            .filter(|p| pool.contains(&p.holder_id))
            .count()
    }
}

fn alive_placement(
    block: SourceBlockId,
    holder: DeviceId,
    first_esi: u32,
    symbols: u32,
) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block,
        holder_id: holder,
        file_id: FileId(0),
        esi_ranges: vec![(first_esi, symbols)],
        binding_seed: [0; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(1),
        consecutive_misses: 0,
    }
}

/// The block the worker picks next (cooldown 0, as in the rig).
pub(super) fn next(pipeline: &WorkPipeline) -> SourceBlockId {
    pipeline
        .next_block(Duration::ZERO, Duration::ZERO, Timestamp::now(), 0)
        .unwrap()
        .expect("a block to work on")
        .block_id
}

/// One iteration of the worker that sends offers: the block it worked on (the one block with
/// an attempt since the cooldowns were cleared). Asserts the attempt sent offers — its offers to
/// the pool peers are written and the block got the cooldown of an attempt with offers (worked,
/// not parked).
pub(super) async fn attempt(rig: &Rig, pipeline: &mut WorkPipeline) -> SourceBlockId {
    rig.db.clear_all_block_cooldowns();
    assert!(
        pipeline.run_iteration().await.unwrap(),
        "a block was picked"
    );
    let worked: Vec<SourceBlockId> = rig
        .db
        .list_all_source_blocks()
        .unwrap()
        .into_iter()
        .map(|r| r.block_id)
        .filter(|b| rig.db.block_cooldown(b).last_attempted_at.is_some())
        .collect();
    assert_eq!(worked.len(), 1, "one attempt per iteration");
    let block = worked[0];
    assert!(
        rig.offers_of(&block) > 0 && !rig.db.block_cooldown(&block).parked,
        "the attempt on {block} sent offers"
    );
    block
}

/// Mutation «no step (a)» → the SS block (higher priority) is picked again; reddens.
#[tokio::test]
async fn user_block_is_taken_on_the_attempt_after_an_ss_attempt() {
    let rig = Rig::new();
    let ss = rig.ss(0x10, 3, 1000);
    let user = rig.user(0x20, 0.05, 0);
    let mut p = rig.pipeline(Some(0x51)).await;

    assert_eq!(attempt(&rig, &mut p).await, ss, "the SS block outranks");
    assert_eq!(
        attempt(&rig, &mut p).await,
        user,
        "after an SS attempt the waiting user block goes next"
    );
    assert_eq!(
        attempt(&rig, &mut p).await,
        ss,
        "and SS is not starved: the third attempt is SS again"
    );
}

/// Review B1. Mutation «(b) before (a)» → after the attempt on the new SS block, the new
/// block (still not restorable) is picked again instead of the photo; reddens.
#[tokio::test]
async fn user_block_goes_after_an_ss_attempt_even_when_an_unrestorable_ss_block_waits() {
    let rig = Rig::new();
    rig.ss(0x10, 3, 1000);
    let user = rig.user(0x20, 0.05, 0);
    let new_ss = rig.ss(0x11, 0, 2000);
    let mut p = rig.pipeline(Some(0x52)).await;

    assert_eq!(attempt(&rig, &mut p).await, new_ss, "new SS first");
    assert_eq!(
        next(&p),
        user,
        "after the SS attempt the photo, though the new SS block is still not restorable"
    );
}

#[tokio::test]
async fn ss_blocks_follow_each_other_when_no_user_block_waits() {
    let rig = Rig::new();
    let a = rig.ss(0x10, 3, 1000);
    let b = rig.ss(0x11, 3, 1000);
    let mut p = rig.pipeline(Some(0x53)).await;
    let first = attempt(&rig, &mut p).await;
    assert!(p.last_was_ss);
    let second = attempt(&rig, &mut p).await;
    assert!(
        [a, b].contains(&first) && [a, b].contains(&second),
        "no user block waits: SS again"
    );
}

/// A user file of importance 1 is the user's, not service. Mutation «SS = importance ≥ 1»
/// → after the first attempt the 0.05 block is taken; reddens.
#[tokio::test]
async fn user_block_of_importance_one_is_not_treated_as_ss() {
    let rig = Rig::new();
    let important = rig.user(0x30, 1.0, 3);
    rig.user(0x31, 0.05, 0);
    let mut p = rig.pipeline(Some(0x54)).await;
    assert_eq!(attempt(&rig, &mut p).await, important);
    assert!(!p.last_was_ss, "the user block of importance 1 is not SS");
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
    let rig = Rig::new();
    let ss = rig.ss(0x10, 3, 1000);
    let important = rig.user(0x30, 1.0, 0);
    rig.user(0x31, 0.05, 0);
    let mut p = rig.pipeline(Some(0x55)).await;

    assert_eq!(attempt(&rig, &mut p).await, ss, "placed SS first");
    assert_eq!(
        next(&p),
        important,
        "the best user block, importance 1 included"
    );
}

/// backup-i28-e: an SS attempt that sent no offers (here: no swarm, the block is parked) does
/// not use up the SS turn — the user block does not jump. Mutation «the turn is set at the pick,
/// whatever the outcome» (the code before i28-e) → the photo goes next; reddens.
#[tokio::test]
async fn an_ss_attempt_without_offers_does_not_use_up_the_turn() {
    let rig = Rig::new();
    let ss = rig.ss(0x10, 3, 1000);
    rig.user(0x20, 0.05, 0);
    let mut p = rig.pipeline(None).await;

    assert_eq!(next(&p), ss);
    assert!(p.run_iteration().await.unwrap(), "the SS block was picked");
    assert_eq!(rig.offers_of(&ss), 0, "no swarm: no offers");
    assert!(rig.db.block_cooldown(&ss).last_attempted_at.is_some());
    assert!(!p.last_was_ss, "the turn did not pass");
    assert_eq!(next(&p), ss, "no user jump after an attempt without offers");
}

/// backup-i28-e, the other class: after an SS attempt with offers, a user attempt without
/// offers (every pool peer already holds the block: nobody to offer to) leaves the turn with
/// the user blocks; the iteration goes on to a user block, not to the SS block. Mutation «the
/// turn is set at the pick, whatever the outcome» → the SS block gets the next pick of the
/// iteration; reddens.
#[tokio::test]
async fn a_user_attempt_without_offers_keeps_the_turn_with_the_user_blocks() {
    let rig = Rig::new();
    let ss = rig.ss(0x10, 3, 1000);
    let held = rig.user(0x21, 0.5, 2);
    for peer in POOL.map(device_id) {
        rig.db
            .upsert_placement(&alive_placement(held, peer, 0, 1))
            .unwrap();
    }
    let mut p = rig.pipeline(Some(0x56)).await;

    assert_eq!(attempt(&rig, &mut p).await, ss);
    rig.db.clear_all_block_cooldowns();
    assert_eq!(next(&p), held, "(a): the best user block");
    assert!(p.run_iteration().await.unwrap());
    assert!(
        rig.db.block_cooldown(&held).parked,
        "nobody to offer to: parked, no offers"
    );
    assert!(p.last_was_ss, "the turn stays with the user blocks");
    assert!(
        rig.db.block_cooldown(&ss).last_attempted_at.is_none(),
        "the SS block was not picked after the user attempt without offers"
    );
}

/// The picked line says whether the block is SS (the E2E bar counts these).
#[tokio::test]
async fn picked_line_says_ss() {
    let rig = Rig::new();
    rig.ss(0x10, 3, 1000);
    rig.user(0x20, 0.05, 0);
    let mut p = rig.pipeline(Some(0x57)).await;

    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = Arc::clone(&buf);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || BufWriter(Arc::clone(&writer)))
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    attempt(&rig, &mut p).await;
    attempt(&rig, &mut p).await;

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
