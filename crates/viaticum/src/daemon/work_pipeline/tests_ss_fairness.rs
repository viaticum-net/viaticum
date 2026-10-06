// backup-i28 / backup-i28-a: the service blocks of SystemState and the user's blocks share
// the worker. After an attempt on an SS block a waiting user block goes next; within SS a
// new block (no live holder, never attempted) goes before a re-pick of a placed one.
//
// No swarm and no pool peers: every attempt is one "pool too small" park, one attempt per
// iteration, and with pool signature 0 no cooldown applies — every block is eligible again
// on the next attempt, so only the rule decides the order (spec review W3).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use viaticum_core::db::Db;
use viaticum_core::types::{SourceBlockId, SourceBlockRecord, Timestamp};

use super::WorkPipeline;
use super::tests::{block_id, make_block_record, make_config, pipeline_with};

fn db() -> Db {
    Db::open_in_memory().unwrap()
}

/// A below-target block with `alive` live holders.
fn block(db: &Db, byte: u8, importance: f64, alive: u32) -> SourceBlockId {
    let id = block_id(byte);
    let mut rec: SourceBlockRecord = make_block_record(id, importance, 0.99999);
    rec.current_alive = alive;
    rec.current_reliability = if alive > 0 { 0.9 } else { 0.0 };
    db.upsert_source_block(&rec).unwrap();
    id
}

fn ss_block(db: &Db, byte: u8, alive: u32) -> SourceBlockId {
    let id = block(db, byte, 1.0, alive);
    db.mark_ss_block(&id, 1).unwrap();
    id
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
    let ss = ss_block(&db, 0x10, 3);
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

#[tokio::test]
async fn ss_blocks_follow_each_other_when_no_user_block_waits() {
    let db = db();
    ss_block(&db, 0x10, 3);
    ss_block(&db, 0x11, 3);
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

/// backup-i28-a. Mutation «no step (b)» → the placed base (higher priority) goes first;
/// reddens. A new block jumps the queue once: tried and still without holders (every holder
/// refused it), it waits behind the placed one again (spec review round 2, WARN-b).
#[tokio::test]
async fn new_ss_block_goes_before_a_re_pick_of_a_placed_ss_block() {
    let db = db();
    let base = ss_block(&db, 0x40, 3);
    let diff = ss_block(&db, 0x41, 0);
    let mut p = pipeline_with(&db, make_config(), None);
    assert_eq!(next(&p), diff, "the new diff first");
    assert!(attempt(&mut p).await);
    assert_eq!(
        next(&p),
        base,
        "tried once: the placed base gets its turn again"
    );
}

/// The picked line says whether the block is SS (the E2E bar counts these).
#[tokio::test]
async fn picked_line_says_ss() {
    let db = db();
    ss_block(&db, 0x10, 3);
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
