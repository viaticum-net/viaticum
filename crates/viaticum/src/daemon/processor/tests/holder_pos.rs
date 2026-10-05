// К-b4 (pos-i14, spec v3.10 / v3.10a): the holder answers a PoS challenge by streaming its
// share through one buffer, on the blocking pool, at most `HOLDER_POS_CONCURRENCY` answers at
// once. A child of `processor/tests.rs`. The peak of memory is measured by the separate test
// binary `tests/holder_pos_alloc_peak.rs` (a counting allocator must not leak into unit tests);
// the incremental hasher against `compute_chain_hash` is `chain_hasher_equals_compute_chain_hash`
// in `viaticum-core`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use viaticum_core::db::Db;
use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder, binding_keystream};
use viaticum_core::messages::{Message, PosHashChallengeMsg, build_pos_hash_challenge, to_cbor};
use viaticum_core::pos::compute_chain_hash;
use viaticum_core::types::{
    DeviceId, ErasureParams, HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp,
    hex_encode,
};

use super::super::ProcessorError;
use super::super::pos::{HOLDER_POS_CONCURRENCY, PosResponder, ProcessorPosHandler, new_pos_slots};
use super::make_processor;
use crate::daemon::mailbox::poll::{PosChallengeAnswer, PosMailboxChallengeHandler};
use crate::daemon::mem_budget::{HolderKind, MemBudget};
use crate::daemon::scheduler::{FoldHolder, hash_holders};

/// A holder with `ranges` held for one owner: the symbol of ESI `e` is `len` bytes of a pattern
/// that depends on `e` (so a swapped, repeated or skipped symbol changes the hash).
struct Held {
    db: Db,
    dir: TempDir,
    owner_key: ed25519_dalek::SigningKey,
    owner: IdentityPub,
    block_id: SourceBlockId,
}

fn symbol_of(esi: u32, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(31).wrapping_add(esi * 7 + 1) as u8)
        .collect()
}

impl Held {
    fn new(ranges: &[(u32, u32)], len: usize) -> Self {
        let db = Db::open_in_memory().unwrap();
        let dir = TempDir::new().unwrap();
        let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x61u8; 32]);
        let owner = IdentityPub(owner_key.verifying_key().to_bytes());
        let block_id = SourceBlockId([0x62; 32]);
        db.upsert_holding(&HoldingRecord {
            source_block_id: block_id,
            owner_id: owner,
            esi_ranges: ranges.to_vec(),
            importance: 0.5,
            total_bytes: 0,
            status: HoldingStatus::Active,
            received_at: Timestamp::now(),
            delete_requested_at: None,
            drop_notice_sent_at: None,
        })
        .unwrap();
        let held = Held {
            db,
            dir,
            owner_key,
            owner,
            block_id,
        };
        std::fs::create_dir_all(held.block_dir()).unwrap();
        for &(start, count) in ranges {
            for esi in start..start + count {
                std::fs::write(held.file(esi), symbol_of(esi, len)).unwrap();
            }
        }
        held
    }

    fn block_dir(&self) -> std::path::PathBuf {
        self.dir.path().join(hex_encode(&self.block_id.0))
    }

    fn file(&self, esi: u32) -> std::path::PathBuf {
        self.block_dir().join(format!("{esi}.bin"))
    }

    /// This holder device's key: the responder signs with it, challenges are addressed to it.
    fn device_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32])
    }

    fn device_id() -> DeviceId {
        DeviceId(Self::device_key().verifying_key().to_bytes())
    }

    fn responder(&self) -> PosResponder {
        PosResponder::new(
            self.db.clone(),
            self.dir.path().to_path_buf(),
            Self::device_key(),
            IdentityPub([0xABu8; 32]),
            None,
        )
    }

    fn challenge(&self, id: u8, ranges: Vec<(u32, u32)>) -> PosHashChallengeMsg {
        build_pos_hash_challenge(
            [id; 16],
            self.block_id,
            ranges,
            Timestamp::now(),
            Self::device_id(),
            &self.owner_key,
        )
    }
}

fn hash_of(msg: Message) -> [u8; 32] {
    match msg {
        Message::PosHashResponse(r) => r.chain_hash,
        other => panic!(
            "expected a response, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ─── A missing symbol (M79) ───────────────────────────────────────────────────────────────────

/// A symbol gone after others were already hashed (first, middle, last): a Nack with ITS esi on
/// the direct path, `None` on the mailbox path — never a hash of the rest, never an error.
#[tokio::test]
async fn missing_symbol_after_hashed_ones_gives_nack_with_its_esi() {
    for gone in [0u32, 3, 7] {
        let held = Held::new(&[(0, 8)], 100);
        std::fs::remove_file(held.file(gone)).unwrap();
        let ranges = vec![(0, 8)];

        let reply = held
            .responder()
            .compute_response(held.owner, held.challenge(1, ranges.clone()))
            .await
            .expect("a missing symbol is a Nack, not an error");
        match reply {
            Message::PosHashNack(nack) => {
                assert_eq!(
                    nack.first_missing_esi, gone,
                    "the Nack names the missing ESI"
                )
            }
            other => panic!(
                "gone={gone}: expected a Nack, got {:?}",
                std::mem::discriminant(&other)
            ),
        }

        let handler = ProcessorPosHandler::new(held.responder());
        let payload = to_cbor(&held.challenge(2, ranges)).unwrap();
        let over_mailbox = handler
            .handle_pos_challenge(held.owner, payload)
            .await
            .expect("not a handler error");
        assert!(
            matches!(over_mailbox, PosChallengeAnswer::NoAnswer),
            "gone={gone}: the mailbox path publishes nothing"
        );
    }
}

// ─── Another IO error (M80) ───────────────────────────────────────────────────────────────────

/// A symbol that cannot be read for a reason other than "not there" (here: a directory in its
/// place) is an error — not a Nack: the holder does not claim it lost the symbol.
#[tokio::test]
async fn other_io_error_is_err_not_nack() {
    let held = Held::new(&[(0, 4)], 100);
    std::fs::remove_file(held.file(2)).unwrap();
    std::fs::create_dir(held.file(2)).unwrap();

    let result = held
        .responder()
        .compute_response(held.owner, held.challenge(3, vec![(0, 4)]))
        .await;
    assert!(
        matches!(result, Err(ProcessorError::Io(_))),
        "an unreadable symbol is Err(Io), got {:?}",
        result.map(|m| std::mem::discriminant(&m))
    );
}

// ─── The order of the ESIs, as at the owner (M81) ─────────────────────────────────────────────

/// The holder's answer to overlapping and unsorted ranges equals the hash the owner's walk
/// (`fold.rs`, `hash_holders`) folds for the same ranges: sorted ascending, duplicates kept (a
/// repeated ESI hashed once per occurrence). The holder stores what the owner binds.
#[tokio::test]
async fn holder_answer_equals_owner_fold_with_overlapping_and_unsorted_ranges() {
    let (k, t) = (8u32, 64u16);
    let k_eff = k + viaticum_core::constants::DECODE_OVERHEAD;
    let params = ErasureParams {
        k,
        k_eff,
        t,
        overhead: 1.5,
        n: (k_eff as f64 * 1.5).ceil() as u32,
    };
    let block_id = SourceBlockId([0x62; 32]);
    let holder_id = DeviceId([0x63; 32]);
    let blob: Vec<u8> = (0..k as usize * t as usize)
        .map(|i| (i % 251) as u8 + 1)
        .collect();
    let enc = RaptorQEncoder::new();

    // The holder's share: ESIs 0..12, bound to it, as delivered.
    let held = Held::new(&[(0, 12)], 1);
    for sym in enc.encode_raw_ranges(&blob, &params, &[(0, 12)]).unwrap() {
        let ks = binding_keystream(&block_id, &holder_id, sym.esi, sym.data.len());
        let bound: Vec<u8> = sym.data.iter().zip(&ks).map(|(a, b)| a ^ b).collect();
        std::fs::write(held.file(sym.esi), bound).unwrap();
    }

    // Unsorted, overlapping: 5, 6, 7, 2, 3, 4, 5, 6 (5 and 6 twice).
    let ranges = vec![(5u32, 3u32), (2, 4), (6, 2)];
    let challenge_id = [0x64u8; 16];
    let challenge = build_pos_hash_challenge(
        challenge_id,
        held.block_id,
        ranges.clone(),
        Timestamp::now(),
        Held::device_id(),
        &held.owner_key,
    );
    let answer = hash_of(
        held.responder()
            .compute_response(held.owner, challenge)
            .await
            .unwrap(),
    );

    let budget = MemBudget::new(64 << 20);
    let permit = budget
        .try_acquire(HolderKind::Pos, &block_id, 1 << 20)
        .expect("a free budget");
    let folded = hash_holders(
        &permit,
        &enc,
        &block_id,
        &params,
        blob,
        &[FoldHolder {
            holder_id,
            challenge_id,
            esi_ranges: ranges,
        }],
    )
    .expect("the walk");
    assert_eq!(
        answer,
        *folded[0].as_ref().expect("a hash"),
        "the holder's chain hash is the owner's fold"
    );
}

// ─── Off the runtime thread (M78) ─────────────────────────────────────────────────────────────

/// The share is read and hashed on the blocking pool, not on the runtime's thread: a task
/// ticking on the same single-threaded runtime is not held up by an answer over 1024 real
/// symbols (64 MiB). Two readings, neither a clock bound: the thread that reads is not the
/// runtime's, and the longest gap between ticks during the answer is far below the answer's
/// own duration (a read-and-hash inline holds the runtime for all of it).
#[tokio::test]
async fn holder_pos_answer_runs_off_the_runtime_thread() {
    const N: u32 = 1024;
    const T: usize = 65_535;
    let held = Held::new(&[(0, N)], T);
    let runtime_thread = std::thread::current().id();
    let read_on_runtime_thread = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&read_on_runtime_thread);
    let responder = held.responder().with_read_hook(Arc::new(move |_esi| {
        if std::thread::current().id() == runtime_thread {
            seen.store(true, Ordering::SeqCst);
        }
    }));

    let ticks = Arc::new(Mutex::new(Vec::<Instant>::new()));
    let beat = {
        let ticks = Arc::clone(&ticks);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(5)).await;
                ticks.lock().unwrap().push(Instant::now());
            }
        })
    };
    // The heartbeat is alive before the answer starts.
    while ticks.lock().unwrap().len() < 3 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let from = Instant::now();
    let reply = responder
        .compute_response(held.owner, held.challenge(4, vec![(0, N)]))
        .await
        .expect("the answer");
    let to = Instant::now();
    beat.abort();
    assert!(matches!(reply, Message::PosHashResponse(_)));

    let mut marks = vec![from];
    marks.extend(
        ticks
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|t| *t >= from && *t <= to),
    );
    marks.push(to);
    let longest_gap = marks.windows(2).map(|w| w[1] - w[0]).max().unwrap();
    let whole = to - from;
    assert!(
        !read_on_runtime_thread.load(Ordering::SeqCst),
        "a symbol was read on the runtime's thread"
    );
    assert!(
        longest_gap * 2 <= whole,
        "the runtime stood still for {longest_gap:?} of the answer's {whole:?}"
    );
}

// ─── At most two answers read at once (M83) ───────────────────────────────────────────────────

/// A gate the stand-in read waits at: counts the reads inside and their maximum.
struct Gate {
    inside: AtomicUsize,
    most: AtomicUsize,
    open: Mutex<bool>,
    opened: Condvar,
}

/// Six parallel answers, the read of each held at a gate: no more than two are inside at once
/// (the rest wait without a thread), and when the gate opens all six are answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn at_most_two_holder_pos_answers_read_at_once() {
    const CALLS: u8 = 6;
    let held = Held::new(&[(0, CALLS as u32)], 100);
    let gate = Arc::new(Gate {
        inside: AtomicUsize::new(0),
        most: AtomicUsize::new(0),
        open: Mutex::new(false),
        opened: Condvar::new(),
    });
    let g = Arc::clone(&gate);
    let responder = Arc::new(held.responder().with_read_hook(Arc::new(move |_esi| {
        let now = g.inside.fetch_add(1, Ordering::SeqCst) + 1;
        g.most.fetch_max(now, Ordering::SeqCst);
        let open = g.open.lock().unwrap();
        let (_open, timeout) = g
            .opened
            .wait_timeout_while(open, Duration::from_secs(60), |open| !*open)
            .unwrap();
        assert!(!timeout.timed_out(), "the gate was never opened");
        g.inside.fetch_sub(1, Ordering::SeqCst);
    })));

    let answers: Vec<_> = (0..CALLS)
        .map(|i| {
            let responder = Arc::clone(&responder);
            let challenge = held.challenge(10 + i, vec![(u32::from(i), 1)]);
            let owner = held.owner;
            tokio::spawn(async move { responder.compute_response(owner, challenge).await })
        })
        .collect();

    // Two get in; then give the others every chance to get in too (a third one in is the bug).
    let deadline = Instant::now() + Duration::from_secs(60);
    while gate.most.load(Ordering::SeqCst) < HOLDER_POS_CONCURRENCY {
        assert!(Instant::now() < deadline, "no two reads came in");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let grace = Instant::now() + Duration::from_secs(1);
    while gate.most.load(Ordering::SeqCst) <= HOLDER_POS_CONCURRENCY && Instant::now() < grace {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        gate.most.load(Ordering::SeqCst),
        HOLDER_POS_CONCURRENCY,
        "more answers read at once than the semaphore allows"
    );

    *gate.open.lock().unwrap() = true;
    gate.opened.notify_all();
    for answer in answers {
        let reply = answer.await.unwrap().expect("every answer ends");
        assert!(matches!(reply, Message::PosHashResponse(_)));
    }
    assert!(gate.most.load(Ordering::SeqCst) <= HOLDER_POS_CONCURRENCY);
}

/// The semaphore is one for the node: two responders given the same slots share it (the direct
/// path and the mailbox path), and a fresh one has the permits it should.
#[tokio::test]
async fn responders_given_one_semaphore_share_it() {
    let slots = new_pos_slots();
    assert_eq!(slots.available_permits(), HOLDER_POS_CONCURRENCY);
    let held = Held::new(&[(0, 1)], 10);
    let a = held.responder().with_pos_slots(Arc::clone(&slots));
    let b = held.responder().with_pos_slots(Arc::clone(&slots));
    let _taken = slots
        .acquire_many(HOLDER_POS_CONCURRENCY as u32)
        .await
        .unwrap();
    // Both wait on the one semaphore: neither answers while it is taken.
    for r in [&a, &b] {
        let waiting = tokio::time::timeout(
            Duration::from_millis(200),
            r.compute_response(held.owner, held.challenge(20, vec![(0, 1)])),
        )
        .await;
        assert!(waiting.is_err(), "an answer ran without a permit");
    }
}

/// The wiring: the Processor's direct path and a mailbox responder made by
/// `Processor::pos_responder` wait on ONE semaphore, the processor's. With every permit taken,
/// neither answers; released, both do.
#[tokio::test]
async fn processor_direct_and_mailbox_paths_share_one_answer_semaphore() {
    let held = Held::new(&[(0, 2)], 50);
    let processor = make_processor(held.db.clone(), &held.dir).await;
    let mailbox = processor.pos_responder(held.responder());
    let taken = Arc::clone(&processor.pos_slots)
        .acquire_many_owned(HOLDER_POS_CONCURRENCY as u32)
        .await
        .unwrap();

    let direct = tokio::time::timeout(
        Duration::from_millis(300),
        processor.handle_pos_hash_challenge_inner(held.owner, held.challenge(50, vec![(0, 2)])),
    )
    .await;
    assert!(direct.is_err(), "the direct path answered without a permit");
    let via_mailbox = tokio::time::timeout(
        Duration::from_millis(300),
        mailbox.compute_response(held.owner, held.challenge(51, vec![(0, 2)])),
    )
    .await;
    assert!(
        via_mailbox.is_err(),
        "the mailbox path has its own semaphore"
    );

    drop(taken);
    let reply = processor
        .handle_pos_hash_challenge_inner(held.owner, held.challenge(52, vec![(0, 2)]))
        .await
        .expect("answers once a permit is free");
    assert!(matches!(reply, Message::PosHashResponse(_)));
    let reply = mailbox
        .compute_response(held.owner, held.challenge(53, vec![(0, 2)]))
        .await
        .expect("answers once a permit is free");
    assert!(matches!(reply, Message::PosHashResponse(_)));
}

/// A symbol file longer than T is a corrupted local file: `Err(Io)` with a plain text — not a
/// hash over it, not a Nack, and not a read of the whole file.
#[tokio::test]
async fn symbol_file_longer_than_the_symbol_size_is_err() {
    let held = Held::new(&[(0, 2)], 100);
    let too_long = usize::from(viaticum_core::constants::SYMBOL_SIZE) + 1;
    std::fs::write(held.file(1), symbol_of(1, too_long)).unwrap();
    let result = held
        .responder()
        .compute_response(held.owner, held.challenge(60, vec![(0, 2)]))
        .await;
    match result {
        Err(ProcessorError::Io(e)) => assert!(e.to_string().contains("longer"), "{e}"),
        other => panic!(
            "expected Err(Io), got {:?}",
            other.map(|m| std::mem::discriminant(&m))
        ),
    }
    // Exactly T is fine.
    std::fs::write(
        held.file(1),
        symbol_of(1, usize::from(viaticum_core::constants::SYMBOL_SIZE)),
    )
    .unwrap();
    let ok = held
        .responder()
        .compute_response(held.owner, held.challenge(61, vec![(0, 2)]))
        .await
        .expect("a symbol of T bytes");
    assert!(matches!(ok, Message::PosHashResponse(_)));
}

// ─── A panic of the blocking task (M84) ───────────────────────────────────────────────────────

/// The blocking task panics (the stand-in read does): the answer is an error, the processor
/// does not go down, the semaphore's permit is back, and the next answer is served.
#[tokio::test]
async fn holder_pos_answer_panic_is_an_error_not_a_crash() {
    let held = Held::new(&[(0, 2)], 100);
    let slots = new_pos_slots();
    let first = Arc::new(AtomicBool::new(true));
    let responder = held
        .responder()
        .with_pos_slots(Arc::clone(&slots))
        .with_read_hook(Arc::new(move |_esi| {
            if first.swap(false, Ordering::SeqCst) {
                panic!("the read panicked (a test)");
            }
        }));

    let result = responder
        .compute_response(held.owner, held.challenge(30, vec![(0, 1)]))
        .await;
    assert!(
        matches!(result, Err(ProcessorError::Join(_))),
        "a panic of the task is Err(Join), got {:?}",
        result.map(|m| std::mem::discriminant(&m))
    );
    assert_eq!(
        slots.available_permits(),
        HOLDER_POS_CONCURRENCY,
        "the permit is released"
    );
    let next = responder
        .compute_response(held.owner, held.challenge(31, vec![(0, 2)]))
        .await
        .expect("the next answer is served");
    let expected = compute_chain_hash(
        &[31u8; 16],
        &[
            (0, symbol_of(0, 100).as_slice()),
            (1, symbol_of(1, 100).as_slice()),
        ],
    )
    .unwrap();
    assert_eq!(hash_of(next), expected);
}

// ─── The memory budget is not the holder's business (M82) ─────────────────────────────────────

/// STRUCTURAL guard, not a mutation one (M82 is structural): the responder has no budget to ask
/// (v3.10 §2: the answer is O(T) and must not wait for the owner's heavy work), so this unit
/// passes whatever it is given. It documents the rule and goes red only for whoever threads a
/// budget in AND wires it here: the holder answers while the budget of its node is closed (a
/// DR runs) and while it is full (a worker holds it all), and the budget grants nothing for it.
#[tokio::test]
async fn holder_answers_while_the_budget_is_closed_or_full() {
    let closed = MemBudget::new_closed(64 << 20);
    let full = MemBudget::new(64 << 20);
    let _hold = full
        .try_acquire(HolderKind::Worker, &SourceBlockId([0xEE; 32]), 64 << 20)
        .expect("a free budget");
    assert_eq!(full.available_bytes(), 0);

    let held = Held::new(&[(0, 3)], 100);
    // The closed budget has granted nothing and never will; the full one only the worker's hold.
    for (i, (budget, grants)) in [(&closed, 0u64), (&full, 1)].into_iter().enumerate() {
        let reply = tokio::time::timeout(
            Duration::from_secs(60),
            held.responder()
                .compute_response(held.owner, held.challenge(40 + i as u8, vec![(0, 3)])),
        )
        .await
        .expect("the answer does not wait for the budget")
        .expect("the answer");
        assert!(matches!(reply, Message::PosHashResponse(_)));
        assert_eq!(budget.grants(), grants, "the answer took a permit");
    }
    assert!(closed.is_closed());
}
