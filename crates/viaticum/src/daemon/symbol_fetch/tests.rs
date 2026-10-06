// Unit tests for the wire-validation / dedup / cap boundary logic of the symbol
// fetch path (CS-DR-2, CS-DR-5). These exercise `accept_holder_symbols`, the pure
// helper extracted from `fetch_unbound_symbols`, with real symbols and a real
// RaptorQEncoder — no swarm needed. The full network round-trip is covered by
// restore/tests.rs integration tests and local_e2e_test.sh.
//
// Pattern: what_when_then.

use std::collections::HashSet;
use std::sync::Arc;

use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder, Symbol};
use viaticum_core::types::{DeviceId, SourceBlockId};

use super::accept_holder_symbols;

const SYMBOL_LEN: usize = 4;

fn encoder() -> Arc<dyn ErasureEncoder> {
    Arc::new(RaptorQEncoder::new())
}

fn block() -> SourceBlockId {
    SourceBlockId([1u8; 32])
}

fn holder() -> DeviceId {
    DeviceId([2u8; 32])
}

fn sym(esi: u32, len: usize) -> Symbol {
    Symbol {
        esi,
        data: vec![0xABu8; len],
    }
}

/// CS-DR-2: a holder reply containing a symbol with `esi >= 2^24` AND another
/// with the wrong data length must be skipped without panicking; only the
/// well-formed, requested symbol is accepted.
#[test]
fn fetch_skips_symbol_with_oversized_esi_and_wrong_length_without_panic() {
    let enc = encoder();
    let blk = block();
    let hld = holder();

    let wanted: HashSet<u32> = [0u32, 1u32].into_iter().collect();
    let mut accepted_esis: HashSet<u32> = HashSet::new();
    let mut unbound: Vec<Symbol> = Vec::new();

    let symbols = vec![
        sym(1 << 24, SYMBOL_LEN), // oversized ESI → would assert-panic in decode
        sym(0, SYMBOL_LEN + 1),   // wrong length → would slice-panic in decode
        sym(0, SYMBOL_LEN),       // well-formed, requested → accepted
    ];

    // Must not panic.
    accept_holder_symbols(
        &enc,
        &blk,
        &hld,
        symbols,
        &wanted,
        /*holder_cap*/ 2,
        SYMBOL_LEN,
        /*k_eff*/ 2,
        &mut accepted_esis,
        &mut unbound,
    );

    assert_eq!(
        accepted_esis,
        [0u32].into_iter().collect::<HashSet<u32>>(),
        "only the well-formed, requested symbol (esi=0) is accepted"
    );
    assert_eq!(unbound.len(), 1, "exactly one unbound symbol produced");
    assert_eq!(unbound[0].esi, 0);
}

/// CS-DR-5: a symbol whose ESI was not requested from this holder is rejected.
#[test]
fn fetch_rejects_unrequested_esi() {
    let enc = encoder();
    let mut accepted_esis: HashSet<u32> = HashSet::new();
    let mut unbound: Vec<Symbol> = Vec::new();
    let wanted: HashSet<u32> = [5u32].into_iter().collect();

    let symbols = vec![sym(7, SYMBOL_LEN), sym(5, SYMBOL_LEN)];
    accept_holder_symbols(
        &enc,
        &block(),
        &holder(),
        symbols,
        &wanted,
        2,
        SYMBOL_LEN,
        2,
        &mut accepted_esis,
        &mut unbound,
    );

    assert_eq!(
        accepted_esis,
        [5u32].into_iter().collect::<HashSet<u32>>(),
        "esi=7 was never requested and must be rejected; only esi=5 accepted"
    );
}

/// CS-DR-5: per-holder cap and global dedup — duplicate ESIs from one holder do
/// not pad the quota.
#[test]
fn fetch_dedups_and_caps_per_holder() {
    let enc = encoder();
    let mut accepted_esis: HashSet<u32> = HashSet::new();
    let mut unbound: Vec<Symbol> = Vec::new();
    let wanted: HashSet<u32> = [0u32, 1u32].into_iter().collect();

    // Holder returns esi=0 three times (dupes) plus esi=1 once.
    let symbols = vec![
        sym(0, SYMBOL_LEN),
        sym(0, SYMBOL_LEN),
        sym(0, SYMBOL_LEN),
        sym(1, SYMBOL_LEN),
    ];
    accept_holder_symbols(
        &enc,
        &block(),
        &holder(),
        symbols,
        &wanted,
        /*holder_cap*/ 2,
        SYMBOL_LEN,
        /*k_eff*/ 2,
        &mut accepted_esis,
        &mut unbound,
    );

    assert_eq!(
        accepted_esis,
        [0u32, 1u32].into_iter().collect::<HashSet<u32>>(),
        "each ESI counts once; dupes don't pad quota"
    );
    assert_eq!(unbound.len(), 2, "two distinct symbols accepted");
}

/// CS-DR-5: a Byzantine first holder that floods k_eff duplicate symbols cannot
/// starve honest holders — progress is measured by UNIQUE accepted ESIs, so the
/// honest holder's distinct symbols still get us to k_eff.
#[test]
fn byzantine_first_holder_cannot_starve_honest_holders() {
    let enc = encoder();
    let blk = block();
    let k_eff = 3usize;

    let byzantine = DeviceId([0xBBu8; 32]);
    let honest = DeviceId([0xAAu8; 32]);

    let mut accepted_esis: HashSet<u32> = HashSet::new();
    let mut unbound: Vec<Symbol> = Vec::new();

    // Byzantine holder is asked for esi 0 (requested set = {0}); it floods many
    // copies of esi=0. With raw-count logic this would fill the k_eff quota; with
    // unique-ESI logic it contributes exactly one ESI.
    let byz_wanted: HashSet<u32> = [0u32].into_iter().collect();
    let byz_symbols: Vec<Symbol> = (0..k_eff * 4).map(|_| sym(0, SYMBOL_LEN)).collect();
    accept_holder_symbols(
        &enc,
        &blk,
        &byzantine,
        byz_symbols,
        &byz_wanted,
        /*holder_cap*/ 1, // only esi 0 was requested from it
        SYMBOL_LEN,
        k_eff,
        &mut accepted_esis,
        &mut unbound,
    );
    assert_eq!(
        accepted_esis.len(),
        1,
        "Byzantine flood contributes exactly one distinct ESI, not k_eff"
    );

    // Honest holder is asked for the remaining ESIs {1,2} and returns them.
    let honest_wanted: HashSet<u32> = [1u32, 2u32].into_iter().collect();
    let honest_symbols = vec![sym(1, SYMBOL_LEN), sym(2, SYMBOL_LEN)];
    accept_holder_symbols(
        &enc,
        &blk,
        &honest,
        honest_symbols,
        &honest_wanted,
        /*holder_cap*/ 2,
        SYMBOL_LEN,
        k_eff,
        &mut accepted_esis,
        &mut unbound,
    );

    assert_eq!(
        accepted_esis,
        [0u32, 1u32, 2u32].into_iter().collect::<HashSet<u32>>(),
        "honest holder's distinct symbols still reach k_eff despite the flood"
    );
    assert_eq!(accepted_esis.len(), k_eff, "collected k_eff distinct ESIs");
}

// ─── restore-i12: chunked requests in rounds, no deadline ────────────────────
//
// `ScriptedHolders` is the fake `SymbolSource`: per holder it serves the requested
// ESIs (symbols of length `t`), fails the first N requests (the 30 s request
// timeout), answers empty, answers only even ESIs, or hangs. Every request is
// logged.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio_util::sync::CancellationToken;
use viaticum_core::messages::RestoreRequestMsg;
use viaticum_core::types::{ErasureParams, PlacementStatus, SymbolPlacement, Timestamp};

use super::{
    BlockFetch, FailedInTask, FetchError, RESTORE_FETCH_CHUNK_BYTES, RoundEnd, SymbolSource,
    chunk_esis, fetch_in_rounds, fetch_unbound_symbols,
};

enum Behavior {
    Serve,
    /// Fail this many requests, then serve.
    FailFirst(AtomicU32),
    AlwaysFail,
    /// Every request runs into the request timeout (restore-i44: a silent holder).
    TimesOut,
    /// Every request ends on a dropped connection (EOF: the holder evicted us).
    Closed,
    Empty,
    EvenOnly,
    Hang,
}

struct ScriptedHolders {
    t: usize,
    behavior: HashMap<DeviceId, Behavior>,
    log: Mutex<Vec<(DeviceId, Vec<u32>)>>,
    /// Fired inside the first request (the request itself still answers).
    cancel_on_first_request: Option<CancellationToken>,
    /// What `connected_holders` reports (restore-i43); empty unless a test sets it.
    connected: HashSet<DeviceId>,
}

impl ScriptedHolders {
    fn new(t: usize, behavior: Vec<(DeviceId, Behavior)>) -> Self {
        ScriptedHolders {
            t,
            behavior: behavior.into_iter().collect(),
            log: Mutex::new(Vec::new()),
            cancel_on_first_request: None,
            connected: HashSet::new(),
        }
    }

    /// Pin the round order of a two-holder test to A, B: A is the connected one, asked
    /// first (restore-i43); otherwise the per-block shuffle decides.
    fn a_first(mut self) -> Self {
        self.connected = [A].into_iter().collect();
        self
    }

    fn asked(&self, holder: DeviceId) -> Vec<Vec<u32>> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|(h, _)| *h == holder)
            .map(|(_, esis)| esis.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl SymbolSource for ScriptedHolders {
    async fn request(
        &self,
        holder: DeviceId,
        req: RestoreRequestMsg,
    ) -> Result<Vec<Symbol>, FetchError> {
        let first = {
            let mut log = self.log.lock().unwrap();
            log.push((holder, req.esi_list.clone()));
            log.len() == 1
        };
        if first && let Some(c) = &self.cancel_on_first_request {
            c.cancel();
        }
        let serve = |esis: &[u32]| esis.iter().map(|e| sym(*e, self.t)).collect::<Vec<_>>();
        match self.behavior.get(&holder).expect("scripted holder") {
            Behavior::Serve => Ok(serve(&req.esi_list)),
            Behavior::FailFirst(n) => {
                if n.load(Ordering::SeqCst) > 0 {
                    n.fetch_sub(1, Ordering::SeqCst);
                    Err(FetchError::Swarm("request timed out".into()))
                } else {
                    Ok(serve(&req.esi_list))
                }
            }
            Behavior::AlwaysFail => Err(FetchError::Swarm("dial failed".into())),
            Behavior::TimesOut => Err(FetchError::Timeout),
            Behavior::Closed => Err(FetchError::Swarm(
                "request failed: Connection closed before a response was received".into(),
            )),
            Behavior::Empty => Ok(Vec::new()),
            Behavior::EvenOnly => {
                let even: Vec<u32> = req
                    .esi_list
                    .iter()
                    .copied()
                    .filter(|e| e % 2 == 0)
                    .collect();
                Ok(serve(&even))
            }
            Behavior::Hang => {
                std::future::pending::<()>().await;
                unreachable!()
            }
        }
    }

    async fn connected_holders(&self) -> HashSet<DeviceId> {
        self.connected.clone()
    }
}

fn params(k_eff: u32, t: u16) -> ErasureParams {
    ErasureParams {
        k: k_eff,
        k_eff,
        t,
        overhead: 1.5,
        n: k_eff * 2,
    }
}

fn placement(holder: DeviceId, start: u32, count: u32) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block(),
        holder_id: holder,
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(start, count)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    }
}

const A: DeviceId = DeviceId([0xA1u8; 32]);
const B: DeviceId = DeviceId([0xB2u8; 32]);

/// restore-i12: no request asks one holder for more than RESTORE_FETCH_CHUNK_BYTES
/// of symbols (64 ESIs at the largest symbol size), even when the holder has
/// everything and k_eff is far larger.
#[tokio::test]
async fn each_request_asks_at_most_chunk_esis() {
    let t = u16::MAX;
    let p = params(200, t);
    let holders = ScriptedHolders::new(t as usize, vec![(A, Behavior::Serve)]);
    let got = fetch_unbound_symbols(
        &holders,
        &encoder(),
        &block(),
        &[placement(A, 0, 300)],
        &p,
        None,
        &FailedInTask::default(),
    )
    .await
    .unwrap();

    assert_eq!(got.len(), 200);
    let max_esis = (RESTORE_FETCH_CHUNK_BYTES / u64::from(t)) as usize;
    let asked = holders.asked(A);
    assert_eq!(asked.len(), 200usize.div_ceil(max_esis), "{asked:?}");
    for req in &asked {
        assert!(
            req.len() * t as usize <= RESTORE_FETCH_CHUNK_BYTES as usize,
            "a request of {} ESIs x {t} B exceeds the chunk",
            req.len()
        );
    }
}

#[tokio::test]
async fn fetch_collects_k_eff_across_multiple_chunks_from_one_holder() {
    let holders = ScriptedHolders::new(SYMBOL_LEN, vec![(A, Behavior::Serve)]);
    let got = fetch_in_rounds(
        &holders,
        &encoder(),
        &block(),
        &[placement(A, 0, 20)],
        &params(10, SYMBOL_LEN as u16),
        None,
        3,
    )
    .await
    .unwrap();

    let mut esis: Vec<u32> = got.iter().map(|s| s.esi).collect();
    esis.sort();
    assert_eq!(esis, (0..10).collect::<Vec<u32>>());
    let sizes: Vec<usize> = holders.asked(A).iter().map(Vec::len).collect();
    assert_eq!(
        sizes,
        vec![3, 3, 3, 1],
        "chunks, the last one only what is still needed"
    );
}

/// restore-i12: a holder whose request times out is skipped for the rest of the
/// round (the others go on) and asked again in the next round.
#[tokio::test]
async fn stalled_holder_is_skipped_this_round_and_retried_next_round() {
    let holders = ScriptedHolders::new(
        SYMBOL_LEN,
        vec![
            (A, Behavior::FailFirst(AtomicU32::new(1))),
            (B, Behavior::Serve),
        ],
    )
    .a_first();
    let got = fetch_in_rounds(
        &holders,
        &encoder(),
        &block(),
        &[placement(A, 0, 5), placement(B, 5, 5)],
        &params(8, SYMBOL_LEN as u16),
        None,
        3,
    )
    .await
    .unwrap();

    assert_eq!(got.len(), 8);
    let order: Vec<DeviceId> = holders
        .log
        .lock()
        .unwrap()
        .iter()
        .map(|(h, _)| *h)
        .collect();
    assert_eq!(
        order,
        vec![A, B, B, A],
        "A failed, B served round 1, A retried in round 2"
    );
    assert_eq!(holders.asked(A), vec![vec![0, 1, 2], vec![0, 1, 2]]);
}

/// restore-i12: the fetch gives up only after a whole round without a new ESI —
/// here round 2, when the failing holder fails again and the other has nothing
/// left. It terminates, and reports what it got.
#[tokio::test]
async fn fetch_gives_up_after_a_round_without_new_esis() {
    let holders = ScriptedHolders::new(
        SYMBOL_LEN,
        vec![(A, Behavior::AlwaysFail), (B, Behavior::Serve)],
    );
    let err = fetch_in_rounds(
        &holders,
        &encoder(),
        &block(),
        &[placement(A, 0, 5), placement(B, 5, 2)],
        &params(5, SYMBOL_LEN as u16),
        None,
        3,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            FetchError::InsufficientSymbols {
                got: 2,
                need: 5,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        holders.asked(A).len(),
        2,
        "asked once per round: rounds 1 and 2"
    );
    assert_eq!(
        holders.asked(B).len(),
        1,
        "B had nothing left to ask in round 2"
    );
}

/// A holder that answers a chunk with nothing usable is exhausted: not asked again.
#[tokio::test]
async fn holder_answering_zero_symbols_is_not_asked_again() {
    let holders =
        ScriptedHolders::new(SYMBOL_LEN, vec![(A, Behavior::Empty), (B, Behavior::Serve)]);
    let err = fetch_in_rounds(
        &holders,
        &encoder(),
        &block(),
        &[placement(A, 0, 5), placement(B, 5, 3)],
        &params(5, SYMBOL_LEN as u16),
        None,
        3,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, FetchError::InsufficientSymbols { got: 3, .. }),
        "{err:?}"
    );
    assert_eq!(holders.asked(A).len(), 1);
}

/// ESIs a holder was asked for and did not return are not asked from it again
/// (termination: a holder contributes each of its ESIs at most once).
#[tokio::test]
async fn esis_a_holder_did_not_return_are_not_asked_again() {
    let holders = ScriptedHolders::new(
        SYMBOL_LEN,
        vec![(A, Behavior::EvenOnly), (B, Behavior::Serve)],
    )
    .a_first();
    let got = fetch_in_rounds(
        &holders,
        &encoder(),
        &block(),
        &[placement(A, 0, 6), placement(B, 6, 6)],
        &params(6, SYMBOL_LEN as u16),
        None,
        6,
    )
    .await
    .unwrap();

    assert_eq!(got.len(), 6);
    assert_eq!(holders.asked(A), vec![vec![0, 1, 2, 3, 4, 5]]);
    assert_eq!(holders.asked(B), vec![vec![6, 7, 8]]);
}

/// T10: the daemon's cancel token stops the fetch between chunks.
#[tokio::test]
async fn fetch_returns_cancelled_when_token_fires_between_chunks() {
    let cancel = CancellationToken::new();
    let mut holders = ScriptedHolders::new(SYMBOL_LEN, vec![(A, Behavior::Serve)]);
    holders.cancel_on_first_request = Some(cancel.clone());
    let err = fetch_in_rounds(
        &holders,
        &encoder(),
        &block(),
        &[placement(A, 0, 20)],
        &params(10, SYMBOL_LEN as u16),
        Some(&cancel),
        3,
    )
    .await
    .unwrap_err();

    assert!(matches!(err, FetchError::Cancelled), "{err:?}");
    assert_eq!(holders.asked(A).len(), 1, "no chunk after the cancel");
}

/// T10: a request in flight to a silent holder is abandoned on cancel.
#[tokio::test]
async fn hanging_request_is_abandoned_on_cancel() {
    let cancel = CancellationToken::new();
    let holders = ScriptedHolders::new(SYMBOL_LEN, vec![(A, Behavior::Hang)]);
    let c = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        c.cancel();
    });
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fetch_in_rounds(
            &holders,
            &encoder(),
            &block(),
            &[placement(A, 0, 5)],
            &params(3, SYMBOL_LEN as u16),
            Some(&cancel),
            3,
        ),
    )
    .await
    .expect("cancel must abandon the hanging request");
    assert!(matches!(res, Err(FetchError::Cancelled)), "{res:?}");
}

#[test]
fn chunk_of_one_esi_when_symbol_larger_than_chunk_budget() {
    assert_eq!(chunk_esis(10, u16::MAX), 1);
    assert_eq!(chunk_esis(RESTORE_FETCH_CHUNK_BYTES, u16::MAX), 64);
    assert_eq!(
        chunk_esis(RESTORE_FETCH_CHUNK_BYTES, 0),
        RESTORE_FETCH_CHUNK_BYTES as usize
    );
}

// ─── restore-i26: how a round ended ─────────────────────────────────────────

/// Every request of the round failed (no connection, timeout): `NoAnswer`, not
/// "nothing new" — it says nothing about what the holders hold.
#[tokio::test]
async fn round_where_every_request_fails_ends_no_answer() {
    let holders = ScriptedHolders::new(
        SYMBOL_LEN,
        vec![(A, Behavior::AlwaysFail), (B, Behavior::AlwaysFail)],
    )
    .a_first();
    let (enc, blk) = (encoder(), block());
    let placements = [placement(A, 0, 5), placement(B, 5, 5)];
    let p = params(5, SYMBOL_LEN as u16);
    let mut fetch = BlockFetch::new(&enc, &blk, &placements, &p, 3);

    let round = fetch.round(&holders, None).await.unwrap();
    assert_eq!(round.end, RoundEnd::NoAnswer);
    assert!(round.answered.is_empty());
    assert_eq!(round.failed, vec![A, B]);
    assert_eq!(fetch.holder_ids(), vec![A, B]);
    assert_eq!(holders.asked(A).len() + holders.asked(B).len(), 2);
}

/// Every holder asked answered, none gave anything: `NothingNew` (the
/// restore-i12 verdict).
#[tokio::test]
async fn round_where_holders_answer_empty_ends_nothing_new() {
    let holders =
        ScriptedHolders::new(SYMBOL_LEN, vec![(A, Behavior::Empty), (B, Behavior::Empty)])
            .a_first();
    let (enc, blk) = (encoder(), block());
    let placements = [placement(A, 0, 5), placement(B, 5, 5)];
    let p = params(5, SYMBOL_LEN as u16);
    let mut fetch = BlockFetch::new(&enc, &blk, &placements, &p, 3);

    let round = fetch.round(&holders, None).await.unwrap();
    assert_eq!(round.end, RoundEnd::NothingNew);
    assert_eq!(round.answered, vec![A, B]);
    assert!(round.failed.is_empty());
}

/// restore-i33: right after DR one holder is connected and has nothing, the others
/// are not connected yet. Their failure is not "they have nothing": `NoAnswer`, so
/// restore pauses instead of giving the block up in milliseconds.
#[tokio::test]
async fn round_where_one_answers_empty_and_others_fail_ends_no_answer() {
    let holders = ScriptedHolders::new(
        SYMBOL_LEN,
        vec![(A, Behavior::Empty), (B, Behavior::AlwaysFail)],
    );
    let (enc, blk) = (encoder(), block());
    let placements = [placement(A, 0, 5), placement(B, 5, 5)];
    let p = params(5, SYMBOL_LEN as u16);
    let mut fetch = BlockFetch::new(&enc, &blk, &placements, &p, 3);

    let round = fetch.round(&holders, None).await.unwrap();
    assert_eq!(round.end, RoundEnd::NoAnswer);
    assert_eq!(round.answered, vec![A]);
    assert_eq!(round.failed, vec![B]);
    // A answered empty: exhausted, never asked again, so no endless retry of it.
    let round = fetch.round(&holders, None).await.unwrap();
    assert_eq!(round.end, RoundEnd::NoAnswer);
    assert!(round.answered.is_empty());
    assert_eq!(holders.asked(A).len(), 1);
}

/// No candidate holder: no request, `NobodyToAsk` (never a retry).
#[tokio::test]
async fn round_without_candidate_holders_ends_nobody_to_ask() {
    let holders = ScriptedHolders::new(SYMBOL_LEN, vec![]);
    let (enc, blk) = (encoder(), block());
    let p = params(5, SYMBOL_LEN as u16);
    let mut fetch = BlockFetch::new(&enc, &blk, &[], &p, 3);

    assert_eq!(
        fetch.round(&holders, None).await.unwrap().end,
        RoundEnd::NobodyToAsk
    );
    assert!(holders.log.lock().unwrap().is_empty());
}

/// A round nobody answered loses nothing: the next round of the same fetch goes on
/// from the ESIs already collected.
#[tokio::test]
async fn round_after_no_answer_keeps_what_was_collected() {
    let holders = ScriptedHolders::new(
        SYMBOL_LEN,
        vec![
            (A, Behavior::Serve),
            (B, Behavior::FailFirst(AtomicU32::new(2))),
        ],
    );
    let (enc, blk) = (encoder(), block());
    let placements = [placement(A, 0, 3), placement(B, 3, 5)];
    let p = params(6, SYMBOL_LEN as u16);
    let mut fetch = BlockFetch::new(&enc, &blk, &placements, &p, 3);

    assert_eq!(
        fetch.round(&holders, None).await.unwrap().end,
        RoundEnd::Progress
    );
    assert_eq!(fetch.have(), 3);
    assert_eq!(
        fetch.round(&holders, None).await.unwrap().end,
        RoundEnd::NoAnswer
    );
    assert_eq!(fetch.have(), 3, "nothing lost");
    assert_eq!(
        fetch.round(&holders, None).await.unwrap().end,
        RoundEnd::Complete
    );
    let got = fetch.finish().unwrap();
    assert_eq!(got.len(), 6);
    assert_eq!(
        holders.asked(A).len(),
        1,
        "A is not asked again for what it gave"
    );
}

/// DR keeps its behaviour (spec §2.15 p. 6): `fetch_in_rounds` stops at a round
/// nobody answered, with `InsufficientSymbols` (it takes a bare `SymbolSource`, so
/// it cannot redial).
#[tokio::test]
async fn fetch_in_rounds_stops_at_no_answer() {
    let holders = ScriptedHolders::new(SYMBOL_LEN, vec![(A, Behavior::AlwaysFail)]);
    let err = fetch_in_rounds(
        &holders,
        &encoder(),
        &block(),
        &[placement(A, 0, 5)],
        &params(3, SYMBOL_LEN as u16),
        None,
        3,
    )
    .await
    .unwrap_err();

    assert!(
        matches!(
            err,
            FetchError::InsufficientSymbols {
                got: 0,
                need: 3,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(holders.asked(A).len(), 1, "one round");
}

// restore-i43: the order a round asks a block's holders in.
mod holder_order;
// restore-i43: the swarm's authenticated devices are the connected holders.
mod connected;
// restore-i44: a holder that failed in the task is asked last for the rest of it.
mod failed_in_task;
