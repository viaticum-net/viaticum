// One block's fetch, round by round (restore-i12, restore-i26).
//
// `BlockFetch` keeps what was collected so far across rounds; `round` asks every
// holder that still has something for us once (in chunks) and says how the round
// ended. Callers decide what to do next: `fetch_in_rounds` stops at the first
// round without progress (DR, tests); restore pauses after a round nobody
// answered and tries the same `BlockFetch` again (restore-i26).

use std::collections::HashSet;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use viaticum_core::erasure::{ErasureEncoder, Symbol};
use viaticum_core::messages::RestoreRequestMsg;
use viaticum_core::types::{
    DeviceId, ErasureParams, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
    ranges_to_esi_list,
};

use super::{FetchError, SymbolSource, accept_holder_symbols};

/// How one round over the holders ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoundEnd {
    /// `k_eff` distinct ESIs collected: the block can be decoded.
    Complete,
    /// New ESIs accepted but the block is not complete: another round.
    Progress,
    /// At least one holder answered, none gave anything new: the holders we can
    /// reach do not have the rest. The block cannot be completed.
    NothingNew,
    /// Every request of the round failed (timeout, no connection): nobody
    /// answered. Says nothing about what the holders hold (restore-i26).
    NoAnswer,
    /// No request was sent: every holder is exhausted or has nothing left we
    /// could ask for (or there are no candidate holders at all).
    NobodyToAsk,
}

/// Per-holder state across rounds.
struct HolderRound<'a> {
    placement: &'a SymbolPlacement,
    /// The holder's assigned ESIs, in order.
    esis: Vec<u32>,
    /// ESIs this holder was asked for and did not return (or returned malformed).
    missing: HashSet<u32>,
    /// Answered a chunk with nothing usable: not asked again.
    exhausted: bool,
}

/// The collected state of one block's fetch.
pub(crate) struct BlockFetch<'a> {
    encoder: &'a Arc<dyn ErasureEncoder>,
    block_id: &'a SourceBlockId,
    k_eff: usize,
    symbol_len: usize,
    chunk: usize,
    holders: Vec<HolderRound<'a>>,
    unbound_symbols: Vec<Symbol>,
    /// Every ESI already accepted, from any holder: progress toward k_eff is the
    /// size of this set, never a raw symbol count (CS-DR-5).
    accepted_esis: HashSet<u32>,
    round: u32,
}

impl<'a> BlockFetch<'a> {
    /// Candidates: Alive | Uncertain | PresumedLost placements (restore-i2).
    pub(crate) fn new(
        encoder: &'a Arc<dyn ErasureEncoder>,
        block_id: &'a SourceBlockId,
        placements: &'a [SymbolPlacement],
        params: &ErasureParams,
        chunk: usize,
    ) -> Self {
        let holders = placements
            .iter()
            .filter(|p| {
                matches!(
                    p.status,
                    PlacementStatus::Alive
                        | PlacementStatus::Uncertain
                        | PlacementStatus::PresumedLost
                )
            })
            .map(|p| HolderRound {
                placement: p,
                esis: ranges_to_esi_list(&p.esi_ranges),
                missing: HashSet::new(),
                exhausted: false,
            })
            .collect();
        BlockFetch {
            encoder,
            block_id,
            k_eff: params.k_eff as usize,
            symbol_len: params.t as usize,
            chunk: chunk.max(1),
            holders,
            unbound_symbols: Vec::new(),
            accepted_esis: HashSet::new(),
            round: 0,
        }
    }

    /// The candidate holders (for a redial before a pause).
    pub(crate) fn holder_ids(&self) -> Vec<DeviceId> {
        self.holders.iter().map(|h| h.placement.holder_id).collect()
    }

    /// Distinct ESIs accepted so far.
    pub(crate) fn have(&self) -> usize {
        self.accepted_esis.len()
    }

    /// One round: each holder not exhausted is asked, in chunks of at most `chunk`
    /// ESIs from its ranges not yet accepted and not yet asked-and-not-returned by
    /// it, until it has nothing left for us, fails, is exhausted, or the block is
    /// complete. A holder whose request errors is skipped for the rest of the round
    /// (asked again next round); one that answers a chunk with zero accepted
    /// symbols is exhausted. `Err` only on cancel (a request in flight is
    /// abandoned).
    pub(crate) async fn round(
        &mut self,
        source: &dyn SymbolSource,
        cancel: Option<&CancellationToken>,
    ) -> Result<RoundEnd, FetchError> {
        if self.accepted_esis.len() >= self.k_eff {
            return Ok(RoundEnd::Complete);
        }
        self.round += 1;
        let round = self.round;
        let block_id = self.block_id;
        let (k_eff, chunk) = (self.k_eff, self.chunk);
        let before = self.accepted_esis.len();
        let (mut asked, mut answered) = (0usize, 0usize);
        let is_cancelled = || cancel.is_some_and(|c| c.is_cancelled());

        for holder in self.holders.iter_mut().filter(|h| !h.exhausted) {
            while self.accepted_esis.len() < k_eff {
                if is_cancelled() {
                    return Err(FetchError::Cancelled);
                }
                let still_needed = k_eff - self.accepted_esis.len();
                let wanted: Vec<u32> = holder
                    .esis
                    .iter()
                    .copied()
                    .filter(|e| !self.accepted_esis.contains(e) && !holder.missing.contains(e))
                    .take(chunk.min(still_needed))
                    .collect();
                if wanted.is_empty() {
                    break;
                }
                let holder_id = holder.placement.holder_id;
                let request = RestoreRequestMsg {
                    v: 1,
                    source_block_id: *block_id,
                    esi_list: wanted.clone(),
                    timestamp: Timestamp::now(),
                };
                asked += 1;
                let reply = match cancel {
                    Some(c) => tokio::select! {
                        biased;
                        _ = c.cancelled() => return Err(FetchError::Cancelled),
                        r = source.request(holder_id, request) => r,
                    },
                    None => source.request(holder_id, request).await,
                };
                match reply {
                    Ok(symbols) => {
                        answered += 1;
                        debug!(
                            holder = %holder_id,
                            block = %block_id,
                            round,
                            asked = wanted.len(),
                            count = symbols.len(),
                            "fetch: received bound symbols from holder"
                        );
                        // The holder's allowed ESIs and the cap on how many symbols
                        // we accept from it for this chunk (CS-DR-5).
                        let wanted_set: HashSet<u32> = wanted.iter().copied().collect();
                        let got = accept_holder_symbols(
                            self.encoder,
                            block_id,
                            &holder_id,
                            symbols,
                            &wanted_set,
                            wanted.len(),
                            self.symbol_len,
                            k_eff,
                            &mut self.accepted_esis,
                            &mut self.unbound_symbols,
                        );
                        for esi in &wanted {
                            if !self.accepted_esis.contains(esi) {
                                holder.missing.insert(*esi);
                            }
                        }
                        if got == 0 {
                            holder.exhausted = true;
                            break;
                        }
                    }
                    Err(FetchError::Cancelled) => return Err(FetchError::Cancelled),
                    Err(e) => {
                        warn!(
                            holder = %holder_id,
                            block = %block_id,
                            round,
                            err = %e,
                            "fetch: holder did not answer; skipped this round, asked again next round"
                        );
                        break;
                    }
                }
            }
            if self.accepted_esis.len() >= k_eff {
                break;
            }
        }

        let have = self.accepted_esis.len();
        let end = if have >= k_eff {
            RoundEnd::Complete
        } else if have > before {
            RoundEnd::Progress
        } else if answered > 0 {
            RoundEnd::NothingNew
        } else if asked > 0 {
            RoundEnd::NoAnswer
        } else {
            RoundEnd::NobodyToAsk
        };
        if end == RoundEnd::Progress {
            info!(
                block = %block_id,
                round,
                have,
                need = k_eff,
                "fetch: round made progress but the block is not complete; next round"
            );
        }
        Ok(end)
    }

    /// The unbound symbols once `k_eff` distinct ESIs are in, else
    /// `InsufficientSymbols` with how many there are.
    pub(crate) fn finish(self) -> Result<Vec<Symbol>, FetchError> {
        if self.accepted_esis.len() < self.k_eff {
            Err(FetchError::InsufficientSymbols {
                block: *self.block_id,
                got: self.accepted_esis.len(),
                need: self.k_eff,
            })
        } else {
            Ok(self.unbound_symbols)
        }
    }
}
