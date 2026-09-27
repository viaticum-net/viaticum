// Shared helper for fetching unbound erasure symbols from holders over libp2p.
//
// Used by:
//   - `restore`: normal restore flow (with the daemon's cancel token).
//   - `dr`:      the SystemState block during disaster recovery (no cancel).
//
// restore-i12: a slow home link is not "holders unavailable". Each request asks one
// holder for at most `RESTORE_FETCH_CHUNK_BYTES` of symbols; there is no deadline on
// a block. The fetch goes in rounds over the holders and gives up only after a full
// round that accepted no new ESI. A holder whose request fails (the 30 s request
// timeout, a dial failure) is skipped for the rest of the round and asked again in
// the next one.
//
// There is no restore gate on the holder (restore-i6): a holder either serves the
// owner's symbols or answers empty (no active holding for this owner).

use std::collections::HashSet;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use viaticum_core::erasure::{ErasureEncoder, Symbol};
use viaticum_core::messages::{Message, RestoreRequestMsg};
use viaticum_core::types::{
    DeviceId, ErasureParams, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
    ranges_to_esi_list,
};

use crate::daemon::network::swarm::SwarmHandle;

/// Maximum ESI value the raptorq decoder accepts: ESI is a 24-bit field, so any
/// value `>= 2^24` makes `PayloadId::new(0, esi)` assert-panic inside raptorq.
/// We reject such symbols at the wire boundary before they ever reach `decode`.
const MAX_VALID_ESI: u32 = 1 << 24;

/// Upper bound on symbol bytes asked from one holder in one `RestoreRequest`. At the
/// fixed 30 s request timeout (`network/swarm.rs`) this tolerates ≈ 1.1 Mbit/s per
/// holder (restore-i12).
pub const RESTORE_FETCH_CHUNK_BYTES: u64 = 4 * 1024 * 1024;

#[cfg(test)]
mod tests;

/// Errors from fetching unbound symbols from holders.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("insufficient symbols: collected {got}, need {need} for block {block}")]
    InsufficientSymbols {
        block: SourceBlockId,
        got: usize,
        need: usize,
    },

    /// One request to one holder failed (timeout, dial, unexpected reply). Never
    /// returned by `fetch_unbound_symbols`: it skips the holder for the round.
    #[error("swarm error: {0}")]
    Swarm(String),

    /// The daemon is stopping; the fetch was abandoned.
    #[error("fetch cancelled: the daemon is stopping")]
    Cancelled,
}

/// One `RestoreRequest` to one holder. Implemented for `SwarmHandle`; tests use a
/// scripted fake.
#[async_trait::async_trait]
pub trait SymbolSource: Send + Sync {
    /// Ask `holder` for the ESIs in `req`; returns the bound symbols it sent.
    async fn request(
        &self,
        holder: DeviceId,
        req: RestoreRequestMsg,
    ) -> Result<Vec<Symbol>, FetchError>;
}

#[async_trait::async_trait]
impl SymbolSource for SwarmHandle {
    async fn request(
        &self,
        holder: DeviceId,
        req: RestoreRequestMsg,
    ) -> Result<Vec<Symbol>, FetchError> {
        fetch_symbols_from_holder(self, &holder, req).await
    }
}

/// ESIs per request for symbol size `t`: `max(1, chunk_bytes / t)`.
pub(crate) fn chunk_esis(chunk_bytes: u64, t: u16) -> usize {
    (chunk_bytes / u64::from(t.max(1))).max(1) as usize
}

/// Collect `k_eff` distinct unbound symbols for `block_id` (restore-i12).
///
/// Rounds over the candidate placements (Alive | Uncertain | PresumedLost). Within a
/// round each holder is asked in chunks of at most
/// `max(1, RESTORE_FETCH_CHUNK_BYTES / params.t)` ESIs from its assigned ranges that
/// are not yet accepted and not yet asked-and-not-returned by it. A holder whose
/// request errors is skipped for the rest of the round and asked again next round. A
/// holder that answers a chunk with zero accepted symbols is exhausted. No deadline:
/// the fetch gives up only after a full round that accepted zero new ESIs
/// (→ `InsufficientSymbols`), or on cancel (→ `Cancelled`; a request in flight is
/// abandoned). Every accepted symbol passes the CS-DR-2 / CS-DR-5 checks
/// (`accept_holder_symbols`).
///
/// Termination: every round that does not stop the loop accepts at least one new
/// ESI, and a holder can only contribute ESIs of its own finite ranges, each once.
pub(crate) async fn fetch_unbound_symbols(
    source: &dyn SymbolSource,
    encoder: &Arc<dyn ErasureEncoder>,
    block_id: &SourceBlockId,
    placements: &[SymbolPlacement],
    params: &ErasureParams,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<Symbol>, FetchError> {
    let chunk = chunk_esis(RESTORE_FETCH_CHUNK_BYTES, params.t);
    fetch_in_rounds(source, encoder, block_id, placements, params, cancel, chunk).await
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

/// `fetch_unbound_symbols` with the chunk size given (seam for tests).
pub(crate) async fn fetch_in_rounds(
    source: &dyn SymbolSource,
    encoder: &Arc<dyn ErasureEncoder>,
    block_id: &SourceBlockId,
    placements: &[SymbolPlacement],
    params: &ErasureParams,
    cancel: Option<&CancellationToken>,
    chunk: usize,
) -> Result<Vec<Symbol>, FetchError> {
    let k_eff = params.k_eff as usize;
    let symbol_len = params.t as usize;
    let chunk = chunk.max(1);
    let mut unbound_symbols: Vec<Symbol> = Vec::new();
    // Every ESI already accepted, from any holder: progress toward k_eff is the
    // size of this set, never a raw symbol count (CS-DR-5).
    let mut accepted_esis: HashSet<u32> = HashSet::new();
    let is_cancelled = || cancel.is_some_and(|c| c.is_cancelled());

    let mut holders: Vec<HolderRound<'_>> = placements
        .iter()
        .filter(|p| {
            matches!(
                p.status,
                PlacementStatus::Alive | PlacementStatus::Uncertain | PlacementStatus::PresumedLost
            )
        })
        .map(|p| HolderRound {
            placement: p,
            esis: ranges_to_esi_list(&p.esi_ranges),
            missing: HashSet::new(),
            exhausted: false,
        })
        .collect();

    let mut round = 0u32;
    while accepted_esis.len() < k_eff {
        round += 1;
        let before = accepted_esis.len();
        for holder in holders.iter_mut().filter(|h| !h.exhausted) {
            // Chunks to this holder until it has nothing left for us, fails, is
            // exhausted, or the block is complete.
            while accepted_esis.len() < k_eff {
                if is_cancelled() {
                    return Err(FetchError::Cancelled);
                }
                let still_needed = k_eff - accepted_esis.len();
                let wanted: Vec<u32> = holder
                    .esis
                    .iter()
                    .copied()
                    .filter(|e| !accepted_esis.contains(e) && !holder.missing.contains(e))
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
                            encoder,
                            block_id,
                            &holder_id,
                            symbols,
                            &wanted_set,
                            wanted.len(),
                            symbol_len,
                            k_eff,
                            &mut accepted_esis,
                            &mut unbound_symbols,
                        );
                        for esi in &wanted {
                            if !accepted_esis.contains(esi) {
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
            if accepted_esis.len() >= k_eff {
                break;
            }
        }
        let accepted_this_round = accepted_esis.len() - before;
        if accepted_this_round == 0 {
            break;
        }
        if accepted_esis.len() < k_eff {
            info!(
                block = %block_id,
                round,
                have = accepted_esis.len(),
                need = k_eff,
                "fetch: round made progress but the block is not complete; next round"
            );
        }
    }

    if accepted_esis.len() < k_eff {
        Err(FetchError::InsufficientSymbols {
            block: *block_id,
            got: accepted_esis.len(),
            need: k_eff,
        })
    } else {
        Ok(unbound_symbols)
    }
}

/// Apply the wire-boundary checks to one holder's reply and append the accepted,
/// unbound symbols to `unbound_symbols`, recording newly-accepted ESIs in
/// `accepted_esis`; returns how many were accepted. Pure (no network) so it can be
/// unit-tested directly.
///
/// Enforces, in order, for each received symbol:
///   - per-holder cap and global `k_eff` ceiling (stop early once reached),
///   - form validity (CS-DR-2): `esi < 2^24` and `data.len() == symbol_len`,
///   - membership (CS-DR-5): `esi ∈ wanted_set` (only what this holder was asked),
///   - global dedup (CS-DR-5): an ESI already accepted is skipped.
///
/// A symbol failing form/membership is logged WARN and attributed to `holder_id`.
#[allow(clippy::too_many_arguments)]
fn accept_holder_symbols(
    encoder: &Arc<dyn ErasureEncoder>,
    block_id: &SourceBlockId,
    holder_id: &DeviceId,
    symbols: Vec<Symbol>,
    wanted_set: &HashSet<u32>,
    holder_cap: usize,
    symbol_len: usize,
    k_eff: usize,
    accepted_esis: &mut HashSet<u32>,
    unbound_symbols: &mut Vec<Symbol>,
) -> usize {
    let mut accepted_from_holder = 0usize;
    for sym in symbols {
        if accepted_from_holder >= holder_cap || accepted_esis.len() >= k_eff {
            break;
        }
        // CS-DR-2: reject malformed symbols before they reach decode().
        if sym.esi >= MAX_VALID_ESI || sym.data.len() != symbol_len {
            warn!(
                holder = %holder_id,
                block = %block_id,
                esi = sym.esi,
                len = sym.data.len(),
                expected_len = symbol_len,
                "fetch: holder returned malformed symbol (bad esi/len), skipping"
            );
            continue;
        }
        // CS-DR-5: holder may only answer ESIs it was asked for.
        if !wanted_set.contains(&sym.esi) {
            warn!(
                holder = %holder_id,
                block = %block_id,
                esi = sym.esi,
                "fetch: holder returned unrequested esi, skipping"
            );
            continue;
        }
        // CS-DR-5: count each ESI once globally.
        if !accepted_esis.insert(sym.esi) {
            continue;
        }
        let unbound = encoder.unbind(sym, block_id, holder_id);
        unbound_symbols.push(unbound);
        accepted_from_holder += 1;
    }
    accepted_from_holder
}

/// Contact one holder, send a RestoreRequest, receive a RestoreResponse via libp2p.
///
/// Returns the raw bound symbols (caller unbinds).
async fn fetch_symbols_from_holder(
    swarm: &SwarmHandle,
    holder_device: &DeviceId,
    request: RestoreRequestMsg,
) -> Result<Vec<Symbol>, FetchError> {
    let response = swarm
        .send_to_device(*holder_device, Message::RestoreRequest(request))
        .await
        .map_err(|e| FetchError::Swarm(e.to_string()))?;

    match response {
        Message::RestoreResponse(resp) => {
            debug!(
                holder = %holder_device,
                symbols = resp.symbols.len(),
                "fetch: received RestoreResponse via swarm"
            );
            Ok(resp.symbols)
        }
        other => {
            warn!(
                holder = %holder_device,
                msg = ?std::mem::discriminant(&other),
                "fetch: unexpected swarm response, treating as error"
            );
            Err(FetchError::Swarm(
                "unexpected message type during restore".to_string(),
            ))
        }
    }
}
