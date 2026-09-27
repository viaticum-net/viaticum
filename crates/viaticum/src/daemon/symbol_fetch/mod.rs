// Shared helper for fetching unbound erasure symbols from holders over libp2p.
//
// Used by:
//   - `restore`: normal restore flow.
//   - `repair`:  fallback when local `block.bin` and source-file rebuild both fail
//                (holder-disk-dies scenario).
//
// Fetches sequentially from Alive placements, unbinds returned symbols, returns
// at least `k_eff` unbound symbols or `InsufficientSymbols`.
//
// There is no restore gate on the holder (restore-i6): a holder either serves the
// owner's symbols or answers empty (no active holding for this owner).

use std::collections::HashSet;
use std::sync::Arc;

use tracing::{debug, warn};
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

// The network round-trip (fetch_unbound_symbols) requires a live SwarmHandle and
// is covered end-to-end via restore/tests.rs integration tests and
// local_e2e_test.sh. The pure wire-validation / dedup / cap boundary logic
// (CS-DR-2 / CS-DR-5) is split into `accept_holder_symbols` and unit-tested in
// `tests.rs` with real symbols + a real encoder, no swarm needed.
#[cfg(test)]
mod tests;

/// Errors from fetching unbound symbols from holders.
///
/// `pub(crate)` because only callers inside this crate ever observe a
/// `FetchError` — `fetch_unbound_symbols` itself consumes `Swarm` internally
/// (logs WARN, skips holder) and only ever surfaces `InsufficientSymbols` to its
/// caller. `Swarm` exists to carry information *between*
/// `fetch_symbols_from_holder` and the loop in `fetch_unbound_symbols`; it is not
/// part of the public API surface.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FetchError {
    #[error("insufficient symbols: collected {got}, need {need} for block {block}")]
    InsufficientSymbols {
        block: SourceBlockId,
        got: usize,
        need: usize,
    },

    #[error("swarm error: {0}")]
    Swarm(String),
}

/// Fetch unbound symbols for a source block from Alive holders over libp2p.
///
/// - Iterates holders sequentially, collecting up to `k_eff` *distinct-ESI*
///   unbound symbols.
/// - Swarm errors per holder are logged WARN and skipped.
/// - Returns `InsufficientSymbols` if total collected < `k_eff`.
///
/// Input validation (CS-DR-2 / CS-DR-5): symbols arrive over the wire from a
/// holder that may be malformed or Byzantine. Before a received symbol is
/// accepted it must pass three boundary checks, all attributable to the holder:
///   1. **Form (CS-DR-2):** `esi < 2^24` and `data.len() == params.t`. A symbol
///      that fails either would otherwise panic inside `RaptorQEncoder::decode`
///      (`PayloadId::new` assert / decoder slice copy). Invalid → skip + WARN.
///   2. **Membership (CS-DR-5):** the symbol's `esi` must be one this holder was
///      actually asked for. A holder cannot smuggle ESIs it was never assigned.
///   3. **Dedup + cap (CS-DR-5):** each ESI is counted once globally, and no more
///      symbols are accepted from one holder than were requested from it. This
///      keeps a single Byzantine holder (early in placement order, returning
///      `k_eff` dupes/junk for ESIs it was never assigned) from filling the quota
///      and starving honest holders.
///
/// Scope: this closes the *flood / dupe / unrequested-ESI* starvation vector
/// (threshold back to ≥1 honest holder reachable). It does NOT close the residual
/// SM-6 case — a holder returning *well-formed* symbols for its *own* assigned ESIs
/// that are silently wrong (AEAD/decode catches it only after the fact, and an
/// erasure decode failure is not attributable to a specific holder). That bound is
/// still 1 and is tracked separately as SM-6 (per-symbol content attribution).
pub(crate) async fn fetch_unbound_symbols(
    swarm: &Arc<SwarmHandle>,
    encoder: &Arc<dyn ErasureEncoder>,
    block_id: &SourceBlockId,
    placements: &[SymbolPlacement],
    params: &ErasureParams,
) -> Result<Vec<Symbol>, FetchError> {
    let k_eff = params.k_eff as usize;
    let symbol_len = params.t as usize;
    let mut unbound_symbols: Vec<Symbol> = Vec::new();
    // Every ESI we have already accepted, so a later (or the same) holder cannot
    // pad our quota with duplicates. Progress toward k_eff is measured by the
    // size of this set, never by raw symbol count.
    let mut accepted_esis: HashSet<u32> = HashSet::new();

    for placement in placements {
        if !matches!(
            placement.status,
            PlacementStatus::Alive | PlacementStatus::Uncertain | PlacementStatus::PresumedLost
        ) {
            continue;
        }
        if accepted_esis.len() >= k_eff {
            break;
        }

        let still_needed = k_eff - accepted_esis.len();
        // Exclude ESIs we already hold so an overlap across holders (e.g. after a
        // repair re-placement) doesn't make us request ESIs we'd only discard,
        // under-collecting from a holder that had other useful ESIs. No-op under
        // the current disjoint-ranges invariant.
        let wanted_esis: Vec<u32> = ranges_to_esi_list(&placement.esi_ranges)
            .into_iter()
            .filter(|e| !accepted_esis.contains(e))
            .take(still_needed)
            .collect();

        if wanted_esis.is_empty() {
            continue;
        }

        // The set of ESIs this holder is allowed to answer with, and the cap on
        // how many symbols we will accept from it (CS-DR-5).
        let wanted_set: HashSet<u32> = wanted_esis.iter().copied().collect();
        let holder_cap = wanted_esis.len();

        let request = RestoreRequestMsg {
            v: 1,
            source_block_id: *block_id,
            esi_list: wanted_esis,
            timestamp: Timestamp::now(),
        };

        match fetch_symbols_from_holder(swarm, &placement.holder_id, request).await {
            Ok(symbols) => {
                debug!(
                    holder = %placement.holder_id,
                    block = %block_id,
                    count = symbols.len(),
                    "fetch: received bound symbols from holder"
                );
                accept_holder_symbols(
                    encoder,
                    block_id,
                    &placement.holder_id,
                    symbols,
                    &wanted_set,
                    holder_cap,
                    symbol_len,
                    k_eff,
                    &mut accepted_esis,
                    &mut unbound_symbols,
                );
            }
            Err(e) => {
                warn!(
                    holder = %placement.holder_id,
                    block = %block_id,
                    err = %e,
                    "fetch: holder failed, skipping"
                );
            }
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
/// `accepted_esis`. Pure (no network) so it can be unit-tested directly.
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
) {
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
}

/// Contact one holder, send a RestoreRequest, receive a RestoreResponse via libp2p.
///
/// Returns the raw bound symbols (caller unbinds).
async fn fetch_symbols_from_holder(
    swarm: &Arc<SwarmHandle>,
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
