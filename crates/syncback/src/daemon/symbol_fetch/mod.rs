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
// Escrow enforcement (D1): holder may reply with `RestoreDenied`; we propagate
// that as `EscrowDenied` — caller decides whether to continue with remaining
// holders (current logic: skip denied holder, try next).

use std::sync::Arc;

use syncback_core::erasure::{ErasureEncoder, Symbol};
use syncback_core::messages::{Message, RestoreRequestMsg};
use syncback_core::types::{
    ranges_to_esi_list, DeviceId, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
};
use tracing::{debug, warn};

use crate::daemon::network::swarm::SwarmHandle;

// No unit tests here: fetch_unbound_symbols requires a live SwarmHandle (libp2p
// swarm), which is covered end-to-end via restore/tests.rs integration tests and
// local_e2e_test.sh. Keeping the helper thin avoids duplicating that coverage.

/// Errors from fetching unbound symbols from holders.
///
/// `pub(crate)` because only callers inside this crate ever observe a
/// `FetchError` — `fetch_unbound_symbols` itself consumes `EscrowDenied` and
/// `Swarm` internally (logs WARN, skips holder) and only ever surfaces
/// `InsufficientSymbols` to its caller. The private variants exist to carry
/// information *between* `fetch_symbols_from_holder` and the loop in
/// `fetch_unbound_symbols`; they are not part of the public API surface.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FetchError {
    #[error("insufficient symbols: collected {got}, need {need} for block {block}")]
    InsufficientSymbols {
        block: SourceBlockId,
        got: usize,
        need: usize,
    },

    /// Holder answered with `RestoreDenied` (escrow not satisfied).
    /// Note: the message does not carry the requested size, only the holder's
    /// budget/trust view — so we don't expose a bogus `restore_gb` here.
    #[error(
        "restore denied by holder {holder}: trust {current_trust:.2}, \
         budget {restore_budget_gb:.1} GB"
    )]
    EscrowDenied {
        holder: DeviceId,
        current_trust: f64,
        needed_trust: f64,
        restore_budget_gb: f64,
    },

    #[error("swarm error: {0}")]
    Swarm(String),
}

/// Fetch unbound symbols for a source block from Alive holders over libp2p.
///
/// - Iterates holders sequentially, collecting up to `k_eff` unbound symbols.
/// - `EscrowDenied` and swarm errors per holder are logged WARN and skipped.
/// - Returns `InsufficientSymbols` if total collected < `k_eff`.
pub(crate) async fn fetch_unbound_symbols(
    swarm: &Arc<SwarmHandle>,
    encoder: &Arc<dyn ErasureEncoder>,
    block_id: &SourceBlockId,
    placements: &[SymbolPlacement],
    k_eff: usize,
) -> Result<Vec<Symbol>, FetchError> {
    let mut unbound_symbols: Vec<Symbol> = Vec::new();

    for placement in placements {
        if placement.status != PlacementStatus::Alive {
            continue;
        }
        if unbound_symbols.len() >= k_eff {
            break;
        }

        let still_needed = k_eff - unbound_symbols.len();
        let wanted_esis: Vec<u32> = ranges_to_esi_list(&placement.esi_ranges)
            .into_iter()
            .take(still_needed)
            .collect();

        if wanted_esis.is_empty() {
            continue;
        }

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
                for sym in symbols {
                    let unbound = encoder.unbind(sym, block_id, &placement.holder_id);
                    unbound_symbols.push(unbound);
                }
            }
            Err(FetchError::EscrowDenied { ref holder, .. }) => {
                warn!(
                    holder = %holder,
                    block = %block_id,
                    "fetch: holder denied restore (escrow), skipping"
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

    if unbound_symbols.len() < k_eff {
        Err(FetchError::InsufficientSymbols {
            block: *block_id,
            got: unbound_symbols.len(),
            need: k_eff,
        })
    } else {
        Ok(unbound_symbols)
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
        Message::RestoreDenied(denied) => Err(FetchError::EscrowDenied {
            holder: *holder_device,
            current_trust: denied.current_trust,
            needed_trust: denied.needed_trust,
            restore_budget_gb: denied.restore_budget_gb,
        }),
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
