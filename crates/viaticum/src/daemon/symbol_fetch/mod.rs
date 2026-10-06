// Shared helper for fetching unbound erasure symbols from holders over libp2p.
//
// Used by:
//   - `restore`: normal restore flow (with the daemon's cancel token), through a
//     `RestoreSource` (`SwarmSymbols`: requests + redial of holders).
//   - `dr`:      the SystemState block during disaster recovery (no cancel), through
//     the bare `SwarmHandle` (a `SymbolSource`: requests only).
//
// restore-i12: a slow home link is not "holders unavailable". Each request asks one
// holder for at most `RESTORE_FETCH_CHUNK_BYTES` of symbols; there is no deadline on
// a block. The fetch goes in rounds over the holders (`rounds::BlockFetch`) and gives
// up only after a full round that accepted no new ESI. A holder whose request fails
// (the 30 s request timeout, a dial failure) is skipped for the rest of the round and
// asked again in the next one. A round with nothing new where some holder did not
// answer is a separate outcome (`RoundEnd::NoAnswer`, restore-i33): restore retries
// it after a redial and a pause (restore-i26); `fetch_unbound_symbols` (DR) stops there as
// before.
//
// There is no restore gate on the holder (restore-i6): a holder either serves the
// owner's symbols or answers empty (no active holding for this owner).

use std::collections::HashSet;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use viaticum_core::db::Db;
use viaticum_core::erasure::{ErasureEncoder, Symbol};
use viaticum_core::messages::{Message, RestoreRequestMsg};
use viaticum_core::types::{DeviceId, ErasureParams, SourceBlockId, SymbolPlacement};

use crate::daemon::network::swarm::{SwarmError, SwarmHandle};

mod rounds;

pub(crate) use rounds::{BlockFetch, FailedInTask, Round, RoundEnd};

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

    /// The holder did not answer the request in time (restore-i44: only this puts a
    /// holder last for the rest of the task; a dropped connection is `Swarm`).
    #[error("holder did not answer in time")]
    Timeout,

    /// The daemon is stopping; the fetch was abandoned.
    #[error("fetch cancelled: the daemon is stopping")]
    Cancelled,
}

/// One `RestoreRequest` to one holder. The bare `SwarmHandle` (DR); tests use
/// scripted fakes.
#[async_trait::async_trait]
pub trait SymbolSource: Send + Sync {
    /// Ask `holder` for the ESIs in `req`; returns the bound symbols it sent.
    async fn request(
        &self,
        holder: DeviceId,
        req: RestoreRequestMsg,
    ) -> Result<Vec<Symbol>, FetchError>;

    /// Devices we have a live authenticated connection to right now — asked first
    /// in a round (restore-i43). A snapshot; empty when it cannot be taken.
    async fn connected_holders(&self) -> HashSet<DeviceId>;
}

/// What restore needs on top of requests: a redial of holders that did not answer
/// before a retry (restore-i26). `SwarmSymbols` in the daemon; tests use fakes.
#[async_trait::async_trait]
pub trait RestoreSource: SymbolSource {
    /// Try to (re)connect to `holders`. Only starts the dials; failures are
    /// logged, never returned (the retry itself tells).
    async fn reconnect(&self, holders: &[DeviceId]);
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

    async fn connected_holders(&self) -> HashSet<DeviceId> {
        authenticated_devices(self).await
    }
}

/// The daemon's symbol source for restore: requests over the swarm, redial of
/// holders from their stored addresses (the auto-dial mechanism, network-i2).
pub struct SwarmSymbols {
    swarm: Arc<SwarmHandle>,
    db: Db,
}

impl SwarmSymbols {
    pub fn new(swarm: Arc<SwarmHandle>, db: Db) -> Self {
        SwarmSymbols { swarm, db }
    }
}

#[async_trait::async_trait]
impl SymbolSource for SwarmSymbols {
    async fn request(
        &self,
        holder: DeviceId,
        req: RestoreRequestMsg,
    ) -> Result<Vec<Symbol>, FetchError> {
        fetch_symbols_from_holder(&self.swarm, &holder, req).await
    }

    async fn connected_holders(&self) -> HashSet<DeviceId> {
        authenticated_devices(&self.swarm).await
    }
}

/// The swarm's authenticated devices (a live connection with the certificate
/// exchange done). A failed snapshot is no order hint, not an error: empty.
async fn authenticated_devices(swarm: &SwarmHandle) -> HashSet<DeviceId> {
    match swarm.peer_sets().await {
        Ok((authenticated, _connected)) => authenticated,
        Err(e) => {
            warn!(err = %e, "fetch: no snapshot of connected holders; holders asked in shuffled order only");
            HashSet::new()
        }
    }
}

#[async_trait::async_trait]
impl RestoreSource for SwarmSymbols {
    async fn reconnect(&self, holders: &[DeviceId]) {
        match crate::daemon::handle::redial::redial_devices(&self.db, &self.swarm, holders).await {
            Ok(stats) => info!(
                holders = holders.len(),
                dialed = stats.dialed,
                already_connected = stats.already_connected,
                no_addrs = stats.no_addrs,
                "fetch: redialed holders before a retry"
            ),
            Err(e) => warn!(err = %e, "fetch: redial of holders failed"),
        }
    }
}

/// ESIs per request for symbol size `t`: `max(1, chunk_bytes / t)`.
pub(crate) fn chunk_esis(chunk_bytes: u64, t: u16) -> usize {
    (chunk_bytes / u64::from(t.max(1))).max(1) as usize
}

/// Collect `k_eff` distinct unbound symbols for `block_id` (restore-i12).
///
/// Rounds over the candidate placements (Alive | Uncertain | PresumedLost): the holders
/// that timed out earlier in `task` last (restore-i44), connected holders first, each group
/// in a per-block shuffled order (restore-i43). Within a
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
    task: &FailedInTask,
) -> Result<Vec<Symbol>, FetchError> {
    let chunk = chunk_esis(RESTORE_FETCH_CHUNK_BYTES, params.t);
    let fetch = BlockFetch::new(encoder, block_id, placements, params, chunk).in_task(task);
    rounds_until_no_progress(fetch, source, cancel).await
}

/// `fetch_unbound_symbols` with the chunk size given (seam for tests).
///
/// Stops at the first round that accepted nothing, whatever the reason: a round
/// nobody answered is not retried here (DR; restore retries it with a pause,
/// restore-i26).
#[cfg(test)]
pub(crate) async fn fetch_in_rounds(
    source: &dyn SymbolSource,
    encoder: &Arc<dyn ErasureEncoder>,
    block_id: &SourceBlockId,
    placements: &[SymbolPlacement],
    params: &ErasureParams,
    cancel: Option<&CancellationToken>,
    chunk: usize,
) -> Result<Vec<Symbol>, FetchError> {
    let fetch = BlockFetch::new(encoder, block_id, placements, params, chunk);
    rounds_until_no_progress(fetch, source, cancel).await
}

async fn rounds_until_no_progress(
    mut fetch: BlockFetch<'_>,
    source: &dyn SymbolSource,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<Symbol>, FetchError> {
    while fetch.round(source, cancel).await?.end == RoundEnd::Progress {}
    fetch.finish()
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
        .map_err(|e| match e {
            SwarmError::Timeout => FetchError::Timeout,
            e => FetchError::Swarm(e.to_string()),
        })?;

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
