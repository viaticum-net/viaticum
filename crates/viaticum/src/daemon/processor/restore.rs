// Restore handler (holder role): serve the owner's own symbols while we hold them.
//
// v1 has no restore gate (restore-i6, 4R W14): a holder never refuses the legitimate owner
// because of how long it has stored for them. The holding is looked up by the pair
// (block, requester master), so a foreign master gets an empty response (restore-i7).

use tracing::{debug, info, warn};
use viaticum_core::erasure::Symbol;
use viaticum_core::messages::{RestoreRequestMsg, RestoreResponseMsg};
use viaticum_core::types::{HoldingStatus, IdentityPub, Timestamp, hex_encode};

use super::{Processor, ProcessorError, ranges_to_esi_list};

impl Processor {
    /// Load held symbols for owner and return a RestoreResponseMsg.
    ///
    /// Inner method for testability — does not touch the network connection.
    pub(crate) async fn handle_restore_request_inner(
        &self,
        owner_id: IdentityPub,
        request: RestoreRequestMsg,
    ) -> Result<RestoreResponseMsg, ProcessorError> {
        let block_id = request.source_block_id;

        // Check HoldingRecord. restore-i16: everything we hold for the owner is served except
        // what the owner itself asked us to delete. The match is exhaustive on purpose: a new
        // holding status must decide here, it must not silently turn restore into "empty".
        let empty = || RestoreResponseMsg {
            v: 1,
            source_block_id: block_id,
            symbols: vec![],
            timestamp: Timestamp::now(),
        };
        let Some(holding) = self.db.get_holding(&block_id, &owner_id)? else {
            // Not held for this master (or a foreign master): empty response, not an error.
            info!(
                block_id = %block_id,
                requester = %hex_encode(&owner_id.0),
                "processor: RestoreRequest — no active holding for requester, empty response"
            );
            return Ok(empty());
        };
        match holding.status {
            HoldingStatus::Active | HoldingStatus::Silent => {}
            HoldingStatus::MarkedForDelete => {
                info!(
                    block_id = %block_id,
                    requester = %hex_encode(&owner_id.0),
                    "processor: RestoreRequest — holding marked for delete by the owner, empty response"
                );
                return Ok(empty());
            }
        }

        // Determine which ESIs to send.
        let held_esis = ranges_to_esi_list(&holding.esi_ranges);
        let esis_to_send: Vec<u32> = if request.esi_list.is_empty() {
            held_esis
        } else {
            let held_set: std::collections::HashSet<u32> = held_esis.into_iter().collect();
            request
                .esi_list
                .into_iter()
                .filter(|esi| held_set.contains(esi))
                .collect()
        };

        // Load symbol files from disk.
        let block_hex = hex_encode(&block_id.0);
        let block_dir = self.holdings_dir.join(&block_hex);
        let mut symbols: Vec<Symbol> = Vec::with_capacity(esis_to_send.len());

        for esi in esis_to_send {
            let sym_path = block_dir.join(format!("{esi}.bin"));
            match tokio::fs::read(&sym_path).await {
                Ok(data) => {
                    symbols.push(Symbol { esi, data });
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!(
                        block_id = %block_id,
                        esi,
                        "processor: RestoreRequest — symbol file missing on disk, skipping"
                    );
                }
                Err(e) => return Err(ProcessorError::Io(e)),
            }
        }

        if symbols.is_empty() {
            warn!(
                block_id = %block_id,
                owner = %owner_id,
                "processor: RestoreRequest — HoldingRecord exists but no symbol files found on disk"
            );
        } else {
            info!(
                block_id = %block_id,
                owner = %owner_id,
                symbols = symbols.len(),
                "processor: sending RestoreResponse"
            );
        }

        // Accounting only (v1): nothing gates restore on it; input for a future
        // escrow-as-debt (tech-debt [OPEN-NETWORK]).
        let bytes_served: u64 = symbols.iter().map(|s| s.data.len() as u64).sum();
        if bytes_served > 0
            && let Err(e) = self.db.record_restore_served(&owner_id, bytes_served)
        {
            // Non-fatal: the counter is informational.
            warn!(owner = %owner_id, err = %e, "processor: failed to record restore_served");
        }

        Ok(RestoreResponseMsg {
            v: 1,
            source_block_id: block_id,
            symbols,
            timestamp: Timestamp::now(),
        })
    }
}
