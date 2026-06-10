// Restore handlers: serve symbols to owner (holder role), log denial (owner role).

use tracing::{debug, info, warn};
use viaticum_core::constants::{BYTES_PER_GB, SYMBOL_SIZE};
use viaticum_core::erasure::Symbol;
use viaticum_core::escrow::{RestoreDecision, check_restore};
use viaticum_core::messages::{RestoreDeniedMsg, RestoreRequestMsg, RestoreResponseMsg};
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

        // Check HoldingRecord.
        let holding = self.db.get_holding(&block_id, &owner_id)?;
        let holding = match holding {
            Some(h) if h.status == HoldingStatus::Active => h,
            _ => {
                // Not held or not active: return empty response (not a protocol error).
                return Ok(RestoreResponseMsg {
                    v: 1,
                    source_block_id: block_id,
                    symbols: vec![],
                    timestamp: Timestamp::now(),
                });
            }
        };

        // Escrow check: verify owner has earned enough restore budget through storage contribution.
        let k_factor = self.escrow_cfg.k_factor;
        let stored_gb_days =
            self.db
                .stored_for_peer_gb_days(&owner_id, Timestamp::now(), self.time_scale)?;
        let already_restored_bytes = self.db.restored_total_bytes(&owner_id)?;
        let already_restored_gb = already_restored_bytes as f64 / BYTES_PER_GB;
        let this_request_gb = holding
            .esi_ranges
            .iter()
            .map(|&(_start, count)| count as f64 * SYMBOL_SIZE as f64)
            .sum::<f64>()
            / BYTES_PER_GB;
        if let RestoreDecision::Denied(denial) = check_restore(
            stored_gb_days,
            already_restored_gb,
            this_request_gb,
            k_factor,
        ) {
            warn!(
                owner = %owner_id,
                block_id = %block_id,
                stored_gb_days,
                already_restored_gb,
                this_request_gb,
                budget = denial.restore_budget_gb,
                "processor: RestoreRequest denied by escrow check"
            );
            return Err(ProcessorError::EscrowDenied { block_id, denial });
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

        // Increment restore-served counter for this owner after successful symbol load.
        let bytes_served: u64 = symbols.iter().map(|s| s.data.len() as u64).sum();
        if bytes_served > 0
            && let Err(e) = self.db.record_restore_served(&owner_id, bytes_served)
        {
            // Non-fatal: log and continue. Worst case: budget is slightly over-estimated next time.
            warn!(owner = %owner_id, err = %e, "processor: failed to record restore_served");
        }

        Ok(RestoreResponseMsg {
            v: 1,
            source_block_id: block_id,
            symbols,
            timestamp: Timestamp::now(),
        })
    }

    /// Holder denied our restore request. Log warning.
    pub(crate) async fn handle_restore_denied(
        &self,
        holder_id: IdentityPub,
        denied: RestoreDeniedMsg,
    ) -> Result<(), ProcessorError> {
        warn!(
            holder = %holder_id,
            block_id = %denied.source_block_id,
            current_trust = denied.current_trust,
            needed_trust = denied.needed_trust,
            restore_budget_gb = denied.restore_budget_gb,
            "processor: RestoreDenied received"
        );
        Ok(())
    }
}
