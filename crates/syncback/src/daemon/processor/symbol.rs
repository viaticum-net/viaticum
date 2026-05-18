// Symbol handlers: offer/transfer (holder), dropped/drop_notice (owner), delete/cancel_delete (holder).

use syncback_core::constants::{HANDSHAKE_FRESHNESS_SECS, SYMBOL_OFFER_EXPIRY_SECS, SYMBOL_SIZE};
use syncback_core::messages::{
    verify_symbol_offer, CancelDeleteMsg, DeleteMsg, RejectReason, SymbolAcceptMsg,
    SymbolDropNoticeMsg, SymbolDroppedMsg, SymbolOfferMsg, SymbolRejectMsg, SymbolTransferMsg,
};
use syncback_core::types::{
    hex_encode, DeviceId, HoldingRecord, HoldingStatus, IdentityPub, Timestamp,
};
use tracing::{debug, error, info, warn};

use crate::daemon::repair::RepairTrigger;

use super::{
    AcceptedOffer, ProcessorError, Processor,
    esi_list_to_ranges, ranges_to_esi_list,
};

impl Processor {
    /// Store received symbols on disk and record a HoldingRecord in the DB.
    ///
    /// File layout: `{holdings_dir}/{block_id_hex}/{esi}.bin`
    ///
    /// Requires a prior accepted offer in `accepted_offers` for `(owner_id, block_id)`.
    /// If no offer is found: silently rejects (does not store anything).
    /// If the offer is expired: removes and silently rejects.
    /// If any ESI is outside the accepted ranges: rejects (offer consumed).
    pub(crate) async fn handle_symbol_transfer(
        &self,
        owner_id: IdentityPub,
        transfer: SymbolTransferMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = transfer.source_block_id;

        // ── Offer lookup + validation ─────────────────────────────────────────
        // The offer entry persists across multiple SymbolTransfer messages for
        // the same placement: owners chunk large deliveries into several frames
        // because a single message cannot exceed MAX_MESSAGE_SIZE. We subtract
        // the received ESIs from the remaining ranges on each transfer and drop
        // the offer only when all expected ESIs have arrived or the expiry fires.
        let (importance, accepted_esi_ranges) = {
            let map = self.accepted_offers.lock().unwrap();
            let key = (owner_id, block_id);
            match map.get(&key) {
                None => {
                    warn!(
                        block_id = %block_id,
                        owner = %owner_id,
                        "processor: SymbolTransfer rejected — no accepted offer"
                    );
                    return Ok(());
                }
                Some(entry) => {
                    let now = Timestamp::now().0;
                    let age = now.saturating_sub(entry.accepted_at.0);
                    if age > SYMBOL_OFFER_EXPIRY_SECS {
                        debug!(
                            block_id = %block_id,
                            owner = %owner_id,
                            age_secs = age,
                            "processor: accepted offer expired — rejecting SymbolTransfer"
                        );
                        drop(map);
                        self.accepted_offers.lock().unwrap().remove(&key);
                        return Ok(());
                    }
                    (entry.importance, entry.esi_ranges.clone())
                }
            }
        };

        // ── ESI range validation ──────────────────────────────────────────────
        // A sender that attempts to store an ESI outside the accepted ranges is
        // treated as misbehaving: we reject the whole transfer and drop the offer.
        for symbol in &transfer.symbols {
            let esi = symbol.esi;
            let in_range = accepted_esi_ranges
                .iter()
                .any(|&(start, count)| esi >= start && esi < start + count);
            if !in_range {
                warn!(
                    block_id = %block_id,
                    owner = %owner_id,
                    esi,
                    "processor: SymbolTransfer rejected — ESI out of accepted range"
                );
                self.accepted_offers.lock().unwrap().remove(&(owner_id, block_id));
                return Ok(());
            }
        }

        // ── Write symbols to disk ─────────────────────────────────────────────
        let block_hex = hex_encode(&block_id.0);
        let block_dir = self.holdings_dir.join(&block_hex);

        tokio::fs::create_dir_all(&block_dir).await?;

        let mut received_esis: Vec<u32> = Vec::with_capacity(transfer.symbols.len());
        let mut total_bytes: u64 = 0;

        for symbol in &transfer.symbols {
            // Reject oversized symbols: expected size is SYMBOL_SIZE (65535 bytes).
            // Without this check, a malicious peer could write up to MAX_MESSAGE_SIZE
            // per symbol, bypassing quota accounting.
            if symbol.data.len() > SYMBOL_SIZE as usize {
                warn!(
                    block_id = %block_id,
                    owner = %owner_id,
                    esi = symbol.esi,
                    size = symbol.data.len(),
                    expected = SYMBOL_SIZE,
                    "processor: SymbolTransfer rejected — oversized symbol"
                );
                self.accepted_offers.lock().unwrap().remove(&(owner_id, block_id));
                return Ok(());
            }
            let sym_path = block_dir.join(format!("{}.bin", symbol.esi));
            tokio::fs::write(&sym_path, &symbol.data).await?;
            received_esis.push(symbol.esi);
            total_bytes += symbol.data.len() as u64;
        }

        if received_esis.is_empty() {
            debug!(
                block_id = %block_id,
                owner = %owner_id,
                "processor: SymbolTransfer with no symbols, ignored"
            );
            return Ok(());
        }

        received_esis.sort_unstable();
        let new_ranges = esi_list_to_ranges(&received_esis);

        // Merge with existing HoldingRecord if any.
        let record = match self.db.get_holding(&block_id, &owner_id)? {
            Some(mut existing) => {
                let mut all_esis = ranges_to_esi_list(&existing.esi_ranges);
                let mut new_bytes: u64 = 0;
                for symbol in &transfer.symbols {
                    if !all_esis.contains(&symbol.esi) {
                        new_bytes += symbol.data.len() as u64;
                        all_esis.push(symbol.esi);
                    }
                }
                all_esis.sort_unstable();
                existing.esi_ranges = esi_list_to_ranges(&all_esis);
                existing.total_bytes += new_bytes;
                existing.status = HoldingStatus::Active;
                // importance: keep existing value (BR-7). New offer may have different
                // importance, but the holding was already accepted at its original importance.
                existing
            }
            None => HoldingRecord {
                source_block_id: block_id,
                owner_id,
                esi_ranges: new_ranges,
                // importance comes from the validated AcceptedOffer (verified by handle_symbol_offer).
                importance,
                total_bytes,
                status: HoldingStatus::Active,
                received_at: Timestamp::now(),
                delete_requested_at: None,
                drop_notice_sent_at: None,
            },
        };

        self.db.upsert_holding(&record)?;

        // Subtract received ESIs from the offer's remaining ranges. The offer
        // is dropped when fully covered; otherwise we keep it so a follow-up
        // chunk for the same placement can still find and validate against it.
        {
            let mut map = self.accepted_offers.lock().unwrap();
            let key = (owner_id, block_id);
            if let Some(entry) = map.get_mut(&key) {
                let mut remaining = ranges_to_esi_list(&entry.esi_ranges);
                remaining.retain(|e| !received_esis.contains(e));
                if remaining.is_empty() {
                    map.remove(&key);
                } else {
                    remaining.sort_unstable();
                    entry.esi_ranges = esi_list_to_ranges(&remaining);
                }
            }
        }

        // Refresh trust_s for all devices of this peer's master identity.
        for did in self.db.get_devices_for_master(&owner_id).unwrap_or_default() {
            if let Err(e) = self.db.refresh_peer_storage_bytes(&did) {
                error!(
                    peer = %owner_id,
                    device = %did,
                    err = %e,
                    "processor: failed to refresh storage balance after SymbolTransfer"
                );
            }
        }

        info!(
            block_id = %block_id,
            owner = %owner_id,
            symbols = transfer.symbols.len(),
            "processor: stored symbols for block"
        );

        // In the libp2p path an Ack is sent via ResponseChannel in dispatch_libp2p.
        // The BackupCoordinator (sender side) handles the lack of ack gracefully.

        Ok(())
    }

    /// Decide whether to accept or reject a SymbolOffer based on disk quota.
    ///
    /// Returns `true` = accept, `false` = reject.
    /// This is a sync helper used by `handle_symbol_offer` and tests.
    pub(crate) fn decide_symbol_offer(
        &self,
        offer_bytes: u64,
    ) -> Result<bool, ProcessorError> {
        let held_bytes = self.db.total_holding_bytes()?;

        // Hard quota: absolute ceiling — always reject above this.
        if self.hard_quota_bytes > 0 && held_bytes >= self.hard_quota_bytes {
            return Ok(false);
        }

        // Effective soft quota: min(config_soft_quota, disk_free - reserve).
        // When soft_quota=0, uses all available disk minus reserve.
        let disk_free = crate::daemon::handle::disk_available_bytes(&self.data_dir);
        let effective = syncback_core::budget::compute_effective_quota(
            self.soft_quota_bytes,
            disk_free,
            self.disk_reserve_bytes,
        );
        if held_bytes + offer_bytes > effective {
            return Ok(false);
        }
        Ok(true)
    }

    /// Receive a SymbolOffer, decide Accept or Reject, return the reply Message.
    ///
    /// Does NOT create a HoldingRecord — that happens in handle_symbol_transfer
    /// when symbols actually arrive.
    ///
    /// Security checks (in order):
    ///   1. Freshness: |now - timestamp| <= HANDSHAKE_FRESHNESS_SECS
    ///   2. Signature: verify_symbol_offer against owner_id (master identity from handshake)
    ///   3. Quota: decide_symbol_offer
    ///
    /// Called from dispatch_libp2p; reply is sent via ResponseChannel by caller.
    pub(crate) fn handle_symbol_offer_inner(
        &self,
        owner_id: IdentityPub,
        offer: SymbolOfferMsg,
    ) -> syncback_core::messages::Message {
        use syncback_core::messages::{Message, SymbolAcceptMsg};

        let now = Timestamp::now().0;
        let ts = offer.timestamp.0;
        let delta = now.abs_diff(ts);
        if delta > HANDSHAKE_FRESHNESS_SECS {
            warn!(
                owner = %owner_id,
                block_id = %offer.source_block_id,
                delta_secs = delta,
                "processor: SymbolOffer rejected — stale timestamp"
            );
            return Message::SymbolReject(SymbolRejectMsg {
                v: 1,
                source_block_id: offer.source_block_id,
                offer_msg_id: offer.msg_id,
                reason: RejectReason::Other,
                timestamp: Timestamp::now(),
            });
        }

        if let Err(e) = verify_symbol_offer(&offer, &owner_id) {
            warn!(
                owner = %owner_id,
                block_id = %offer.source_block_id,
                err = %e,
                "processor: SymbolOffer rejected — sig verification failed"
            );
            return Message::SymbolReject(SymbolRejectMsg {
                v: 1,
                source_block_id: offer.source_block_id,
                offer_msg_id: offer.msg_id,
                reason: RejectReason::Other,
                timestamp: Timestamp::now(),
            });
        }

        let offer_bytes: u64 = offer
            .esi_ranges
            .iter()
            .map(|&(_start, count)| count as u64 * SYMBOL_SIZE as u64)
            .sum();

        let accept = match self.decide_symbol_offer(offer_bytes) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    owner = %owner_id,
                    block_id = %offer.source_block_id,
                    err = %e,
                    "processor: SymbolOffer — quota check failed"
                );
                return Message::SymbolReject(SymbolRejectMsg {
                    v: 1,
                    source_block_id: offer.source_block_id,
                    offer_msg_id: offer.msg_id,
                    reason: RejectReason::QuotaFull,
                    timestamp: Timestamp::now(),
                });
            }
        };

        if accept {
            info!(
                owner = %owner_id,
                block_id = %offer.source_block_id,
                offer_bytes,
                "processor: SymbolOffer accepted"
            );
            // Store accepted offer so handle_symbol_transfer can validate the transfer.
            {
                let accepted_offer = AcceptedOffer {
                    owner_id,
                    source_block_id: offer.source_block_id,
                    esi_ranges: offer.esi_ranges.clone(),
                    importance: offer.importance,
                    accepted_at: Timestamp::now(),
                };
                let key = (owner_id, offer.source_block_id);
                let mut map = self.accepted_offers.lock().unwrap();
                map.insert(key, accepted_offer);
            }
            Message::SymbolAccept(SymbolAcceptMsg {
                v: 1,
                source_block_id: offer.source_block_id,
                offer_msg_id: offer.msg_id,
                timestamp: Timestamp::now(),
            })
        } else {
            debug!(
                owner = %owner_id,
                block_id = %offer.source_block_id,
                offer_bytes,
                "processor: SymbolOffer rejected (quota full)"
            );
            Message::SymbolReject(SymbolRejectMsg {
                v: 1,
                source_block_id: offer.source_block_id,
                offer_msg_id: offer.msg_id,
                reason: RejectReason::QuotaFull,
                timestamp: Timestamp::now(),
            })
        }
    }

    /// Holder accepted our symbol offer. Notify BackupCoordinator and signal pending delivery.
    pub(crate) async fn handle_symbol_accept(
        &self,
        from_master: IdentityPub,
        accept: SymbolAcceptMsg,
    ) -> Result<(), ProcessorError> {
        info!(
            holder = %from_master,
            block_id = %accept.source_block_id,
            "processor: SymbolAccept received"
        );
        // BackupEvent now uses DeviceId — resolve from master.
        let holder_device = self.db.get_devices_for_master(&from_master)
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or(DeviceId(from_master.0));
        let _ = self.backup_event_tx.send(
            crate::daemon::backup::BackupEvent::SymbolAccepted {
                holder_id: holder_device,
                source_block_id: accept.source_block_id,
            },
        ).await;
        Ok(())
    }

    /// Holder rejected our symbol offer. Notify BackupCoordinator and signal pending delivery.
    pub(crate) async fn handle_symbol_reject(
        &self,
        from_master: IdentityPub,
        reject: SymbolRejectMsg,
    ) -> Result<(), ProcessorError> {
        warn!(
            holder = %from_master,
            block_id = %reject.source_block_id,
            reason = ?reject.reason,
            "processor: SymbolReject received"
        );
        // BackupEvent now uses DeviceId — resolve from master.
        let holder_device = self.db.get_devices_for_master(&from_master)
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or(DeviceId(from_master.0));
        let _ = self.backup_event_tx.send(
            crate::daemon::backup::BackupEvent::SymbolRejected {
                holder_id: holder_device,
                source_block_id: reject.source_block_id,
                reason: format!("{:?}", reject.reason),
            },
        ).await;
        Ok(())
    }

    /// Mark a placement Lost (holder evicted the symbols).
    ///
    /// Idempotent: no-op if already Lost or Deleting.
    /// Returns true if the placement was actually modified.
    pub(crate) fn handle_symbol_dropped_sync(
        &self,
        holder_id: DeviceId,
        dropped: &SymbolDroppedMsg,
    ) -> Result<bool, ProcessorError> {
        let block_id = dropped.source_block_id;
        super::mark_placement_lost(&self.db, &block_id, &holder_id)
    }

    pub(crate) async fn handle_symbol_dropped(
        &self,
        from: DeviceId,
        dropped: SymbolDroppedMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = dropped.source_block_id;

        // Verify the per-message signature using the claimant holder's master
        // identity. Without this, any peer knowing the victim's IdentityPub could
        // forge a SymbolDropped and trigger a repair storm (review S2).
        match self.db.get_master_for_device(&from) {
            Ok(Some(master)) => {
                if let Err(e) = syncback_core::messages::verify_symbol_dropped(&dropped, &master) {
                    warn!(
                        device = %from,
                        block_id = %block_id,
                        err = %e,
                        "processor: SymbolDropped signature verification failed — ignoring"
                    );
                    return Ok(());
                }
            }
            Ok(None) => {
                warn!(
                    device = %from,
                    block_id = %block_id,
                    "processor: SymbolDropped from unknown device — ignoring"
                );
                return Ok(());
            }
            Err(e) => {
                error!(
                    device = %from,
                    err = %e,
                    "processor: SymbolDropped — DB lookup failed"
                );
                return Ok(());
            }
        }

        self.handle_symbol_dropped_sync(from, &dropped)?;

        // Refresh trust_s: holder evicted our symbols, bytes_peer_stores_for_us decreased.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&from) {
            error!(
                device = %from,
                err = %e,
                "processor: failed to refresh storage balance after SymbolDropped"
            );
        }

        info!(block_id = %block_id, holder = %from, "repair: triggered");
        let _ = self
            .repair_tx
            .send(RepairTrigger::RepairNow {
                block_id,
                holder_id: from,
            })
            .await;
        Ok(())
    }

    /// Handle advance eviction notice from a holder.
    ///
    /// Transitions the placement to Lost (if not already), recomputes
    /// `current_alive` and `current_reliability` for the block, and writes
    /// the updated cached fields via `update_block_cached_fields`.
    ///
    /// Idempotent: if the placement is already Lost or Deleting,
    /// `mark_placement_lost` returns false and the block update is skipped.
    ///
    /// On unknown block or unknown holder, logs WARN and returns without
    /// panicking — the authoritative repair path is the later SymbolDropped.
    ///
    /// Unlike `handle_symbol_dropped`, this handler does NOT send a
    /// `RepairTrigger::RepairNow`. The block re-enters the worker queue
    /// automatically via `next_work_item` once `current_reliability` drops
    /// below `target_reliability`. Repair latency is bounded by the worker
    /// poll interval — acceptable for cold backup (time constant = 1 week).
    pub(crate) fn handle_symbol_drop_notice(
        &self,
        from: IdentityPub,
        notice: SymbolDropNoticeMsg,
    ) {
        let block_id = notice.source_block_id;
        info!(
            block_id = %block_id,
            holder = %from,
            deadline = notice.deadline.0,
            "processor: received SymbolDropNotice — transitioning placement to Lost"
        );

        // Step 1: Resolve master identity → DeviceId(s). The DropNotice arrives
        // with the holder's master IdentityPub (board session layer, no per-message
        // sig). Iterate all known devices for this master; use the first one that
        // has a placement for this block.
        let devices = self.db.get_devices_for_master(&from).unwrap_or_default();
        if devices.is_empty() {
            warn!(
                block_id = %block_id,
                holder = %from,
                "processor: DropNotice from unknown master — no devices in DB, ignoring"
            );
            return;
        }

        let holder_device_id = devices.iter().find(|did| {
            self.db
                .get_placement(&block_id, did)
                .ok()
                .flatten()
                .is_some()
        });

        let holder_device_id = match holder_device_id {
            Some(id) => *id,
            None => {
                warn!(
                    block_id = %block_id,
                    holder = %from,
                    "processor: DropNotice — no placement found for any device of this master, ignoring"
                );
                return;
            }
        };

        // Step 2: Mark placement Lost (idempotent — returns false if already Lost/Deleting).
        let changed = match super::mark_placement_lost(&self.db, &block_id, &holder_device_id) {
            Ok(c) => c,
            Err(e) => {
                error!(
                    block_id = %block_id,
                    holder = %holder_device_id,
                    err = %e,
                    "processor: DropNotice — mark_placement_lost failed"
                );
                return;
            }
        };

        if !changed {
            // Placement was already Lost or Deleting — idempotent no-op.
            debug!(
                block_id = %block_id,
                holder = %holder_device_id,
                "processor: DropNotice — placement already Lost/Deleting, skipping block update"
            );
            return;
        }

        // Step 3: Look up the block. If absent (pre-Wave-8 or already deleted), log
        // a warning and return — the placement update already happened.
        let block = match self.db.get_source_block(&block_id) {
            Ok(Some(b)) => b,
            Ok(None) => {
                warn!(
                    block_id = %block_id,
                    "processor: DropNotice — source block not found after placement update"
                );
                return;
            }
            Err(e) => {
                error!(
                    block_id = %block_id,
                    err = %e,
                    "processor: DropNotice — get_source_block failed"
                );
                return;
            }
        };

        // Step 4: Recompute current_alive by counting Alive/Uncertain placements.
        // We recount from scratch (Rule 3) rather than decrementing the cached
        // counter — this handles legacy blocks where current_alive == 0 (sentinel)
        // and is resilient to any prior inconsistency (I6).
        let placements = match self.db.list_placements_for_block(&block_id) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    block_id = %block_id,
                    err = %e,
                    "processor: DropNotice — list_placements_for_block failed"
                );
                return;
            }
        };

        let new_current_alive: u32 = placements
            .iter()
            .filter(|p| {
                p.status == syncback_core::types::PlacementStatus::Alive
                    || p.status == syncback_core::types::PlacementStatus::Uncertain
            })
            .count() as u32;

        // Step 5: Recompute current_reliability using per-holder survival probs.
        // Assemble HolderReliabilityInput for each Alive/Uncertain placement.
        // Survival probability is a simplified proxy from peer.trust_p only;
        // the migration module uses a richer commitment (PoS history, etc.).
        // Match unknown-peer fallback (0.5 neutral prior).
        let k_eff = block.erasure_params().k_eff;
        let holder_inputs: Vec<syncback_core::reliability::HolderReliabilityInput> = placements
            .iter()
            .filter(|p| {
                p.status == syncback_core::types::PlacementStatus::Alive
                    || p.status == syncback_core::types::PlacementStatus::Uncertain
            })
            .map(|p| {
                let survival_prob = self
                    .db
                    .get_peer(&p.holder_id)
                    .ok()
                    .flatten()
                    .map(|peer| {
                        syncback_core::reliability::commitment_to_survival_prob(
                            syncback_core::commitment::CommitmentScore::new(peer.trust_p),
                        )
                    })
                    .unwrap_or(0.5); // neutral prior for unknown peers
                syncback_core::reliability::HolderReliabilityInput {
                    holder_id: p.holder_id,
                    alive_symbols: p.symbol_count(),
                    survival_prob,
                }
            })
            .collect();

        let reliability_input = syncback_core::reliability::BlockReliabilityInput {
            block_id,
            k_eff,
            holders: holder_inputs,
        };

        let new_reliability = match syncback_core::reliability::block_reliability(&reliability_input)
        {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    block_id = %block_id,
                    err = %e,
                    "processor: DropNotice — block_reliability failed, using 0.0"
                );
                0.0
            }
        };

        // Step 6: Write updated cached fields back to DB.
        // Preserve importance, target_reliability, last_attempted_at, last_pool_signature.
        if let Err(e) = self.db.update_block_cached_fields(
            &block_id,
            block.importance,
            new_current_alive,
            new_reliability,
            block.target_reliability,
            block.last_attempted_at,
            block.last_pool_signature,
        ) {
            error!(
                block_id = %block_id,
                err = %e,
                "processor: DropNotice — update_block_cached_fields failed"
            );
            return;
        }

        info!(
            block_id = %block_id,
            holder = %holder_device_id,
            new_current_alive,
            new_reliability,
            "processor: DropNotice — block cached fields updated, repair will be scheduled"
        );

        // Step 7: Refresh storage bytes for the holder (consistent with handle_symbol_dropped).
        if let Err(e) = self.db.refresh_peer_storage_bytes(&holder_device_id) {
            error!(
                device = %holder_device_id,
                err = %e,
                "processor: DropNotice — failed to refresh storage balance"
            );
        }
    }

    /// Handle a Delete request from the owner. Verify signature, then mark
    /// the holding as MarkedForDelete so the cleanup task can process it later.
    pub(crate) async fn handle_delete(
        &self,
        from: IdentityPub,
        delete: DeleteMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = delete.source_block_id;

        // Reject stale/replayed messages (same freshness window as handshake).
        let now = Timestamp::now();
        let age = now.0.saturating_sub(delete.timestamp.0);
        if age > syncback_core::constants::HANDSHAKE_FRESHNESS_SECS {
            warn!(
                block_id = %block_id,
                owner = %from,
                age_secs = age,
                "processor: Delete rejected — timestamp too old (possible replay)"
            );
            return Ok(());
        }

        // Verify signature against the sender's identity (the owner).
        if let Err(e) = syncback_core::messages::verify_delete_msg(&delete, &from) {
            warn!(
                block_id = %block_id,
                owner = %from,
                err = %e,
                "processor: Delete signature verification failed"
            );
            return Ok(());
        }

        // Look up the holding — only Active holdings can be marked for deletion.
        match self.db.get_holding(&block_id, &from)? {
            Some(mut holding) => {
                if holding.status == HoldingStatus::Active {
                    holding.status = HoldingStatus::MarkedForDelete;
                    holding.delete_requested_at = Some(Timestamp::now());
                    self.db.upsert_holding(&holding)?;
                    info!(
                        block_id = %block_id,
                        owner = %from,
                        "processor: holding marked for deletion"
                    );
                } else {
                    debug!(
                        block_id = %block_id,
                        owner = %from,
                        status = ?holding.status,
                        "processor: Delete ignored — holding not Active"
                    );
                }
            }
            None => {
                debug!(
                    block_id = %block_id,
                    owner = %from,
                    "processor: Delete ignored — no holding for this block"
                );
            }
        }
        Ok(())
    }

    /// Handle a CancelDelete from the owner. Revert MarkedForDelete → Active.
    pub(crate) async fn handle_cancel_delete(
        &self,
        from: IdentityPub,
        cancel: CancelDeleteMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = cancel.source_block_id;

        // Reject stale/replayed messages.
        let now = Timestamp::now();
        let age = now.0.saturating_sub(cancel.timestamp.0);
        if age > syncback_core::constants::HANDSHAKE_FRESHNESS_SECS {
            warn!(
                block_id = %block_id,
                owner = %from,
                age_secs = age,
                "processor: CancelDelete rejected — timestamp too old (possible replay)"
            );
            return Ok(());
        }

        if let Err(e) = syncback_core::messages::verify_cancel_delete_msg(&cancel, &from) {
            warn!(
                block_id = %block_id,
                owner = %from,
                err = %e,
                "processor: CancelDelete signature verification failed"
            );
            return Ok(());
        }

        match self.db.get_holding(&block_id, &from)? {
            Some(mut holding) => {
                if holding.status == HoldingStatus::MarkedForDelete {
                    holding.status = HoldingStatus::Active;
                    holding.delete_requested_at = None;
                    self.db.upsert_holding(&holding)?;
                    info!(
                        block_id = %block_id,
                        owner = %from,
                        "processor: cancel delete — holding reverted to Active"
                    );
                } else {
                    debug!(
                        block_id = %block_id,
                        owner = %from,
                        status = ?holding.status,
                        "processor: CancelDelete ignored — holding not MarkedForDelete"
                    );
                }
            }
            None => {
                debug!(
                    block_id = %block_id,
                    owner = %from,
                    "processor: CancelDelete ignored — no holding for this block"
                );
            }
        }
        Ok(())
    }
}
