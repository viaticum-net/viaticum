// Symbol handlers: offer/transfer (holder), dropped/drop_notice (owner), delete/cancel_delete (holder).

use tracing::{debug, error, info, warn};
use viaticum_core::constants::{MESSAGE_FRESHNESS_SECS, SYMBOL_OFFER_EXPIRY_SECS, SYMBOL_SIZE};
use viaticum_core::db::Db;
use viaticum_core::messages::{
    CancelDeleteMsg, DeleteMsg, RejectReason, SymbolAcceptMsg, SymbolDropNoticeMsg,
    SymbolDroppedMsg, SymbolOfferMsg, SymbolRejectMsg, SymbolTransferMsg,
    verify_symbol_drop_notice, verify_symbol_offer,
};
use viaticum_core::types::{
    DeviceId, HoldingRecord, HoldingStatus, IdentityPub, Timestamp, hex_encode,
};

use crate::daemon::repair::RepairTrigger;

use super::{AcceptedOffer, Processor, ProcessorError, esi_list_to_ranges, ranges_to_esi_list};

// ─── SymbolDropHandler: standalone owner-side DropNotice handler ──────────────

/// Standalone handler for `SymbolDropNoticeMsg` entries received from the mailbox or relay.
///
/// Extracted from `Processor::handle_symbol_drop_notice` so the mailbox poll loop
/// can call it without holding an `Arc<Processor>` (mirrors `PosResponder` from T-6).
///
/// Only requires `db` — confirmed: the original method uses `self.db` only.
pub struct SymbolDropHandler {
    db: Db,
}

impl SymbolDropHandler {
    pub fn new(db: Db) -> Self {
        SymbolDropHandler { db }
    }

    /// Apply a single DropNotice: verify signature, mark placement Lost, recompute cached fields.
    ///
    /// Returns `true` if the notice passed verification and the placement was updated (or was
    /// already Lost/Deleting — idempotent). Returns `false` if the signature failed or the
    /// holder/block is unknown. Callers (e.g. `ProcessorDropHandler`) gate side-effects like
    /// `RepairNow` on the return value — prevents repair storms from forged notices.
    ///
    /// Security: verifies `notice.sig` against `from` (holder master identity) before acting.
    /// An attacker controlling a mailbox postman cannot forge a drop for a block they do not hold:
    /// - A valid sig requires the private key of the holder master.
    /// - `mark_placement_lost(block, holder_device)` is a no-op when that holder has no placement
    ///   for this block — so a signed notice can only drop placements the signer actually holds.
    ///
    /// Semantics are identical to `Processor::handle_symbol_drop_notice`.
    /// Idempotent: if placement is already Lost/Deleting, returns `true` (sig passed, no-op).
    /// On unknown holder or block, logs WARN and returns `false` (not a panic path).
    pub fn apply(&self, from: IdentityPub, notice: SymbolDropNoticeMsg) -> bool {
        let block_id = notice.source_block_id;

        // Verify holder signature before marking any placement Lost.
        // This closes the forge vector that existed in T-13a (unauthenticated notices).
        if let Err(e) = verify_symbol_drop_notice(&notice, &from) {
            warn!(
                block_id = %block_id,
                holder = %from,
                err = %e,
                "processor: DropNotice signature verification failed — ignoring (forge attempt or legacy unsigned notice)"
            );
            return false;
        }

        info!(
            block_id = %block_id,
            holder = %from,
            deadline = notice.deadline.0,
            "processor: received SymbolDropNotice — transitioning placement to Lost"
        );

        let devices = self.db.get_devices_for_master(&from).unwrap_or_default();
        if devices.is_empty() {
            warn!(
                block_id = %block_id,
                holder = %from,
                "processor: DropNotice from unknown master — no devices in DB, ignoring"
            );
            return false;
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
                return false;
            }
        };

        let changed = match super::mark_placement_lost(&self.db, &block_id, &holder_device_id) {
            Ok(c) => c,
            Err(e) => {
                error!(
                    block_id = %block_id,
                    holder = %holder_device_id,
                    err = %e,
                    "processor: DropNotice — mark_placement_lost failed"
                );
                return false;
            }
        };

        if !changed {
            debug!(
                block_id = %block_id,
                holder = %holder_device_id,
                "processor: DropNotice — placement already Lost/Deleting, skipping block update"
            );
            // Sig passed and no-op (idempotent): return true so RepairNow is
            // still triggered for immediate drops even on re-delivery.
            return true;
        }

        let block = match self.db.get_source_block(&block_id) {
            Ok(Some(b)) => b,
            Ok(None) => {
                warn!(
                    block_id = %block_id,
                    "processor: DropNotice — source block not found after placement update"
                );
                // Placement was updated successfully; return true so RepairNow is still triggered.
                return true;
            }
            Err(e) => {
                error!(
                    block_id = %block_id,
                    err = %e,
                    "processor: DropNotice — get_source_block failed"
                );
                return true;
            }
        };

        let placements = match self.db.list_placements_for_block(&block_id) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    block_id = %block_id,
                    err = %e,
                    "processor: DropNotice — list_placements_for_block failed"
                );
                return true;
            }
        };

        let new_current_alive: u32 = placements
            .iter()
            .filter(|p| {
                p.status == viaticum_core::types::PlacementStatus::Alive
                    || p.status == viaticum_core::types::PlacementStatus::Uncertain
            })
            .count() as u32;

        let k_eff = block.erasure_params().k_eff;
        let holder_inputs: Vec<viaticum_core::reliability::HolderReliabilityInput> = placements
            .iter()
            .filter(|p| {
                p.status == viaticum_core::types::PlacementStatus::Alive
                    || p.status == viaticum_core::types::PlacementStatus::Uncertain
            })
            .map(|p| {
                let survival_prob = self
                    .db
                    .get_peer(&p.holder_id)
                    .ok()
                    .flatten()
                    .map(|peer| {
                        viaticum_core::reliability::commitment_to_survival_prob(
                            viaticum_core::commitment::CommitmentScore::new(peer.trust_p),
                        )
                    })
                    .unwrap_or_else(|| {
                        viaticum_core::reliability::commitment_to_survival_prob(
                            viaticum_core::commitment::CommitmentScore::new(0.5),
                        )
                    });
                viaticum_core::reliability::HolderReliabilityInput {
                    holder_id: p.holder_id,
                    alive_symbols: p.symbol_count(),
                    survival_prob,
                }
            })
            .collect();

        let reliability_input = viaticum_core::reliability::BlockReliabilityInput {
            block_id,
            k_eff,
            holders: holder_inputs,
        };

        let new_reliability =
            match viaticum_core::reliability::block_reliability(&reliability_input) {
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

        if let Err(e) = self.db.update_block_cached_fields(
            &block_id,
            block.importance,
            new_current_alive,
            new_reliability,
            block.target_reliability,
        ) {
            error!(
                block_id = %block_id,
                err = %e,
                "processor: DropNotice — update_block_cached_fields failed"
            );
            return true;
        }

        info!(
            block_id = %block_id,
            holder = %holder_device_id,
            new_current_alive,
            new_reliability,
            "processor: DropNotice — block cached fields updated, repair will be scheduled"
        );

        if let Err(e) = self.db.refresh_peer_storage_bytes(&holder_device_id) {
            error!(
                device = %holder_device_id,
                err = %e,
                "processor: DropNotice — failed to refresh storage balance"
            );
        }

        true
    }
}

// ─── ProcessorDropHandler: bridges poll loop → SymbolDropHandler ──────────────

/// Production impl of `DropNoticeHandler` that delegates to `SymbolDropHandler`.
///
/// T-13a: extended to trigger `RepairTrigger::RepairNow` for immediate drops
/// (deadline ≤ now + IMMEDIATE_DROP_EPSILON_SECS). This handles the former
/// `SymbolDropped`-via-relay path which is now folded into the DropNotice mailbox
/// path with `deadline = Timestamp::now()`.
///
/// Constructed from the same `db` clone passed into `Processor` —
/// no `Arc<Processor>` wrap is needed (mirrors `ProcessorPosHandler` / `PosResponder`).
///
/// `repair_tx`: mpsc sender to the repair worker. Used to trigger immediate repair
/// for already-dropped symbols (deadline ≤ now). May be None in tests that only
/// exercise the advance-notice path.
pub struct ProcessorDropHandler {
    inner: SymbolDropHandler,
    db: viaticum_core::db::Db,
    repair_tx: tokio::sync::mpsc::Sender<crate::daemon::repair::RepairTrigger>,
}

/// If a DropNotice deadline is within this many seconds of now (or in the past),
/// treat it as an immediate drop and trigger RepairNow instead of lazy repair.
/// 5 minutes: generous for clock skew + publish latency.
const IMMEDIATE_DROP_EPSILON_SECS: u64 = 300;

impl ProcessorDropHandler {
    pub fn new(
        db: viaticum_core::db::Db,
        repair_tx: tokio::sync::mpsc::Sender<crate::daemon::repair::RepairTrigger>,
    ) -> Self {
        ProcessorDropHandler {
            inner: SymbolDropHandler::new(db.clone()),
            db,
            repair_tx,
        }
    }
}

impl crate::daemon::mailbox::poll::DropNoticeHandler for ProcessorDropHandler {
    fn handle_drop_notice(&self, from: IdentityPub, notice: SymbolDropNoticeMsg) {
        let block_id = notice.source_block_id;
        let deadline = notice.deadline.0;

        // Apply DropNotice: verify sig, mark placement Lost, recompute reliability.
        // Returns false if sig verification failed or holder/block unknown.
        // Gate all side-effects (RepairNow) on a successful apply to prevent repair storms
        // from forged notices that pass `is_immediate` but fail sig verification.
        let applied = self.inner.apply(from, notice);
        if !applied {
            return;
        }

        // T-13a: if this is an immediate drop (deadline ≈ now), trigger RepairNow
        // so that repair happens urgently rather than waiting for the next scheduled scan.
        // This preserves the semantics of the former SymbolDropped-via-relay path.
        let now = viaticum_core::types::Timestamp::now().0;
        let is_immediate = deadline <= now.saturating_add(IMMEDIATE_DROP_EPSILON_SECS);
        if is_immediate {
            // Resolve DeviceId for the holder master pub (same lookup as handle_symbol_dropped).
            let holder_device_opt = self
                .db
                .get_devices_for_master(&from)
                .unwrap_or_default()
                .into_iter()
                .find(|did| {
                    // Use the first device that has a placement for this block.
                    // If none found, fall back to first known device.
                    self.db
                        .get_placement(&block_id, did)
                        .ok()
                        .flatten()
                        .is_some()
                })
                .or_else(|| {
                    self.db
                        .get_devices_for_master(&from)
                        .unwrap_or_default()
                        .into_iter()
                        .next()
                });

            if let Some(holder_device) = holder_device_opt {
                let trigger = crate::daemon::repair::RepairTrigger::RepairNow {
                    block_id,
                    holder_id: holder_device,
                };
                // W-1: try_send is non-blocking. Under burst eviction the channel (cap 64)
                // may be full, silently dropping the RepairNow trigger. This is an accepted
                // trade-off for cold backup: the periodic reliability scan (hourly) is the
                // backstop. Worst-case repair latency under burst = reliability-scan interval
                // (≤ 1 hour), which is within the cold-backup time constant of 1 week.
                if let Err(e) = self.repair_tx.try_send(trigger) {
                    tracing::warn!(
                        block_id = %block_id,
                        holder = %from,
                        err = %e,
                        "processor: DropNotice immediate drop — repair_tx full or closed, \
                         repair will be scheduled lazily"
                    );
                } else {
                    tracing::info!(
                        block_id = %block_id,
                        holder = %from,
                        "processor: DropNotice immediate drop — RepairNow triggered"
                    );
                }
            } else {
                tracing::warn!(
                    block_id = %block_id,
                    holder = %from,
                    "processor: DropNotice immediate drop — could not resolve DeviceId for holder, \
                     repair will be scheduled lazily"
                );
            }
        }
    }
}

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
                self.accepted_offers
                    .lock()
                    .unwrap()
                    .remove(&(owner_id, block_id));
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
                self.accepted_offers
                    .lock()
                    .unwrap()
                    .remove(&(owner_id, block_id));
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
        for did in self
            .db
            .get_devices_for_master(&owner_id)
            .unwrap_or_default()
        {
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
    ///
    /// Three-stage rejection (in order):
    ///   1. Hard quota: held_bytes >= hard_quota → reject (absolute ceiling)
    ///   2. Soft pressure: free_ratio < 15% → reject (prevent reaching hard pressure)
    ///   3. Final fill: held_bytes + offer_bytes > effective → reject (would exceed cap)
    pub(crate) fn decide_symbol_offer(&self, offer_bytes: u64) -> Result<bool, ProcessorError> {
        let held_bytes = self.db.total_holding_bytes()?;

        // Hard quota: absolute ceiling — always reject above this.
        if self.hard_quota_bytes > 0 && held_bytes >= self.hard_quota_bytes {
            return Ok(false);
        }

        // Effective soft quota: min(config_soft_quota, disk_free - reserve).
        // When soft_quota=0, uses all available disk minus reserve.
        let disk_free = crate::daemon::handle::disk_available_bytes(&self.data_dir);
        let effective = viaticum_core::budget::compute_effective_quota(
            self.soft_quota_bytes,
            disk_free,
            self.disk_reserve_bytes,
        );

        // Soft pressure: reject before we hit hard pressure threshold. Closes the
        // gap where soft pressure was only logged in holder_cleanup but never
        // actually rejected new offers.
        if viaticum_core::budget::should_reject_offers(effective, held_bytes) {
            return Ok(false);
        }

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
    ///   1. Freshness: |now - timestamp| <= MESSAGE_FRESHNESS_SECS
    ///   2. Signature: verify_symbol_offer against owner_id (master identity from handshake)
    ///   3. Quota: decide_symbol_offer
    ///
    /// Called from dispatch_libp2p; reply is sent via ResponseChannel by caller.
    pub(crate) fn handle_symbol_offer_inner(
        &self,
        owner_id: IdentityPub,
        offer: SymbolOfferMsg,
    ) -> viaticum_core::messages::Message {
        use viaticum_core::messages::{Message, SymbolAcceptMsg};

        let now = Timestamp::now().0;
        let ts = offer.timestamp.0;
        let delta = now.abs_diff(ts);
        if delta > MESSAGE_FRESHNESS_SECS {
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
        let holder_device = self
            .db
            .get_devices_for_master(&from_master)
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or(DeviceId(from_master.0));
        let _ = self
            .backup_event_tx
            .send(crate::daemon::backup::BackupEvent::SymbolAccepted {
                holder_id: holder_device,
                source_block_id: accept.source_block_id,
            })
            .await;
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
        let holder_device = self
            .db
            .get_devices_for_master(&from_master)
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or(DeviceId(from_master.0));
        let _ = self
            .backup_event_tx
            .send(crate::daemon::backup::BackupEvent::SymbolRejected {
                holder_id: holder_device,
                source_block_id: reject.source_block_id,
                reason: format!("{:?}", reject.reason),
            })
            .await;
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
                if let Err(e) = viaticum_core::messages::verify_symbol_dropped(&dropped, &master) {
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
    /// Delegates to `SymbolDropHandler::apply` — extracted so the mailbox poll
    /// loop (T-7) can call the same logic without an `Arc<Processor>`.
    ///
    /// Unlike `handle_symbol_dropped`, this handler does NOT send a
    /// `RepairTrigger::RepairNow`. The block re-enters the worker queue
    /// automatically via `next_work_item` once `current_reliability` drops
    /// below `target_reliability`. Repair latency is bounded by the worker
    /// poll interval — acceptable for cold backup (time constant = 1 week).
    pub(crate) fn handle_symbol_drop_notice(&self, from: IdentityPub, notice: SymbolDropNoticeMsg) {
        SymbolDropHandler::new(self.db.clone()).apply(from, notice);
    }

    /// Handle a Delete request from the owner. Verify signature, then mark
    /// the holding as MarkedForDelete so the cleanup task can process it later.
    pub(crate) async fn handle_delete(
        &self,
        from: IdentityPub,
        delete: DeleteMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = delete.source_block_id;

        // Reject stale/replayed messages. Use MESSAGE_FRESHNESS_SECS (1h) — wider
        // than handshake window — because Delete is operational, msg_id dedup +
        // signature already prevent replay attacks even with looser timestamp gate.
        let now = Timestamp::now();
        let age = now.0.saturating_sub(delete.timestamp.0);
        if age > MESSAGE_FRESHNESS_SECS {
            warn!(
                block_id = %block_id,
                owner = %from,
                age_secs = age,
                "processor: Delete rejected — timestamp too old (possible replay)"
            );
            return Ok(());
        }

        // Verify signature against the sender's identity (the owner).
        if let Err(e) = viaticum_core::messages::verify_delete_msg(&delete, &from) {
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

        // Reject stale/replayed messages. Use MESSAGE_FRESHNESS_SECS (operational).
        let now = Timestamp::now();
        let age = now.0.saturating_sub(cancel.timestamp.0);
        if age > MESSAGE_FRESHNESS_SECS {
            warn!(
                block_id = %block_id,
                owner = %from,
                age_secs = age,
                "processor: CancelDelete rejected — timestamp too old (possible replay)"
            );
            return Ok(());
        }

        if let Err(e) = viaticum_core::messages::verify_cancel_delete_msg(&cancel, &from) {
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
