// PoS handlers: holder responds to challenge, owner verifies response or receives nack.

use std::sync::Arc;

use syncback_core::messages::{Message, PosHashNackMsg, PosHashResponseMsg, PosNackMsg, PosResponseMsg};
use syncback_core::pos::{
    apply_pos_outcome, compute_chain_hash, outcome_from_verify, verify_hash_response,
    verify_response, PosResponse, VerifyOutcome,
};
use syncback_core::trust::{compute_combined, recalculate_trust};
use syncback_core::types::{hex_encode, DeviceId, IdentityPub, SourceBlockId, Timestamp};
use tracing::{debug, error, info, warn};

use crate::daemon::repair::RepairTrigger;

use super::{
    current_week_number_scaled, record_pos_weekly, ProcessorError, Processor,
};

impl Processor {
    /// Load the challenged symbol and send PosResponse, or PosNack if not held.
    ///
    /// Returns the reply message so tests can inspect it without a real connection.
    pub(crate) async fn handle_pos_challenge_inner(
        &self,
        owner_id: IdentityPub,
        challenge: syncback_core::messages::PosChallengeMsg,
    ) -> Result<syncback_core::messages::Message, ProcessorError> {
        use syncback_core::messages::Message;

        let block_id = challenge.source_block_id;
        let esi = challenge.esi;

        // Verify we actually hold symbols for this owner+block.
        // Without this check, any authenticated peer could probe our holdings
        // for arbitrary block IDs and receive symbol data.
        match self.db.get_holding(&block_id, &owner_id)? {
            Some(_) => {}
            None => {
                warn!(
                    block_id = %block_id,
                    challenger = %owner_id,
                    "processor: PoS challenge from non-owner, ignoring"
                );
                return Ok(Message::PosNack(syncback_core::messages::build_pos_nack(
                    challenge.challenge_id,
                    block_id,
                    esi,
                    Timestamp::now(),
                    challenge.device_id,
                    &self.master_signing_key,
                )));
            }
        }

        let sym_path = self
            .holdings_dir
            .join(hex_encode(&block_id.0))
            .join(format!("{esi}.bin"));

        match tokio::fs::read(&sym_path).await {
            Ok(data) => {
                debug!(
                    block_id = %block_id,
                    esi,
                    "processor: PoS challenge — responding with data"
                );
                Ok(Message::PosResponse(PosResponseMsg {
                    v: 1,
                    challenge_id: challenge.challenge_id,
                    esi,
                    data,
                    timestamp: Timestamp::now(),
                    device_id: challenge.device_id,
                }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    block_id = %block_id,
                    esi,
                    "processor: PoS challenge — symbol not held, sending PosNack"
                );
                Ok(Message::PosNack(syncback_core::messages::build_pos_nack(
                    challenge.challenge_id,
                    block_id,
                    esi,
                    Timestamp::now(),
                    challenge.device_id,
                    &self.master_signing_key,
                )))
            }
            Err(e) => Err(ProcessorError::Io(e)),
        }
    }

    /// Verify a PoS response from a holder.
    ///
    /// Looks up the pending challenge by challenge_id in the shared PendingChallenges
    /// map (written by Scheduler when the challenge was issued). On match, consumes
    /// the entry and proceeds to verify. If no match is found the response is stale
    /// or unknown and is silently dropped.
    ///
    /// Returns the VerifyOutcome for testing.
    pub(crate) async fn handle_pos_response(
        &self,
        holder_id: DeviceId,
        response: PosResponseMsg,
    ) -> Result<VerifyOutcome, ProcessorError> {
        // Resolve challenge_id → (source_block_id, map key) via the pending map.
        // Linear scan over in-flight challenges is fine: bounded by active placements,
        // typically in the hundreds.
        let pending_key = {
            let guard = self.pending_challenges.lock().await;
            guard
                .iter()
                .find(|(_, v)| v.challenge_id == response.challenge_id)
                .map(|(k, _)| *k)
        };

        let key = match pending_key {
            Some(k) => k,
            None => {
                warn!(
                    holder = %holder_id,
                    challenge_id = %hex_encode(&response.challenge_id),
                    "processor: PosResponse with unknown challenge_id (stale or duplicate), ignoring"
                );
                return Ok(VerifyOutcome::CannotVerify);
            }
        };

        // Consume the entry — challenge lifecycle ends here regardless of outcome.
        let esi = response.esi;
        {
            let mut guard = self.pending_challenges.lock().await;
            guard.remove(&key);
        };

        let block_id = key.0;

        // Load the placement record from DB (keyed by DeviceId).
        let placement = match self.db.get_placement(&block_id, &holder_id)? {
            Some(p) => p,
            None => {
                warn!(
                    block_id = %block_id,
                    holder = %holder_id,
                    "processor: PosResponse — placement missing from DB, ignoring"
                );
                return Ok(VerifyOutcome::Pass);
            }
        };

        let block_record = match self.db.get_source_block(&block_id)? {
            Some(r) => r,
            None => {
                warn!(
                    block_id = %block_id,
                    holder = %holder_id,
                    "processor: PosResponse — source block DB record missing, cannot verify"
                );
                return Ok(VerifyOutcome::CannotVerify);
            }
        };

        let block_path = self
            .source_blocks_dir
            .join(hex_encode(&block_id.0))
            .join("block.bin");

        let source_data = match tokio::fs::read(&block_path).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // block.bin cleaned up after delivery — rebuild from source files.
                debug!(
                    block_id = %block_id,
                    "processor: block.bin missing, rebuilding from source files"
                );
                match self.rebuild_blob_for_pos(&block_id).await {
                    Ok(data) => data,
                    Err(e) => {
                        warn!(
                            block_id = %block_id,
                            holder = %holder_id,
                            err = %e,
                            "processor: PosResponse — cannot rebuild blob, skipping verify"
                        );
                        return Ok(VerifyOutcome::CannotVerify);
                    }
                }
            }
            Err(e) => return Err(ProcessorError::Io(e)),
        };

        let params = block_record.erasure_params();

        let pos_response = PosResponse {
            challenge_id: response.challenge_id,
            esi: response.esi,
            data: response.data,
        };

        let encoder = Arc::clone(&self.encoder);
        let block_id_clone = block_id;
        let holder_id_clone = holder_id;

        let outcome = tokio::task::spawn_blocking(move || {
            verify_response(
                &pos_response,
                &source_data,
                &params,
                &block_id_clone,
                &holder_id_clone,
                encoder.as_ref(),
            )
        })
        .await
        .map_err(|e| ProcessorError::Join(e.to_string()))?
        .map_err(ProcessorError::PosVerify)?;

        // CannotVerify: owner-side data unavailable. Skip all state updates.
        if outcome == VerifyOutcome::CannotVerify {
            debug!(
                block_id = %block_id,
                holder = %holder_id,
                esi,
                "processor: PoS response received but cannot verify (source block unavailable)"
            );
            return Ok(VerifyOutcome::CannotVerify);
        }

        self.apply_and_persist_pos_outcome(block_id, holder_id, &outcome).await?;

        info!(
            block_id = %block_id,
            holder = %holder_id,
            esi,
            outcome = ?outcome,
            "processor: PoS response processed"
        );

        Ok(outcome)
    }

    /// Common logic: apply a VerifyOutcome to placement + trust + repair trigger.
    ///
    /// Shared by handle_pos_response and handle_pos_hash_response.
    /// No-op for CannotVerify (caller should check before calling if desired).
    async fn apply_and_persist_pos_outcome(
        &self,
        block_id: SourceBlockId,
        holder_id: DeviceId,
        outcome: &VerifyOutcome,
    ) -> Result<(), ProcessorError> {
        if *outcome == VerifyOutcome::CannotVerify {
            return Ok(());
        }

        let placement = match self.db.get_placement(&block_id, &holder_id)? {
            Some(p) => p,
            None => return Ok(()),
        };

        let transition = apply_pos_outcome(&placement, outcome);
        let mut updated = placement;
        updated.status = transition.new_status;
        updated.consecutive_misses = transition.new_consecutive_misses;
        if matches!(outcome, VerifyOutcome::Pass) {
            updated.last_verified = Some(Timestamp::now());
        }
        self.db.upsert_placement(&updated)?;

        // Refresh trust_s: placement status changed, so bytes_peer_stores_for_us may differ.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&holder_id) {
            error!(
                peer = %holder_id,
                err = %e,
                "processor: failed to refresh storage balance after PoS"
            );
        }

        // Update PoS weekly stats and recalculate trust.
        let week = current_week_number_scaled(self.time_scale);
        let pos_outcome = outcome_from_verify(outcome, week);
        record_pos_weekly(&self.db, holder_id, pos_outcome);

        // Recalculate trust scores from accumulated PoS history.
        if let Some((old_p, old_i, new_p, new_i)) =
            recalculate_trust(&self.db, &holder_id, week)
        {
            let old_combined = compute_combined(old_p, old_i, 1.0);
            let new_combined = compute_combined(new_p, new_i, 1.0);
            info!(
                peer = %holder_id,
                trust_p_before = format!("{old_p:.4}"),
                trust_p_after = format!("{new_p:.4}"),
                trust_i_before = format!("{old_i:.4}"),
                trust_i_after = format!("{new_i:.4}"),
                trust_combined_before = format!("{old_combined:.4}"),
                trust_combined_after = format!("{new_combined:.4}"),
                "trust: score updated after PoS"
            );
        }

        if transition.trigger_repair {
            info!(block_id = %block_id, holder = %holder_id, "repair: triggered");
            let _ = self
                .repair_tx
                .send(RepairTrigger::RepairNow { block_id, holder_id })
                .await;
        }

        Ok(())
    }

    /// Rebuild stored blob from source files for PoS verification.
    ///
    /// Used when block.bin has been cleaned up after symbol delivery.
    /// Encryption is deterministic, so rebuild produces identical blob.
    async fn rebuild_blob_for_pos(
        &self,
        block_id: &SourceBlockId,
    ) -> Result<Vec<u8>, ProcessorError> {
        let block_record = self
            .db
            .get_source_block(block_id)?
            .ok_or_else(|| ProcessorError::Join(
                format!("source block record missing: {block_id}")
            ))?;

        let db = self.db.clone();
        let epoch_key = self.epoch_key;
        let expected_id = *block_id;

        let stored = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            let plaintext = crate::daemon::backup::packing::rebuild_plaintext_from_db(
                &db,
                &block_record,
            )?;
            let blob = crate::daemon::backup::pipeline::compress_and_encrypt(&plaintext, &epoch_key)?;
            let rebuilt_id: [u8; 32] = *blake3::hash(&blob).as_bytes();
            if rebuilt_id != expected_id.0 {
                anyhow::bail!(
                    "rebuilt blob hash {} != expected block_id {}",
                    hex_encode(&rebuilt_id),
                    hex_encode(&expected_id.0),
                );
            }
            Ok(blob)
        })
        .await
        .map_err(|e| ProcessorError::Join(e.to_string()))?
        .map_err(|e| ProcessorError::Join(e.to_string()))?;

        info!(block_id = %block_id, "processor: rebuilt blob from source files for PoS");
        Ok(stored)
    }

    /// Mark a placement Lost (holder explicitly said it doesn't hold the symbol).
    ///
    /// Idempotent: no-op if already Lost or Deleting.
    /// Returns true if the placement was actually modified.
    pub(crate) fn handle_pos_nack_sync(
        &self,
        holder_id: DeviceId,
        nack: &PosNackMsg,
    ) -> Result<bool, ProcessorError> {
        let block_id = nack.source_block_id;
        super::mark_placement_lost(&self.db, &block_id, &holder_id)
    }

    // ─── Hash-based PoS handlers (Wave 4) ────────────────────────────────────

    /// Holder side: receive PosHashChallenge, read all assigned symbols, compute
    /// chain hash, return PosHashResponse (or PosHashNack on missing symbols).
    pub(crate) async fn handle_pos_hash_challenge_inner(
        &self,
        owner_id: IdentityPub,
        challenge: syncback_core::messages::PosHashChallengeMsg,
    ) -> Result<Message, ProcessorError> {
        let block_id = challenge.source_block_id;

        // Verify we hold symbols for this owner+block.
        match self.db.get_holding(&block_id, &owner_id)? {
            Some(_) => {}
            None => {
                warn!(
                    block_id = %block_id,
                    challenger = %owner_id,
                    "processor: PosHashChallenge from non-owner, sending nack"
                );
                return Ok(Message::PosHashNack(PosHashNackMsg {
                    v: 1,
                    challenge_id: challenge.challenge_id,
                    source_block_id: block_id,
                    first_missing_esi: 0,
                    timestamp: Timestamp::now(),
                    device_id: challenge.device_id,
                }));
            }
        }

        // Expand ESI ranges to a sorted ESI list.
        let mut esis: Vec<u32> = challenge.esi_ranges.iter()
            .flat_map(|&(start, count)| start..start + count)
            .collect();
        esis.sort_unstable();

        // Read all symbol files.
        let block_hex = hex_encode(&block_id.0);
        let block_dir = self.holdings_dir.join(&block_hex);
        let mut symbol_data: Vec<(u32, Vec<u8>)> = Vec::with_capacity(esis.len());

        for &esi in &esis {
            let sym_path = block_dir.join(format!("{esi}.bin"));
            match tokio::fs::read(&sym_path).await {
                Ok(data) => symbol_data.push((esi, data)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    warn!(
                        block_id = %block_id,
                        esi,
                        "processor: PosHashChallenge — symbol missing, sending nack"
                    );
                    return Ok(Message::PosHashNack(PosHashNackMsg {
                        v: 1,
                        challenge_id: challenge.challenge_id,
                        source_block_id: block_id,
                        first_missing_esi: esi,
                        timestamp: Timestamp::now(),
                        device_id: challenge.device_id,
                    }));
                }
                Err(e) => return Err(ProcessorError::Io(e)),
            }
        }

        // Compute chain hash over bound symbol data.
        let refs: Vec<(u32, &[u8])> = symbol_data.iter()
            .map(|(esi, data)| (*esi, data.as_slice()))
            .collect();
        let chain_hash = compute_chain_hash(&refs).map_err(ProcessorError::PosVerify)?;

        debug!(block_id = %block_id, "processor: PosHashChallenge — responding with chain hash");
        Ok(Message::PosHashResponse(PosHashResponseMsg {
            v: 1,
            challenge_id: challenge.challenge_id,
            chain_hash,
            timestamp: Timestamp::now(),
            device_id: challenge.device_id,
        }))
    }

    /// Owner side: receive PosHashResponse, look up pending challenge, verify hash.
    pub(crate) async fn handle_pos_hash_response(
        &self,
        holder_id: DeviceId,
        response: PosHashResponseMsg,
    ) -> Result<VerifyOutcome, ProcessorError> {
        // Find pending challenge by challenge_id (linear scan, bounded by active placements).
        let pending_key = {
            let guard = self.pending_challenges.lock().await;
            guard.iter()
                .find(|(_, v)| v.challenge_id == response.challenge_id)
                .map(|(k, _)| *k)
        };

        let key = match pending_key {
            Some(k) => k,
            None => {
                warn!(
                    holder = %holder_id,
                    "processor: PosHashResponse with unknown challenge_id (stale or duplicate)"
                );
                return Ok(VerifyOutcome::CannotVerify);
            }
        };

        // Consume the entry — challenge lifecycle ends here.
        let pending = {
            let mut guard = self.pending_challenges.lock().await;
            guard.remove(&key)
        };
        let pending = match pending {
            Some(p) => p,
            None => return Ok(VerifyOutcome::CannotVerify),
        };

        let block_id = key.0;
        let first_esi = pending.esi_ranges.first().map(|&(start, _)| start).unwrap_or(0);

        // Verify the chain hash.
        let outcome = verify_hash_response(
            &response.chain_hash,
            &pending.expected_chain_hash,
            first_esi,
        );

        self.apply_and_persist_pos_outcome(block_id, holder_id, &outcome).await?;

        info!(
            block_id = %block_id,
            holder = %holder_id,
            outcome = ?outcome,
            "processor: PosHash response processed"
        );
        Ok(outcome)
    }

    /// Owner side: receive PosHashNack — holder cannot serve the hash challenge.
    /// Mark placement Lost and trigger repair.
    pub(crate) async fn handle_pos_hash_nack(
        &self,
        from_device: DeviceId,
        nack: PosHashNackMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = nack.source_block_id;

        // Consume pending challenge (if any).
        {
            let mut guard = self.pending_challenges.lock().await;
            let key = guard.iter()
                .find(|(_, v)| v.challenge_id == nack.challenge_id)
                .map(|(k, _)| *k);
            if let Some(k) = key {
                guard.remove(&k);
            }
        }

        // Mark placement Lost.
        super::mark_placement_lost(&self.db, &block_id, &from_device)?;

        // Refresh trust_s.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&from_device) {
            error!(
                device = %from_device,
                err = %e,
                "processor: failed to refresh storage balance after PosHashNack"
            );
        }

        info!(block_id = %block_id, holder = %from_device, "repair: triggered by PosHashNack");
        let _ = self
            .repair_tx
            .send(RepairTrigger::RepairNow { block_id, holder_id: from_device })
            .await;
        Ok(())
    }

    pub(crate) async fn handle_pos_nack(
        &self,
        from_device: DeviceId,
        nack: PosNackMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = nack.source_block_id;

        // Verify the per-message signature using the holder's master identity.
        // Without this check, any peer who knows the victim's IdentityPub could
        // forge a PosNack and trigger a spurious repair (DoS on placement records).
        match self.db.get_master_for_device(&from_device) {
            Ok(Some(master)) => {
                if let Err(e) = syncback_core::messages::verify_pos_nack(&nack, &master) {
                    warn!(
                        device = %from_device,
                        block_id = %block_id,
                        err = %e,
                        "processor: PosNack signature verification failed — ignoring"
                    );
                    return Ok(());
                }
            }
            Ok(None) => {
                warn!(
                    device = %from_device,
                    block_id = %block_id,
                    "processor: PosNack from unknown device — ignoring"
                );
                return Ok(());
            }
            Err(e) => {
                error!(
                    device = %from_device,
                    err = %e,
                    "processor: PosNack — DB lookup failed"
                );
                return Ok(());
            }
        }

        self.handle_pos_nack_sync(from_device, &nack)?;

        // Consume the pending challenge so the scheduler does not re-send it.
        {
            let mut guard = self.pending_challenges.lock().await;
            let key = guard
                .iter()
                .find(|(_, v)| v.challenge_id == nack.challenge_id)
                .map(|(k, _)| *k);
            if let Some(k) = key {
                guard.remove(&k);
            }
        }

        // Refresh trust_s: holder no longer stores those symbols for us.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&from_device) {
            error!(
                device = %from_device,
                err = %e,
                "processor: failed to refresh storage balance after PosNack"
            );
        }

        info!(block_id = %block_id, holder = %from_device, "repair: triggered");
        let _ = self
            .repair_tx
            .send(RepairTrigger::RepairNow {
                block_id,
                holder_id: from_device,
            })
            .await;
        Ok(())
    }
}
