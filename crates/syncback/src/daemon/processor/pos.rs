// PoS handlers: holder responds to hash challenge, owner verifies hash response or receives nack.

use syncback_core::messages::{
    build_pos_hash_nack, verify_pos_hash_nack, Message, PosHashNackMsg, PosHashResponseMsg,
};
use syncback_core::pos::{
    apply_pos_outcome, compute_chain_hash, outcome_from_verify, verify_hash_response,
    VerifyOutcome,
};
use syncback_core::trust::{compute_combined, recalculate_trust};
use syncback_core::types::{hex_encode, DeviceId, IdentityPub, SourceBlockId, Timestamp};
use tracing::{debug, error, info, warn};

use crate::daemon::repair::RepairTrigger;

use super::{
    current_week_number_scaled, record_pos_weekly, ProcessorError, Processor,
};

impl Processor {
    // ─── Hash-based PoS handlers ─────────────────────────────────────────────

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
                return Ok(Message::PosHashNack(build_pos_hash_nack(
                    challenge.challenge_id,
                    block_id,
                    0,
                    Timestamp::now(),
                    challenge.device_id,
                    &self.master_signing_key,
                )));
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
                    return Ok(Message::PosHashNack(build_pos_hash_nack(
                        challenge.challenge_id,
                        block_id,
                        esi,
                        Timestamp::now(),
                        challenge.device_id,
                        &self.master_signing_key,
                    )));
                }
                Err(e) => return Err(ProcessorError::Io(e)),
            }
        }

        // Compute chain hash over bound symbol data.
        let refs: Vec<(u32, &[u8])> = symbol_data.iter()
            .map(|(esi, data)| (*esi, data.as_slice()))
            .collect();
        let chain_hash = compute_chain_hash(&challenge.challenge_id, &refs)
            .map_err(ProcessorError::PosVerify)?;

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
    /// Verifies that the nack is signed by the expected holder before marking placement Lost.
    pub(crate) async fn handle_pos_hash_nack(
        &self,
        from_device: DeviceId,
        nack: PosHashNackMsg,
    ) -> Result<(), ProcessorError> {
        let block_id = nack.source_block_id;

        // 1. Find pending challenge by challenge_id (linear scan, bounded by active placements).
        let pending_key = {
            let guard = self.pending_challenges.lock().await;
            guard.iter()
                .find(|(_, v)| v.challenge_id == nack.challenge_id)
                .map(|(k, _)| *k)
        };

        let key = match pending_key {
            Some(k) => k,
            None => {
                warn!(
                    holder = %from_device,
                    "processor: PosHashNack with unknown challenge_id (stale or already consumed)"
                );
                return Ok(());
            }
        };

        // 2. Resolve the expected holder's master identity from the pending challenge.
        //    pending_challenges key = (SourceBlockId, DeviceId) where DeviceId is the holder.
        let expected_holder_device = key.1;
        let expected_holder_master = match self.db.get_master_for_device(&expected_holder_device)? {
            Some(m) => m,
            None => {
                warn!(
                    holder = %expected_holder_device,
                    "processor: PosHashNack expected holder not in DB, rejecting"
                );
                return Ok(());
            }
        };

        // 3. Verify signature — signer must be the expected holder's master identity.
        if let Err(e) = verify_pos_hash_nack(&nack, &expected_holder_master) {
            warn!(
                from = %from_device,
                expected_holder = %expected_holder_device,
                err = %e,
                "processor: PosHashNack signature verification failed, ignoring"
            );
            return Ok(());
        }

        // 4. Consume the challenge entry (challenge lifecycle ends here).
        {
            let mut guard = self.pending_challenges.lock().await;
            guard.remove(&key);
        }

        // 5. Mark placement Lost.
        super::mark_placement_lost(&self.db, &block_id, &expected_holder_device)?;

        // 6. Refresh trust_s.
        if let Err(e) = self.db.refresh_peer_storage_bytes(&expected_holder_device) {
            error!(
                device = %expected_holder_device,
                err = %e,
                "processor: failed to refresh storage balance after PosHashNack"
            );
        }

        info!(block_id = %block_id, holder = %expected_holder_device, "repair: triggered by PosHashNack");
        let _ = self
            .repair_tx
            .send(RepairTrigger::RepairNow { block_id, holder_id: expected_holder_device })
            .await;
        Ok(())
    }

    /// Common logic: apply a VerifyOutcome to placement + trust + repair trigger.
    ///
    /// Shared by handle_pos_hash_response.
    /// No-op for CannotVerify (caller should check before calling if desired).
    pub(crate) async fn apply_and_persist_pos_outcome(
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
}
