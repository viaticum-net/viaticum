// PoS handlers: holder responds to hash challenge, owner verifies hash response or receives nack.

use std::path::PathBuf;

use tracing::{debug, error, info, warn};
use viaticum_core::db::Db;
use viaticum_core::messages::{
    Message, PosHashChallengeMsg, PosHashNackMsg, PosHashResponseMsg, build_pos_hash_nack,
    verify_pos_hash_nack,
};
use viaticum_core::pos::{
    VerifyOutcome, apply_pos_outcome, compute_chain_hash, outcome_from_verify, verify_hash_response,
};
use viaticum_core::trust::{compute_combined, recalculate_trust};
use viaticum_core::types::from_cbor_bytes;
use viaticum_core::types::{DeviceId, IdentityPub, SourceBlockId, Timestamp, hex_encode};

use crate::daemon::mailbox::poll::PosMailboxChallengeHandler;
use crate::daemon::repair::RepairTrigger;

use super::{Processor, ProcessorError, current_week_number_scaled, record_pos_weekly};

// ─── PosResponder: standalone holder-side challenge-response compute ─────────

/// Lightweight struct that owns only the three fields needed to compute a
/// PosHashResponse (or PosHashNack) for an inbound PosHashChallengeMsg.
///
/// Decoupled from the full Processor so it can be cloned into the mailbox poll
/// task without requiring Processor to be Arc-wrapped.
///
/// Fields mirror the corresponding fields of `Processor`:
/// - `db`: used to verify we hold symbols for the given owner+block.
/// - `holdings_dir`: root directory for stored symbol files (`{block_hex}/{esi}.bin`).
/// - `master_signing_key`: signs PosHashNackMsg so the owner can verify authenticity.
pub struct PosResponder {
    db: Db,
    holdings_dir: PathBuf,
    master_signing_key: ed25519_dalek::SigningKey,
}

impl PosResponder {
    pub fn new(
        db: Db,
        holdings_dir: PathBuf,
        master_signing_key: ed25519_dalek::SigningKey,
    ) -> Self {
        PosResponder {
            db,
            holdings_dir,
            master_signing_key,
        }
    }
}

impl PosResponder {
    /// Compute a PosHashResponse (or PosHashNack) for the given challenge.
    ///
    /// This is the exact logic previously inlined in
    /// `Processor::handle_pos_hash_challenge_inner`; `Processor` now delegates here.
    pub async fn compute_response(
        &self,
        owner_id: IdentityPub,
        challenge: PosHashChallengeMsg,
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
        let mut esis: Vec<u32> = challenge
            .esi_ranges
            .iter()
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
        let refs: Vec<(u32, &[u8])> = symbol_data
            .iter()
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
}

impl Processor {
    // ─── Hash-based PoS handlers ─────────────────────────────────────────────

    /// Holder side: receive PosHashChallenge, read all assigned symbols, compute
    /// chain hash, return PosHashResponse (or PosHashNack on missing symbols).
    ///
    /// Delegates to `PosResponder::compute_response` — the responder owns only
    /// the three fields needed (db, holdings_dir, master_signing_key), keeping
    /// the compute logic decoupled from the full Processor lifetime.
    pub(crate) async fn handle_pos_hash_challenge_inner(
        &self,
        owner_id: IdentityPub,
        challenge: viaticum_core::messages::PosHashChallengeMsg,
    ) -> Result<Message, ProcessorError> {
        let responder = PosResponder::new(
            self.db.clone(),
            self.holdings_dir.clone(),
            self.master_signing_key.clone(),
        );
        responder.compute_response(owner_id, challenge).await
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
        let first_esi = pending
            .esi_ranges
            .first()
            .map(|&(start, _)| start)
            .unwrap_or(0);

        // Verify the chain hash.
        let outcome = verify_hash_response(
            &response.chain_hash,
            &pending.expected_chain_hash,
            first_esi,
        );

        self.apply_and_persist_pos_outcome(block_id, holder_id, &outcome)
            .await?;

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
            guard
                .iter()
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

        // 5a. Recompute cached fields (best-effort, unconditional — mark_placement_lost
        //     is idempotent and the hook recount is idempotent if already Lost).
        super::recompute_and_persist_block_cached_fields(&self.db, &block_id);

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
            .send(RepairTrigger::RepairNow {
                block_id,
                holder_id: expected_holder_device,
            })
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

        let old_status = placement.status;
        let transition = apply_pos_outcome(&placement, outcome);
        let mut updated = placement;
        updated.status = transition.new_status;
        updated.consecutive_misses = transition.new_consecutive_misses;
        if matches!(outcome, VerifyOutcome::Pass) {
            updated.last_verified = Some(Timestamp::now());
        }
        self.db.upsert_placement(&updated)?;

        // Update cached fields only when placement status actually changed (avoids
        // noise on Pass-on-Alive cycle where current_alive stays the same).
        if updated.status != old_status {
            super::recompute_and_persist_block_cached_fields(&self.db, &block_id);
        }

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
        if let Some((old_p, old_i, new_p, new_i)) = recalculate_trust(&self.db, &holder_id, week) {
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
                .send(RepairTrigger::RepairNow {
                    block_id,
                    holder_id,
                })
                .await;
        }

        Ok(())
    }
}

// ─── ProcessorPosHandler: bridges poll loop → PosResponder ──────────────────

/// Production impl of PosMailboxChallengeHandler that delegates to a `PosResponder`.
///
/// The poll loop calls this when it receives a PosChallenge entry from the mailbox.
/// The handler decodes the challenge, calls `PosResponder::compute_response`, and
/// returns the response (if any). The poll loop then publishes the response via mailbox.
///
/// `PosResponder` is constructed from the same db / holdings_dir / master_signing_key
/// clones that are passed into Processor — no Arc<Processor> wrapping is needed.
///
/// Note: owner_id here is the sender field from the MailboxEntry (the owner's master_pub
/// who published the challenge). We pass it as `owner_id` to `compute_response` which uses
/// it to look up our HoldingRecord for that owner+block.
///
/// Nack-over-mailbox delivery (so the owner receives an explicit Nack instead of waiting
/// for the 14d2h pending timeout) is a documented follow-up; it requires a new MailboxClass
/// and is out of scope for A2. The 14d2h timeout is the correct backstop for cold backup.
pub struct ProcessorPosHandler {
    responder: PosResponder,
}

impl ProcessorPosHandler {
    pub fn new(responder: PosResponder) -> Self {
        ProcessorPosHandler { responder }
    }
}

#[async_trait::async_trait]
impl PosMailboxChallengeHandler for ProcessorPosHandler {
    async fn handle_pos_challenge(
        &self,
        owner_master_pub: IdentityPub,
        payload: Vec<u8>,
    ) -> anyhow::Result<Option<PosHashResponseMsg>> {
        // owner_master_pub = MailboxEntry.sender (the owner who sent the challenge).
        // Passed as owner_id to compute_response which uses it to look up our HoldingRecord.
        match from_cbor_bytes::<PosHashChallengeMsg>(&payload) {
            Ok(challenge) => {
                match self
                    .responder
                    .compute_response(owner_master_pub, challenge)
                    .await
                {
                    Ok(Message::PosHashResponse(response)) => Ok(Some(response)),
                    Ok(Message::PosHashNack(_)) => {
                        // Nack-over-mailbox delivery is a documented A2 follow-up (needs a new
                        // MailboxClass). The owner's pending challenge timeout (14d2h) is the
                        // correct backstop for cold backup — this is a conscious limitation, not
                        // a silent drop.
                        info!(
                            "mailbox PoS: holder cannot serve challenge (nack); \
                             owner will detect via pending timeout — \
                             nack-over-mailbox delivery is a documented A2 follow-up"
                        );
                        Ok(None)
                    }
                    Ok(other) => {
                        warn!(
                            msg_variant = ?std::mem::discriminant(&other),
                            "mailbox PoS: unexpected Message variant from compute_response"
                        );
                        Ok(None)
                    }
                    Err(e) => Err(anyhow::anyhow!("pos challenge handler error: {e}")),
                }
            }
            Err(e) => Err(anyhow::anyhow!("failed to decode PosHashChallengeMsg: {e}")),
        }
    }
}
