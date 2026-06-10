// PoS handlers: holder responds to hash challenge, owner verifies hash response or receives nack.

use std::path::PathBuf;

use tracing::{debug, info, warn};
use viaticum_core::db::Db;
use viaticum_core::messages::{
    Message, PosHashChallengeMsg, PosHashResponseMsg, build_pos_hash_nack,
};
use viaticum_core::pos::compute_chain_hash;
use viaticum_core::types::from_cbor_bytes;
use viaticum_core::types::{IdentityPub, Timestamp, hex_encode};

use crate::daemon::mailbox::poll::PosMailboxChallengeHandler;

use super::{Processor, ProcessorError};

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
