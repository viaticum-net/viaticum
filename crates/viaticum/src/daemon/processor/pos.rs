// PoS handlers: holder responds to hash challenge, owner verifies hash response or receives nack.

use std::path::PathBuf;

use tracing::{debug, info, warn};
use viaticum_core::db::Db;
use viaticum_core::messages::{
    Message, PosHashChallengeMsg, PosHashResponseMsg, build_pos_hash_nack, build_pos_hash_response,
    verify_pos_hash_challenge,
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

        // CS-ID-5 / P1-2: authenticate the challenge BEFORE any disk work or re-encode.
        // The owner signs the challenge with its master key; `owner_id` is the claimed owner
        // (MailboxEntry.sender on the mailbox path, the handshake-verified master on direct-RR).
        // A forged challenge whose `sender` the attacker does not hold the key for cannot carry
        // a valid signature → drop with UnauthenticatedChallenge (no Nack, no compute). The
        // holding-check below stays: it binds the signer to a real owner we actually store for.
        if let Err(e) = verify_pos_hash_challenge(&challenge, &owner_id) {
            warn!(
                block_id = %block_id,
                challenger = %owner_id,
                err = %e,
                "processor: PosHashChallenge signature verification failed — dropping (forge attempt or legacy unsigned challenge)"
            );
            return Err(ProcessorError::UnauthenticatedChallenge);
        }

        // Verify we hold symbols for this owner+block. Capture the holding — its
        // `symbol_count()` bounds the legitimate challenge size (SM-1 guard below).
        let holding = match self.db.get_holding(&block_id, &owner_id)? {
            Some(holding) => holding,
            None => {
                warn!(
                    block_id = %block_id,
                    challenger = %owner_id,
                    challenge_id = %hex_encode(&challenge.challenge_id),
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
        };

        // SM-1: bound the ESI-range expansion BEFORE allocating.
        //
        // `esi_ranges` is attacker-shaped on the wire: a malicious-but-authenticated owner
        // (it passed the signature + holding checks above) can send `[(0, u32::MAX)]`, which
        // the old `flat_map(start..start+count).collect()` expanded into a ~4.29-billion-
        // element Vec<u32> (~16 GB) BEFORE the per-symbol existence check — OOM. The companion
        // bug: `start + count` near u32::MAX overflows → debug panic.
        //
        // A legitimate owner builds the challenge from `placement.esi_ranges`, which equals the
        // holding's coverage, so a legit challenge always has `sum(counts) <= symbol_count()`.
        // We REJECT (not clamp) an abusive challenge: the owner computes its expected chain_hash
        // over the exact `esi_ranges` it sent, so responding over a shrunk set would record a
        // false Fail for an honest holder. Reject → silent drop (no Nack = no signed-reply
        // amplification), matching the `UnauthenticatedChallenge` drop pattern above.
        let held = holding.symbol_count();
        let mut requested: u64 = 0;
        for &(start, count) in &challenge.esi_ranges {
            if start.checked_add(count).is_none() {
                warn!(
                    block_id = %block_id,
                    challenger = %owner_id,
                    start,
                    count,
                    "processor: PosHashChallenge ESI range overflows u32 — dropping (malformed/abusive)"
                );
                return Err(ProcessorError::OversizedChallenge {
                    block_id,
                    requested: u64::from(start) + u64::from(count),
                    held,
                });
            }
            requested = requested.saturating_add(u64::from(count));
        }
        // CS-POS-4: an empty/zero esi_ranges (requested == 0) passes the `requested > held`
        // check below (0 <= held) but would then feed `compute_chain_hash` an empty input →
        // `ChainHashEmptyInput` Err, and a handler error is not remembered by the poll (pos-i5),
        // so it would recur on every poll until the entry's TTL from one signed junk
        // challenge. A legitimate challenge always covers ≥1 ESI, so reject
        // it here as malformed — same clean-drop treatment as the oversized case (no Nack, no
        // response, surfaced as `OversizedChallenge` which the poll handler drops cleanly).
        if requested == 0 {
            warn!(
                block_id = %block_id,
                challenger = %owner_id,
                "processor: PosHashChallenge has empty esi_ranges (0 ESIs) — dropping (malformed)"
            );
            return Err(ProcessorError::OversizedChallenge {
                block_id,
                requested,
                held,
            });
        }
        if requested > u64::from(held) {
            warn!(
                block_id = %block_id,
                challenger = %owner_id,
                requested,
                held,
                "processor: PosHashChallenge requests more ESIs than we hold — dropping (abusive/malformed)"
            );
            return Err(ProcessorError::OversizedChallenge {
                block_id,
                requested,
                held,
            });
        }

        // Expand ESI ranges to a sorted ESI list — now bounded by `symbol_count()` (small,
        // real). The legit path (requested <= held) is unchanged: it expands exactly the
        // requested ESIs and the per-ESI file-read + Nack-on-missing logic below is untouched,
        // so chain-hash matching for honest holders is preserved.
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
                        challenge_id = %hex_encode(&challenge.challenge_id),
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

        // pos-i5: on the mailbox path this line comes once per challenge (the poll keeps
        // the answer in memory); the scenario counts it per `challenge_id`.
        debug!(
            block_id = %block_id,
            challenge_id = %hex_encode(&challenge.challenge_id),
            owner = %owner_id,
            "processor: PosHashChallenge — responding with chain hash"
        );
        // CS-ID-1 / P1-1: sign the response with our master key so the owner can verify it
        // came from the challenged holder (not a positioned postman forging a wrong hash).
        Ok(Message::PosHashResponse(build_pos_hash_response(
            challenge.challenge_id,
            block_id,
            chain_hash,
            Timestamp::now(),
            challenge.device_id,
            &self.master_signing_key,
        )))
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
                    // CS-ID-5 / P1-2: an unauthenticated (forged/unsigned) challenge was already
                    // logged inside compute_response. Treat it as a clean drop — no response is
                    // published and the poll loop must NOT surface it as a handler error.
                    Err(ProcessorError::UnauthenticatedChallenge) => Ok(None),
                    // SM-1: an oversized/malformed challenge (sum of counts > what we hold, or a
                    // range overflowing u32) was already warn-logged inside compute_response.
                    // Same clean-drop treatment as UnauthenticatedChallenge — no Nack, no
                    // response, not surfaced as a handler error.
                    Err(ProcessorError::OversizedChallenge { .. }) => Ok(None),
                    Err(e) => Err(anyhow::anyhow!("pos challenge handler error: {e}")),
                }
            }
            Err(e) => Err(anyhow::anyhow!("failed to decode PosHashChallengeMsg: {e}")),
        }
    }
}
