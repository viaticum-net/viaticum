// PoS handlers: holder responds to hash challenge, owner verifies hash response or receives nack.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;
use tracing::{debug, info, warn};
use viaticum_core::cluster::ClusterState;
use viaticum_core::db::Db;
use viaticum_core::messages::{
    Message, PosHashChallengeMsg, build_pos_hash_nack, build_pos_hash_response,
    verify_pos_hash_challenge,
};
use viaticum_core::pos::ChainHasher;
use viaticum_core::types::from_cbor_bytes;
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp, hex_encode};

use crate::daemon::mailbox::poll::{PosChallengeAnswer, PosMailboxChallengeHandler};

use super::{Processor, ProcessorError};

// ─── PosResponder: standalone holder-side challenge-response compute ─────────

/// Lightweight struct that owns only the fields needed to compute a PosHashResponse (or
/// PosHashNack) for an inbound PosHashChallengeMsg.
///
/// Decoupled from the full Processor so it can be cloned into the mailbox poll
/// task without requiring Processor to be Arc-wrapped.
///
/// - `db`: used to verify we hold symbols for the given owner+block, and to know the
///   devices of our own master (sibling check, pos-i15).
/// - `holdings_dir`: root directory for stored symbol files (`{block_hex}/{esi}.bin`).
/// - `device_signing_key`: this device's key; signs the response and the Nack so the
///   owner accepts them only for a placement on this device (pos-i16).
/// - `device_id`: derived from `device_signing_key`; a challenge addressed to another
///   device is not served (pos-i15).
/// - `own_master`: our master identity; its devices are our siblings.
/// - `cluster_state`: the devices this node's cluster knows (siblings not yet in the
///   device→master table).
pub struct PosResponder {
    db: Db,
    holdings_dir: PathBuf,
    device_signing_key: ed25519_dalek::SigningKey,
    device_id: DeviceId,
    own_master: IdentityPub,
    cluster_state: Option<Arc<Mutex<ClusterState>>>,
    /// Scales the freshness window (`challenge_max_age_secs`); 1 = production.
    time_scale: u64,
    /// How many answers read a share at once (K-b4, pos-i14): `HOLDER_POS_CONCURRENCY`
    /// permits, shared by the direct path (`Processor`) and the mailbox path.
    pos_slots: Arc<Semaphore>,
    /// Test seam (always `None` in production): called on the blocking thread before each
    /// symbol file is opened.
    read_hook: Option<ReadHook>,
}

/// Holder-side PoS answers that may read a share at the same time (pos-i14). Each holds one
/// symbol buffer (T) and a thread of the blocking pool for the whole read, so a hung data
/// directory (a NAS) takes at most this many threads, however many challenges arrive; the
/// rest wait as async tasks without a thread.
pub(crate) const HOLDER_POS_CONCURRENCY: usize = 2;

/// The semaphore of the holder's PoS answers: one per node, shared by every `PosResponder`.
pub(crate) fn new_pos_slots() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(HOLDER_POS_CONCURRENCY))
}

pub(crate) type ReadHook = Arc<dyn Fn(u32) + Send + Sync>;

/// What the blocking read-and-hash task ends with.
enum Answered {
    Hash([u8; 32]),
    /// The symbol file is gone; no hash of the rest goes out.
    Missing(u32),
}

/// Clock skew allowed between an owner's and a holder's clock when a challenge's age is
/// judged (not scaled: clocks drift in real seconds whatever the run's time_scale).
///
/// 10 minutes covers consumer machines that sync time rarely (drift of seconds to a few
/// minutes) with room to spare, and is negligible next to the 7-day TTL in production.
/// On the stand (time_scale 900: TTL 672 s) all nodes share one clock and the window is
/// 1272 s, still below the owner's scaled pending timeout (14 d 2 h / 900 ≈ 1353 s).
pub(crate) const POS_CHALLENGE_MAX_CLOCK_SKEW_SECS: u64 = 600;

/// Oldest challenge a holder still answers: the scaled challenge TTL (the owner's own
/// entry lives no longer at the postmen) plus `POS_CHALLENGE_MAX_CLOCK_SKEW_SECS`.
pub(crate) fn challenge_max_age_secs(time_scale: u64) -> u64 {
    viaticum_core::mailbox::scaled_ttl_secs(
        viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL.as_secs(),
        time_scale,
    ) + POS_CHALLENGE_MAX_CLOCK_SKEW_SECS
}

impl PosResponder {
    pub fn new(
        db: Db,
        holdings_dir: PathBuf,
        device_signing_key: ed25519_dalek::SigningKey,
        own_master: IdentityPub,
        cluster_state: Option<Arc<Mutex<ClusterState>>>,
    ) -> Self {
        let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
        PosResponder {
            db,
            holdings_dir,
            device_signing_key,
            device_id,
            own_master,
            cluster_state,
            time_scale: 1,
            pos_slots: new_pos_slots(),
            read_hook: None,
        }
    }

    /// Share the node's answer semaphore (`new_pos_slots`) with the other responders.
    pub(crate) fn with_pos_slots(mut self, pos_slots: Arc<Semaphore>) -> Self {
        self.pos_slots = pos_slots;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_read_hook(mut self, hook: ReadHook) -> Self {
        self.read_hook = Some(hook);
        self
    }

    /// Set the run's time_scale (the freshness window shrinks with it).
    pub fn with_time_scale(mut self, time_scale: u64) -> Self {
        self.time_scale = time_scale.max(1);
        self
    }

    /// Whether `device` is another device of our own master: in the device→master table
    /// or in the cluster state.
    fn is_sibling(&self, device: &DeviceId) -> Result<bool, ProcessorError> {
        if self
            .db
            .get_devices_for_master(&self.own_master)?
            .contains(device)
        {
            return Ok(true);
        }
        Ok(self.cluster_state.as_ref().is_some_and(|cs| {
            cs.lock()
                .map(|g| g.get_device(device).is_some())
                .unwrap_or(false)
        }))
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

        // pos-i5-a: a replay. The signature does not expire, so a postman could keep an
        // owner's old challenges and replay them after the holder's memory forgot them.
        // Answer only a challenge younger than the TTL + clock skew (the owner's own entry
        // lives only the TTL); an older one is dropped before any disk or DB work. A
        // challenge "from the future" (owner's clock ahead) is not judged here. The poll
        // remembers the drop as a no-answer, so this WARN comes once per quarter TTL.
        let age = Timestamp::now().0.saturating_sub(challenge.timestamp.0);
        let max_age = challenge_max_age_secs(self.time_scale);
        if age > max_age {
            warn!(
                block_id = %block_id,
                challenger = %owner_id,
                challenge_id = %hex_encode(&challenge.challenge_id),
                age_secs = age,
                max_age_secs = max_age,
                "processor: PosHashChallenge older than TTL + clock skew — dropping (replay)"
            );
            return Err(ProcessorError::StaleChallenge { age_secs: age });
        }

        // pos-i15: the challenge goes to our MASTER box, which every device of our master
        // reads; `device_id` (signed by the owner) names the one device whose placement is
        // challenged. Another device's challenge is not served: no Nack, no response, no
        // disk read — before the holding lookup, so even a sibling holding stale symbols
        // at the same ESIs cannot speak for the addressed device. A sibling's challenge is
        // `NotAddressedToThisDevice` (remembered until forgotten); a device we do not know
        // as a sibling is `NotAddressedToThisMaster` (junk, re-checked like a no-answer).
        if challenge.device_id != self.device_id {
            let sibling = self.is_sibling(&challenge.device_id)?;
            debug!(
                block_id = %block_id,
                challenger = %owner_id,
                challenge_id = %hex_encode(&challenge.challenge_id),
                addressed_device = %challenge.device_id,
                own_device = %self.device_id,
                sibling,
                "processor: PosHashChallenge addressed to another device — not answering"
            );
            return Err(if sibling {
                ProcessorError::NotAddressedToThisDevice
            } else {
                ProcessorError::NotAddressedToThisMaster
            });
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
                    &self.device_signing_key,
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

        // K-b4 (pos-i14): the share is read ONE symbol at a time into one reused buffer, hashed
        // on the spot, on a thread of the blocking pool — never the runtime's. At most
        // `HOLDER_POS_CONCURRENCY` answers read at once: the rest wait here, as async tasks
        // without a thread. The permit lives to the end of the blocking task.
        let permit = Arc::clone(&self.pos_slots)
            .acquire_owned()
            .await
            .map_err(|_| ProcessorError::Join("PoS answer semaphore closed".into()))?;

        // Expand ESI ranges to a sorted ESI list — bounded by `symbol_count()` (SM-1), so
        // `requested` is the exact size. Duplicates stay, as at the owner (`fold.rs`): a
        // duplicate is hashed once per occurrence (NOTE 1 v3.3).
        let mut esis: Vec<u32> = Vec::with_capacity(requested as usize);
        for &(start, count) in &challenge.esi_ranges {
            esis.extend(start..start + count);
        }
        esis.sort_unstable();

        let block_dir = self.holdings_dir.join(hex_encode(&block_id.0));
        let challenge_id = challenge.challenge_id;
        let hook = self.read_hook.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            hash_share(&block_dir, &challenge_id, &esis, hook)
        });
        let answered = task
            .await
            .map_err(|e| ProcessorError::Join(format!("PoS answer task: {e}")))??;
        let chain_hash = match answered {
            Answered::Hash(hash) => hash,
            Answered::Missing(esi) => {
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
                    &self.device_signing_key,
                )));
            }
        };

        // pos-i5: on the mailbox path this line comes once per challenge (the poll keeps
        // the answer in memory); the scenario counts it per `challenge_id`.
        debug!(
            block_id = %block_id,
            challenge_id = %hex_encode(&challenge.challenge_id),
            owner = %owner_id,
            "processor: PosHashChallenge — responding with chain hash"
        );
        // CS-ID-1 / pos-i16: sign the response with our DEVICE key so the owner accepts it
        // only for the placement on this device (not a postman's forgery, not a sibling's
        // answer, not anything signed with the master key alone).
        Ok(Message::PosHashResponse(build_pos_hash_response(
            challenge.challenge_id,
            block_id,
            chain_hash,
            Timestamp::now(),
            &self.device_signing_key,
        )))
    }
}

/// Read a symbol file into `buf`, at most T bytes: a longer file is a corrupted local file
/// (an error with a plain text, not a Nack: the holder does not claim to have lost it).
fn read_symbol(file: std::fs::File, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    let cap = u64::from(viaticum_core::constants::SYMBOL_SIZE);
    let n = file.take(cap + 1).read_to_end(buf)?;
    if n as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("symbol file is longer than the symbol size ({cap} bytes)"),
        ));
    }
    Ok(n)
}

/// The chain hash over `esis` (ascending, duplicates kept): each symbol file is read into
/// `buf` (cleared between symbols, so its capacity is T) and pushed into the hasher before the
/// next one is read. A missing file anywhere ends it `Missing`; any other IO error is `Err`.
fn hash_share(
    block_dir: &Path,
    challenge_id: &[u8; 16],
    esis: &[u32],
    hook: Option<ReadHook>,
) -> Result<Answered, ProcessorError> {
    let mut hasher = ChainHasher::new(challenge_id);
    let mut buf: Vec<u8> = Vec::new();
    for &esi in esis {
        if let Some(hook) = &hook {
            hook(esi);
        }
        buf.clear();
        let read = std::fs::File::open(block_dir.join(format!("{esi}.bin")))
            .and_then(|file| read_symbol(file, &mut buf));
        match read {
            Ok(_) => hasher.push(esi, &buf),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Answered::Missing(esi));
            }
            Err(e) => return Err(ProcessorError::Io(e)),
        }
    }
    hasher
        .finish()
        .map(Answered::Hash)
        .map_err(ProcessorError::PosVerify)
}

impl Processor {
    // ─── Hash-based PoS handlers ─────────────────────────────────────────────

    /// Holder side: receive PosHashChallenge, read all assigned symbols, compute
    /// chain hash, return PosHashResponse (or PosHashNack on missing symbols).
    ///
    /// Delegates to `PosResponder::compute_response` — the responder owns only
    /// the fields it needs, keeping the compute logic decoupled from the full
    /// Processor lifetime.
    pub(crate) async fn handle_pos_hash_challenge_inner(
        &self,
        owner_id: IdentityPub,
        challenge: viaticum_core::messages::PosHashChallengeMsg,
    ) -> Result<Message, ProcessorError> {
        let responder = PosResponder::new(
            self.db.clone(),
            self.holdings_dir.clone(),
            self.device_signing_key.clone(),
            self.own_identity,
            self.cluster_state.clone(),
        )
        .with_pos_slots(Arc::clone(&self.pos_slots));
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
/// `PosResponder` is constructed from the same db / holdings_dir / device key / master /
/// cluster state clones that are passed into Processor — no Arc<Processor> wrapping.
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
    ) -> anyhow::Result<PosChallengeAnswer> {
        // owner_master_pub = MailboxEntry.sender (the owner who sent the challenge).
        // Passed as owner_id to compute_response which uses it to look up our HoldingRecord.
        let challenge = match from_cbor_bytes::<PosHashChallengeMsg>(&payload) {
            Ok(c) => c,
            // An undecodable payload is junk (a postman's plant or a broken peer): a clean
            // drop like an unauthenticated challenge, so the poll remembers it as a
            // no-answer and re-checks it once per quarter TTL instead of logging an
            // error on every poll (pos-i5).
            Err(e) => {
                warn!(
                    challenger = %owner_master_pub,
                    err = %e,
                    "mailbox PoS: undecodable PosHashChallengeMsg — dropping"
                );
                return Ok(PosChallengeAnswer::NoAnswer);
            }
        };
        match self
            .responder
            .compute_response(owner_master_pub, challenge)
            .await
        {
            Ok(Message::PosHashResponse(response)) => Ok(PosChallengeAnswer::Respond(response)),
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
                Ok(PosChallengeAnswer::NoAnswer)
            }
            Ok(other) => {
                warn!(
                    msg_variant = ?std::mem::discriminant(&other),
                    "mailbox PoS: unexpected Message variant from compute_response"
                );
                Ok(PosChallengeAnswer::NoAnswer)
            }
            // pos-i15: a sibling device's challenge, already debug-logged. Not ours to
            // answer, and the addressee is signed: remembered until forgotten, no re-check.
            Err(ProcessorError::NotAddressedToThisDevice) => Ok(PosChallengeAnswer::NotMine),
            // A device we do not know as a sibling: may be a postman replaying someone
            // else's signed challenge into our box. A plain no-answer (junk cap, re-check).
            Err(ProcessorError::NotAddressedToThisMaster) => Ok(PosChallengeAnswer::NoAnswer),
            // CS-ID-5 / P1-2: an unauthenticated (forged/unsigned) challenge was already
            // logged inside compute_response. Treat it as a clean drop — no response is
            // published and the poll loop must NOT surface it as a handler error.
            Err(ProcessorError::UnauthenticatedChallenge) => Ok(PosChallengeAnswer::NoAnswer),
            // SM-1: an oversized/malformed challenge (sum of counts > what we hold, or a
            // range overflowing u32) was already warn-logged inside compute_response.
            // Same clean-drop treatment as UnauthenticatedChallenge.
            Err(ProcessorError::OversizedChallenge { .. }) => Ok(PosChallengeAnswer::NoAnswer),
            // pos-i5-a: a replay older than TTL + skew, already warn-logged.
            Err(ProcessorError::StaleChallenge { .. }) => Ok(PosChallengeAnswer::NoAnswer),
            Err(e) => Err(anyhow::anyhow!("pos challenge handler error: {e}")),
        }
    }
}
