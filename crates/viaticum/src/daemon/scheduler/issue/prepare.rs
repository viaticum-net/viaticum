// The work of one block in an issue tick: re-encode the source once and compute every
// holder's expected chain hash (pos-i7), then the signed entry of each challenge, stamped
// at its publish (pos-i7-a).

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{error, warn};
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::to_cbor;
use viaticum_core::types::{DeviceId, IdentityPub, SourceBlockId, SymbolPlacement, Timestamp};

use super::super::{PendingHashChallenge, Scheduler, random_challenge_id};

/// One challenge of a block, its expected answer computed.
pub(super) struct PreparedChallenge {
    pub(super) holder_id: DeviceId,
    challenge_id: [u8; 16],
    expected_chain_hash: [u8; 32],
    esi_ranges: Vec<(u32, u32)>,
}

impl Scheduler {
    /// Re-encode one block once and compute every holder's expected chain hash (pos-i7:
    /// the honest cost, 1× per block per tick). Empty when the block cannot be served
    /// this tick (logged).
    pub(super) async fn prepare_block(
        &self,
        block_id: SourceBlockId,
        holder_placements: &[&SymbolPlacement],
    ) -> Vec<PreparedChallenge> {
        if holder_placements.is_empty() {
            return Vec::new();
        }

        // Load source block data (retained SS blob, else rebuild from source files).
        let source_data = match self.load_source_block_data(&block_id).await {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    block_id = %block_id,
                    err = %e,
                    "scheduler: cannot load source block for PoS hash, skipping"
                );
                return Vec::new();
            }
        };

        let block_record = match self.db.get_source_block(&block_id) {
            Ok(Some(r)) => r,
            _ => {
                warn!(block_id = %block_id, "scheduler: source block record missing, skipping");
                return Vec::new();
            }
        };
        let params = block_record.erasure_params();

        // Compute union of all ESI ranges across all holders for this block.
        let mut all_esi_ranges: Vec<(u32, u32)> = Vec::new();
        for p in holder_placements {
            all_esi_ranges.extend_from_slice(&p.esi_ranges);
        }

        // Per-holder data for the spawn_blocking closure.
        let holder_data: Vec<(DeviceId, Vec<(u32, u32)>)> = holder_placements
            .iter()
            .map(|p| (p.holder_id, p.esi_ranges.clone()))
            .collect();

        // Generate challenge_ids BEFORE spawn_blocking so the OsRng nonce is committed
        // before compute_chain_hash runs. This binds expected_hash to this challenge_id.
        let challenge_ids: HashMap<DeviceId, [u8; 16]> = holder_data
            .iter()
            .map(|(holder_id, _)| (*holder_id, random_challenge_id()))
            .collect();
        let challenge_ids_clone = challenge_ids.clone();

        let encoder = Arc::clone(&self.encoder);
        let block_id_clone = block_id;

        // encode_raw once for the block, then compute per-holder chain hashes.
        #[allow(clippy::type_complexity)]
        let hash_results =
            tokio::task::spawn_blocking(move || -> Vec<(DeviceId, [u8; 32], Vec<(u32, u32)>)> {
                // Encode raw symbols for the union of all holders' ESI ranges.
                let mut raw_symbols: HashMap<u32, Vec<u8>> = HashMap::new();
                for &(start, count) in &all_esi_ranges {
                    if count == 0 {
                        continue;
                    }
                    match encoder.encode_raw(&source_data, &params, start, count) {
                        Ok(syms) => {
                            for sym in syms {
                                raw_symbols.insert(sym.esi, sym.data);
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                block_id = %block_id_clone,
                                "scheduler: encode_raw failed: {e}"
                            );
                            return vec![];
                        }
                    }
                }

                // Per-holder: apply binding, compute chain hash.
                let mut results = Vec::new();
                for (holder_id, esi_ranges) in &holder_data {
                    // Expand ranges to sorted ESI list.
                    let mut esis: Vec<u32> = esi_ranges
                        .iter()
                        .flat_map(|&(start, count)| start..start + count)
                        .collect();
                    esis.sort_unstable();

                    // Apply binding keystream and collect bound symbols.
                    let bound_pairs: Vec<(u32, Vec<u8>)> = esis
                        .iter()
                        .filter_map(|&esi| {
                            raw_symbols.get(&esi).map(|raw_data| {
                                let mut data = raw_data.clone();
                                let ks = viaticum_core::erasure::binding_keystream(
                                    &block_id_clone,
                                    holder_id,
                                    esi,
                                    data.len(),
                                );
                                for (d, k) in data.iter_mut().zip(ks.iter()) {
                                    *d ^= k;
                                }
                                (esi, data)
                            })
                        })
                        .collect();

                    let refs: Vec<(u32, &[u8])> = bound_pairs
                        .iter()
                        .map(|(esi, data)| (*esi, data.as_slice()))
                        .collect();

                    // Use the pre-generated challenge_id to seed the chain hash.
                    // Invariant: challenge_ids_clone is built from the same holder_data
                    // iterated here, so the key is always present. Falling back to a
                    // constant seed would silently bind chain_hash to a known value —
                    // expect() surfaces any future invariant violation immediately.
                    let cid = *challenge_ids_clone
                        .get(holder_id)
                        .expect("challenge_id always present: built from same holder_data");
                    match viaticum_core::pos::compute_chain_hash(&cid, &refs) {
                        Ok(hash) => results.push((*holder_id, hash, esi_ranges.clone())),
                        Err(e) => {
                            tracing::error!(
                                holder = %holder_id,
                                block_id = %block_id_clone,
                                "scheduler: chain hash failed: {e}"
                            );
                        }
                    }
                }
                results
            })
            .await;

        // CS-POS-8: a JoinError here means the blocking task panicked (e.g. the
        // `expect` inside it). `unwrap_or_default()` would silently swallow that and
        // skip the whole block with zero logs. Log it loudly and degrade gracefully —
        // treat it as "no hashes for this block this tick" rather than re-panicking the
        // scheduler task.
        let hash_results = match hash_results {
            Ok(results) => results,
            Err(join_err) => {
                error!(
                    block_id = %block_id,
                    err = %join_err,
                    "scheduler: PoS hash compute task failed (panicked or cancelled) — skipping block this tick"
                );
                return Vec::new();
            }
        };

        hash_results
            .into_iter()
            .map(
                |(holder_id, expected_chain_hash, esi_ranges)| PreparedChallenge {
                    holder_id,
                    challenge_id: challenge_ids[&holder_id],
                    expected_chain_hash,
                    esi_ranges,
                },
            )
            .collect()
    }

    /// The signed mailbox entry of one challenge and its pending record, both stamped
    /// with the time of this call — the moment the challenge is published (pos-i7-a).
    /// None when the challenge cannot be encoded (logged).
    pub(super) fn challenge_entry(
        &self,
        block_id: SourceBlockId,
        c: PreparedChallenge,
    ) -> Option<(MailboxEntry, PendingHashChallenge)> {
        let holder_master = self
            .db
            .get_master_for_device(&c.holder_id)
            .ok()
            .flatten()
            .map(|m| IdentityPub(m.0))
            .unwrap_or_else(|| IdentityPub(c.holder_id.0));

        let now = Timestamp::now();
        // CS-ID-5 / P1-2: sign the challenge with our master key so the holder can
        // authenticate it against MailboxEntry.sender before doing any disk work.
        let challenge_msg = viaticum_core::messages::build_pos_hash_challenge(
            c.challenge_id,
            block_id,
            c.esi_ranges.clone(),
            now,
            Some(c.holder_id),
            &self.signing_key,
        );
        let payload = match to_cbor(&challenge_msg) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    block_id = %block_id,
                    holder_id = %c.holder_id,
                    err = %e,
                    "scheduler: failed to encode PosHashChallenge"
                );
                return None;
            }
        };

        let ttl_secs = viaticum_core::mailbox::scaled_ttl_secs(
            viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL.as_secs(),
            self.config.time_scale,
        );
        let entry = MailboxEntry {
            target: MailboxAddress::for_master(&holder_master),
            msg_id: c.challenge_id,
            class: MailboxClass::PosChallenge,
            payload_version: 1,
            payload,
            expires_at: now.0 + ttl_secs,
            stored_at: now.0,
            // W-3: sender is our master_pub so holder knows where to publish the response.
            sender: Some(self.my_master_pub),
        };
        // CS-POS-3: capture the holder_master resolved above so the response is later
        // verified against the SAME key the challenge was addressed to — not a re-resolve
        // that may have degraded to device-pub by then.
        let challenge = PendingHashChallenge {
            source_block_id: block_id,
            holder_id: c.holder_id,
            esi_ranges: c.esi_ranges,
            expected_chain_hash: c.expected_chain_hash,
            issued_at: now,
            challenge_id: c.challenge_id,
            holder_master,
        };
        Some((entry, challenge))
    }
}
