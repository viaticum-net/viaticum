// DR: collect every pointer of the identity from its rendezvous box (CROWN-1 C3a,
// V.3, V.15.2, V.17.3).
//
// The box address and every key come from the phrase (`RendezvousKeys`); nothing on
// this path reads the local clock. The walk does NOT go through `MailboxRouter::poll`:
// poll drops entries with `expires_at <= now` by the local clock and collapses copies
// by `msg_id` before opening, which would hide a pointer from a DR machine whose clock
// is wrong and hide the older versions of one place held by lagging postmen. Here every
// SelfPointer entry of every answer is opened, decoded and verified; duplicates are
// dropped only by the pointer's own signature, after verification.

use std::sync::Arc;

use tracing::{debug, warn};
use viaticum_core::constants::MAILBOX_DR_WALK_BATCHES;
use viaticum_core::mailbox::seal::{RendezvousKeys, open_self_pointer};
use viaticum_core::mailbox::{MailboxClass, MailboxEntry};
use viaticum_core::messages::{MAILBOX_WIRE_VERSION, MailboxFetchRequest};
use viaticum_core::system_state::{SelfPointer, verify_self_pointer};
use viaticum_core::types::{DeviceId, IdentityPub, from_cbor_bytes, hex_encode};

use super::MailboxRouter;

/// What `MailboxRouter::dr_collect_pointers` found.
#[derive(Debug, Clone)]
pub struct DrWalk {
    /// Every distinct (by signature) verified SelfPointer of the identity, with the
    /// `msg_id` (= pointer place slot) of the entry it was opened from.
    pub pointers: Vec<([u8; 16], SelfPointer)>,
    /// Peers the walk could ask (0 = no peer known at all).
    pub candidates: usize,
    /// Peers that answered the fetch.
    pub responders: usize,
}

impl MailboxRouter {
    /// DR: collect EVERY verified SelfPointer of `my_master_pub` from the rendezvous box
    /// `rv.address` (CS-DR-1, mailbox-i43).
    ///
    /// Candidates are the DB peers ranked by XOR distance to the box (closest first),
    /// queried in the expanding batches of `MAILBOX_DR_WALK_BATCHES` ([100, 300, 1000]).
    /// Each peer is asked at most once; a batch that adds no new peer ends the walk.
    /// There is no early exit: a fresher pointer, the other place of a history, or
    /// another history of the same phrase may sit in a later batch. Choosing is the
    /// caller's job (`select_catalog`, then the place order of the attempts).
    ///
    /// Every fetch carries `rv.fetch_proof(my_device)` (the postman serves only the
    /// SelfPointer entries of a proof-gated box). An entry that does not open, decode
    /// or verify is logged (`mailbox: open failed` with its hex `msg_id`) and skipped.
    pub async fn dr_collect_pointers(
        &self,
        rv: &RendezvousKeys,
        my_master_pub: &IdentityPub,
        my_device: &DeviceId,
    ) -> anyhow::Result<DrWalk> {
        let ranked = self.build_ranked_candidates(&rv.address);
        let max_batch = MAILBOX_DR_WALK_BATCHES.last().copied().unwrap_or(0);
        let candidates = ranked.len().min(max_batch);
        tracing::info!(
            ranked_candidates = ranked.len(),
            candidates,
            "dr_walk: candidates built from DB"
        );

        let req = MailboxFetchRequest {
            v: MAILBOX_WIRE_VERSION,
            target: rv.address,
            since_stored_at: None,
            target_proof: Some(rv.fetch_proof(my_device)),
        };

        let mut pointers: Vec<([u8; 16], SelfPointer)> = Vec::new();
        let mut seen_sigs: std::collections::HashSet<[u8; 64]> = std::collections::HashSet::new();
        let mut responders = 0usize;
        let mut prev_len = 0usize;

        for &batch_size in MAILBOX_DR_WALK_BATCHES {
            let end = batch_size.min(ranked.len());
            if end <= prev_len {
                tracing::info!(
                    batch_size,
                    queried = prev_len,
                    "dr_walk: no new candidates for this batch, walk complete"
                );
                break;
            }
            let batch: Vec<DeviceId> = ranked[prev_len..end].iter().map(|(d, _)| *d).collect();
            prev_len = end;
            tracing::info!(
                batch_size,
                peers = batch.len(),
                "dr_walk: sending fetch to batch"
            );

            let mut handles = Vec::with_capacity(batch.len());
            for device_id in batch {
                let sender = Arc::clone(&self.sender);
                let req_clone = req.clone();
                handles.push(tokio::spawn(async move {
                    (device_id, sender.send_fetch(device_id, req_clone).await)
                }));
            }

            for handle in handles {
                match handle.await {
                    Ok((device_id, Ok(resp))) => {
                        responders += 1;
                        tracing::info!(
                            device = %device_id,
                            entries = resp.entries.len(),
                            "dr_walk: fetch response from peer"
                        );
                        super::record_avail_contact(&self.db, device_id, unix_now());
                        for entry in &resp.entries {
                            if let Some(p) = open_pointer(rv, my_master_pub, &device_id, entry)
                                && seen_sigs.insert(p.signature)
                            {
                                pointers.push((entry.msg_id, p));
                            }
                        }
                    }
                    Ok((device_id, Err(e))) => {
                        tracing::info!(device = %device_id, err = %e, "dr_walk: fetch failed for peer");
                    }
                    Err(join_err) => {
                        warn!("dr_walk: task panicked: {join_err}");
                    }
                }
            }
        }

        tracing::info!(
            candidates,
            responders,
            pointers = pointers.len(),
            "dr_walk: collection complete"
        );
        Ok(DrWalk {
            pointers,
            candidates,
            responders,
        })
    }
}

/// Open, decode and verify one entry of a rendezvous-box answer. `None` (logged) for
/// anything that is not a valid pointer of this identity. No clock check.
fn open_pointer(
    rv: &RendezvousKeys,
    my_master_pub: &IdentityPub,
    device_id: &DeviceId,
    entry: &MailboxEntry,
) -> Option<SelfPointer> {
    if entry.class != MailboxClass::SelfPointer {
        return None;
    }
    let body = match open_self_pointer(rv, entry) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                device = %device_id,
                msg_id = %hex_encode(&entry.msg_id),
                class = ?entry.class,
                err = %e,
                "mailbox: open failed"
            );
            return None;
        }
    };
    let pointer = match from_cbor_bytes::<SelfPointer>(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                device = %device_id,
                msg_id = %hex_encode(&entry.msg_id),
                err = %e,
                "dr_walk: opened entry is not a SelfPointer"
            );
            return None;
        }
    };
    if verify_self_pointer(&pointer, my_master_pub).is_err() {
        warn!(
            device = %device_id,
            msg_id = %hex_encode(&entry.msg_id),
            "dr_walk: pointer signature verification failed"
        );
        return None;
    }
    debug!(
        device = %device_id,
        msg_id = %hex_encode(&entry.msg_id),
        generation = pointer.generation,
        created_at = pointer.created_at.0,
        "mailbox: opened entry"
    );
    Some(pointer)
}

/// Wall clock for the avail observation only (never a filter on this path).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
