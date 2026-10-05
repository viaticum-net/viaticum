// The pointer publisher: two places per catalog history (CROWN-1 C3a, V.16.3-V.16.4,
// V.17; mailbox-i46, i47, i50..i56, i58, i59; dr-i48).
//
// State lives in META (`PointerPublications`), not in RAM: one record per place, each
// with the sealed envelope as sent. One tick:
//   1. build the pointer of the running base over its placed prefix;
//   2. a new envelope is needed when the running base is not the one in `current`
//      (compaction or restart → a NEW base), when the pointer changed structurally,
//      when the refresh interval (30 d / time_scale) elapsed, or when the last attempt
//      was refused by every postman as clock skew (or as expired in transit,
//      mailbox-i61) and nobody holds it;
//      - the same base → the same place (`current.place`);
//      - a new base → `place_for_new_base` (empty / unconfirmed / weaker base; never
//        by generation); the record it displaces goes to the new record's `to_retire`;
//      the record is written to META BEFORE the envelope is sent (a crash after the
//      send leaves it known, never retired by the startup sweep);
//      mailbox-i62: never a second envelope into a place within the second its last
//      one was sealed (`stored_at` has second granularity: the postmen would hold the
//      first and refuse the second as `Superseded`); the change waits one tick;
//   2b. every other record whose envelope was stored a refresh interval ago gets the
//      SAME signed pointer re-sealed with a new expiry (mailbox-i58); META is written
//      before any send and a failed write skips the whole tick (mailbox-i59);
//   3. every other record with fewer than the dr-i39 number of acks re-offers its
//      envelope byte-identical (acks accumulate as distinct postmen); an expired
//      envelope is not re-offered; every send returns once the dr-i39 number of
//      postmen acked or after 15 s (mailbox-i60);
//   4. a record with the dr-i39 number of acks retires its `to_retire`; SS blocks
//      outside META and the running candidate are retired (`sweep_ss_ledger`);
//   5. `waiting` is set while the newest catalog state is in no accepted pointer.
//
// dr-i52: an envelope replaced in its place with the same base (a diff, a refresh, a
// re-seal) is kept as the record's `reached` when it had the threshold; readiness
// counts it until the new envelope reaches the threshold. A new base in a place
// starts without it.
//
// The daemon never reads its pointer box (РС3.1): this state is what the node knows.

use std::path::Path;

use tracing::{debug, error, info, warn};
use viaticum_core::db::Db;
use viaticum_core::mailbox::seal::{
    PointerPlace, RendezvousKeys, open_self_pointer, seal_self_pointer,
};
use viaticum_core::mailbox::{MailboxEntry, class_config, scaled_ttl_secs};
use viaticum_core::system_state::SelfPointer;
use viaticum_core::system_state::catalog::{
    PlacePublication, PointerPublications, PointerRefusal, ReachedEnvelope, RefusalKind,
    RetiredPointer, Waiting, WaitingReason,
};
use viaticum_core::types::{
    DeviceId, SourceBlockId, Timestamp, from_cbor_bytes, hex_encode, to_cbor_bytes,
};

use super::publish::{self, PointerCatalog};
use super::strength::{KAD_NEAR_K, dr_ack_threshold, place_for_new_base, sweep_ss_ledger};
use super::{log_refusal, pointer_refresh_interval_secs};
use crate::daemon::mailbox::routing::{MailboxRouter, NearPeer, PublishOutcome, PublishVerdict};

#[cfg(test)]
mod tests;

/// Distinct acking postmen remembered per envelope.
const MAX_ACKS_KEPT: usize = 64;

/// What the push loop is building right now: the running base and all its diffs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RunningState<'a> {
    pub generation: u32,
    pub base: &'a SourceBlockId,
    /// Every diff of the running base, placed or not.
    pub diffs: &'a [SourceBlockId],
    pub catalog: PointerCatalog<'a>,
}

/// Publishes this history's pointer into its two places.
pub(crate) struct PointerPublisher<'a> {
    pub db: &'a Db,
    pub router: &'a MailboxRouter,
    pub master_key: &'a ed25519_dalek::SigningKey,
    pub rv: &'a RendezvousKeys,
    pub data_dir: &'a Path,
    pub time_scale: u64,
}

impl PointerPublisher<'_> {
    /// Daemon start (V.16.4 п.6): retire every SS block that is not in META. Runs
    /// before the first base of this process exists.
    pub(crate) fn startup_sweep(&self) {
        let meta = match self.db.pointer_publications() {
            Ok(m) => m,
            Err(e) => {
                error!(error = %e, "system_state push: cannot read pointer META; startup sweep skipped");
                return;
            }
        };
        match sweep_ss_ledger(self.db, self.data_dir, meta.as_ref(), None) {
            Ok(0) => {}
            Ok(n) => info!(
                retired = n,
                "system_state push: retired SS blocks of earlier processes not in any pointer place"
            ),
            Err(e) => error!(error = %e, "system_state push: startup sweep failed"),
        }
    }

    /// One tick of the pointer publisher (see the module header).
    pub(crate) async fn tick(&self, running: RunningState<'_>, now_secs: u64) {
        let lineage = running.catalog.lineage;
        let mut meta = match self.db.pointer_publications() {
            Ok(Some(m)) if m.lineage == lineage => m,
            Ok(Some(m)) => {
                warn!(meta = %m.lineage, db = %lineage, "system_state push: pointer META of another history — starting fresh");
                PointerPublications::new(lineage)
            }
            Ok(None) => PointerPublications::new(lineage),
            Err(e) => {
                error!(error = %e, "system_state push: cannot read pointer META; tick skipped");
                return;
            }
        };
        // dr-i63: the postmen DR asks — this tick's Kademlia lookup of the box; an
        // empty or failed lookup keeps the last set.
        let known_peers = match self.db.list_all_peers() {
            Ok(p) => p.len(),
            Err(e) => {
                warn!(error = %e, "system_state push: cannot count peers; threshold by the near set");
                0
            }
        };
        let near = self.refresh_kad_near(&mut meta, known_peers).await;
        let threshold = dr_ack_threshold(meta.kad_near.len(), known_peers);

        // 1-2. A new envelope for the running base, when due.
        let mut fresh: Option<SelfPointer> = None;
        if let Some(pointer) = self.build(&running, now_secs)
            && self.new_envelope_due(&meta, &pointer, running.base, now_secs)
        {
            let place = match meta.current.as_ref() {
                Some(c) if c.base == *running.base => c.place,
                _ => match place_for_new_base(self.db, &meta, now_secs, self.time_scale) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(error = %e, "system_state push: cannot choose a pointer place; tick skipped");
                        return;
                    }
                },
            };
            if sealed_this_second(&meta, place, now_secs) {
                debug!(
                    place = ?place,
                    "system_state push: this place got an envelope this second; the new one waits for the next tick (mailbox-i62)"
                );
            } else if let Some(record) = self.seal_record(&pointer, running.base, place, now_secs) {
                install(&mut meta, record, running.base, threshold);
                fresh = Some(pointer);
            }
        }
        let fresh_place = fresh
            .as_ref()
            .and_then(|_| meta.current.as_ref().map(|c| c.place));

        // 2b. mailbox-i58: every other record keeps a live envelope — the SAME signed
        // pointer re-sealed with a new stored_at / expires_at before it expires.
        let resealed = self.reseal_due(&mut meta, fresh_place, threshold, now_secs);

        // mailbox-i52, i59: META is on disk before anything leaves this tick; when it
        // cannot be written nothing is sent (no new envelope, no re-offer). A changed
        // Kademlia-near set is written with it (or by the write at the end of the tick).
        if (fresh.is_some() || resealed) && !self.put(&meta) {
            return;
        }
        let kad_near = meta.kad_near.clone();

        let mut fresh_accepted = false;
        if let Some(pointer) = fresh.as_ref() {
            let outcome = self
                .send(meta.current.as_ref().expect("installed"), threshold, &near)
                .await;
            let current = meta.current.as_mut().expect("installed");
            fresh_accepted = !outcome.acks.is_empty();
            self.log_fresh(current, pointer, &outcome);
            absorb(current, &outcome, &kad_near, now_secs);
        }

        // 3. Re-offer the other envelopes that lack the dr-i39 number of acks.
        for slot in [&mut meta.current, &mut meta.other] {
            let Some(record) = slot.as_mut() else {
                continue;
            };
            if Some(record.place) == fresh_place || record.near_acks(&kad_near) >= threshold {
                continue;
            }
            let Some((entry, sig)) = envelope(record) else {
                continue;
            };
            if entry.expires_at <= now_secs {
                continue;
            }
            let outcome = self
                .router
                .publish_pointer(entry, Some(sig), threshold, &near)
                .await;
            absorb(record, &outcome, &kad_near, now_secs);
            debug!(
                place = ?record.place,
                acks = record.acks.len(),
                near_acks = record.near_acks(&kad_near),
                threshold,
                "system_state push: re-offered the pointer envelope"
            );
        }

        // 4. Retire what the records that reached the threshold displaced. dr-i52: a
        // record at the threshold no longer needs the earlier envelope it kept; an
        // expired one is no longer held by the postmen.
        for record in [meta.current.as_mut(), meta.other.as_mut()]
            .into_iter()
            .flatten()
        {
            let reached_threshold = record.near_acks(&kad_near) >= threshold;
            if reached_threshold
                || record
                    .reached
                    .as_ref()
                    .is_some_and(|r| r.expires_at <= now_secs)
            {
                record.reached = None;
            }
            if reached_threshold && !record.to_retire.is_empty() {
                info!(
                    place = ?record.place,
                    bases = record.to_retire.len(),
                    "system_state push: displaced pointer bases retired (replacement reached the threshold)"
                );
                record.to_retire.clear();
            }
        }

        // 5. Waiting (mailbox-i54).
        update_waiting(&mut meta, &running, fresh_accepted, now_secs);

        // The sweep runs only once META (with every displaced base) is on disk.
        if self.put(&meta)
            && let Err(e) = sweep_ss_ledger(
                self.db,
                self.data_dir,
                Some(&meta),
                Some((running.base, running.diffs)),
            )
        {
            error!(error = %e, "system_state push: SS ledger sweep failed");
        }
    }

    /// The pointer of the running base over its placed prefix; `None` while the base
    /// has no live holder.
    fn build(&self, running: &RunningState<'_>, now_secs: u64) -> Option<SelfPointer> {
        match publish::build_pointer_for_placed(
            self.db,
            self.master_key,
            running.generation,
            running.base,
            running.diffs,
            Timestamp(now_secs),
            running.catalog,
        ) {
            Ok(Some(p)) => Some(p),
            Ok(None) => {
                debug!(base = %running.base, "system_state push: base not placed yet, skipping pointer");
                None
            }
            Err(e) => {
                error!(error = %e, "system_state push: build_pointer failed");
                None
            }
        }
    }

    fn new_envelope_due(
        &self,
        meta: &PointerPublications,
        pointer: &SelfPointer,
        base: &SourceBlockId,
        now_secs: u64,
    ) -> bool {
        let Some(c) = meta.current.as_ref().filter(|c| c.base == *base) else {
            return true; // a new base (compaction, restart, first publication)
        };
        let diffs: Vec<SourceBlockId> = pointer.diffs.iter().map(|d| d.block_id).collect();
        let changed = c.generation != pointer.generation || c.diffs != diffs;
        let refresh_due = now_secs.saturating_sub(c.created_at.0)
            >= pointer_refresh_interval_secs(self.time_scale);
        // Nobody holds an envelope every postman refused as clock skew, or as expired in
        // transit (mailbox-i61): re-seal it with the (possibly corrected) clock instead
        // of re-offering it forever.
        let clock_refused = c.acks.is_empty()
            && c.last_refusal
                .is_some_and(|r| r.expired || r.kind == RefusalKind::ClockSkew);
        changed || refresh_due || clock_refused
    }

    /// mailbox-i58: a record whose envelope was stored `pointer_refresh_interval` ago
    /// (or earlier) gets a new envelope with the SAME signed pointer — opened from its
    /// `entry_cbor`, sealed again with new `stored_at` / `expires_at`. The pointer is
    /// never rebuilt: a newer `created_at` would make an old state the head of the
    /// history for DR. Acks restart (they count holders of the newest envelope); the
    /// re-offer step sends it this tick. `skip` = the place sealed fresh this tick.
    /// dr-i52: the replaced envelope stays `reached` while it was at the threshold.
    fn reseal_due(
        &self,
        meta: &mut PointerPublications,
        skip: Option<PointerPlace>,
        threshold: usize,
        now_secs: u64,
    ) -> bool {
        let lineage = meta.lineage.0;
        let interval = pointer_refresh_interval_secs(self.time_scale);
        let kad_near = meta.kad_near.clone();
        let mut any = false;
        for slot in [&mut meta.current, &mut meta.other] {
            let Some(record) = slot.as_mut() else {
                continue;
            };
            if Some(record.place) == skip {
                continue;
            }
            let Some((entry, _)) = envelope(record) else {
                continue;
            };
            if now_secs.saturating_sub(entry.stored_at) < interval {
                continue;
            }
            let pointer_cbor = match open_self_pointer(self.rv, &entry) {
                Ok(b) => b,
                Err(e) => {
                    error!(place = ?record.place, error = %e, "system_state push: cannot open the stored pointer envelope; not re-sealed");
                    continue;
                }
            };
            let expires_at = now_secs
                + scaled_ttl_secs(class_config::SELF_POINTER_TTL.as_secs(), self.time_scale);
            let sealed = match seal_self_pointer(
                self.rv,
                &lineage,
                record.place,
                &pointer_cbor,
                expires_at,
                now_secs,
            ) {
                Ok(s) => s,
                Err(e) => {
                    error!(place = ?record.place, error = %e, "system_state push: cannot re-seal the stored pointer");
                    continue;
                }
            };
            record.reached = reached_of(record, &kad_near, threshold);
            record.entry_cbor = to_cbor_bytes(sealed.entry());
            record.target_sig = sealed
                .target_sig()
                .expect("a sealed pointer carries its store signature");
            record.acks.clear();
            record.last_refusal = None;
            info!(
                place = ?record.place,
                base = %record.base,
                created_at = record.created_at.0,
                previous_stored_at = entry.stored_at,
                expires_at,
                "system_state push: pointer envelope re-sealed (same pointer, new expiry)"
            );
            any = true;
        }
        any
    }

    /// Seal `pointer` into `place`; the record starts with no acks.
    fn seal_record(
        &self,
        pointer: &SelfPointer,
        base: &SourceBlockId,
        place: PointerPlace,
        now_secs: u64,
    ) -> Option<PlacePublication> {
        let blob = to_cbor_bytes(pointer);
        let expires_at =
            now_secs + scaled_ttl_secs(class_config::SELF_POINTER_TTL.as_secs(), self.time_scale);
        let sealed = match seal_self_pointer(
            self.rv,
            &pointer.catalog.lineage.0,
            place,
            &blob,
            expires_at,
            now_secs,
        ) {
            Ok(s) => s,
            Err(e) => {
                // Impossible by construction (≤ 5 holders, ≤ 4 short addresses, ≤ 20
                // diffs): skip the tick rather than publish anything else.
                error!(error = %e, pointer_bytes = blob.len(), "system_state push: cannot seal the pointer");
                return None;
            }
        };
        Some(PlacePublication {
            place,
            base: *base,
            diffs: pointer.diffs.iter().map(|d| d.block_id).collect(),
            generation: pointer.generation,
            created_at: pointer.created_at,
            files: pointer.catalog.files,
            acks: Vec::new(),
            entry_cbor: to_cbor_bytes(sealed.entry()),
            target_sig: sealed
                .target_sig()
                .expect("a sealed pointer carries its store signature"),
            last_refusal: None,
            to_retire: Vec::new(),
            reached: None,
        })
    }

    /// Publish `record`'s envelope to the trust-top and the Kademlia-near postmen
    /// (dr-i63); returns once every near postman answered (with none: at `need` acks,
    /// mailbox-i60).
    async fn send(
        &self,
        record: &PlacePublication,
        need: usize,
        near: &[NearPeer],
    ) -> PublishOutcome {
        match envelope(record) {
            Some((entry, sig)) => {
                self.router
                    .publish_pointer(entry, Some(sig), need, near)
                    .await
            }
            None => PublishOutcome::default(),
        }
    }

    /// dr-i63: look up the Kademlia-near peers of the box and keep them in META's
    /// `kad_near`. An empty or failed lookup keeps the last set (a lookup that found
    /// nobody does not make every place unready), and this tick sends to it without
    /// lookup addresses — the address book's (review W6). So does a POOR answer (fewer
    /// than half of `min(known peers, K)`, a node that sees 1-2 peers after a restart or
    /// on another network) while a set is kept: it would make readiness blink until the
    /// next tick; this tick then sends to the kept set and to the answer's peers (code
    /// review W-2). Returns this tick's near peers.
    async fn refresh_kad_near(
        &self,
        meta: &mut PointerPublications,
        known_peers: usize,
    ) -> Vec<NearPeer> {
        let kept = |meta: &PointerPublications| -> Vec<NearPeer> {
            meta.kad_near
                .iter()
                .map(|&device| NearPeer {
                    device,
                    addrs: Vec::new(),
                })
                .collect()
        };
        let near = match self.router.kad_near(&self.rv.address).await {
            Ok(near) => near,
            Err(e) => {
                warn!(error = %e, kept = meta.kad_near.len(), "system_state push: Kademlia lookup of the pointer box failed; the last near set is kept");
                return kept(meta);
            }
        };
        if near.is_empty() {
            debug!(
                kept = meta.kad_near.len(),
                "system_state push: Kademlia lookup of the pointer box found nobody; the last near set is kept"
            );
            return kept(meta);
        }
        let poor = near.len() < known_peers.min(KAD_NEAR_K).div_ceil(2);
        if poor && !meta.kad_near.is_empty() {
            info!(
                answer = near.len(),
                kept = meta.kad_near.len(),
                known_peers,
                "system_state push: poor Kademlia answer for the pointer box; the last near set is kept"
            );
            let mut out = near;
            for p in kept(meta) {
                if !out.iter().any(|q| q.device == p.device) {
                    out.push(p);
                }
            }
            return out;
        }
        let devices: Vec<DeviceId> = near.iter().map(|p| p.device).collect();
        let same = devices.len() == meta.kad_near.len()
            && devices.iter().all(|d| meta.kad_near.contains(d));
        if !same {
            let unknown = devices
                .iter()
                .filter(|d| matches!(self.db.get_peer(d), Ok(None)))
                .count();
            info!(
                size = devices.len(),
                left = meta
                    .kad_near
                    .iter()
                    .filter(|d| !devices.contains(d))
                    .count(),
                unknown_to_owner = unknown,
                "system_state push: pointer kad-near set"
            );
            meta.kad_near = devices;
        }
        near
    }

    fn log_fresh(
        &self,
        record: &PlacePublication,
        pointer: &SelfPointer,
        outcome: &PublishOutcome,
    ) {
        match outcome.verdict() {
            PublishVerdict::Stored { acks } => {
                debug!(
                    address = %hex_encode(&self.rv.address.0),
                    slot = %hex_encode(&self.rv.pointer_slot(&pointer.catalog.lineage.0, record.place)),
                    "system_state push: pointer box"
                );
                info!(
                    generation = pointer.generation,
                    base = %record.base,
                    diffs = pointer.diffs.len(),
                    pointer_bytes = to_cbor_bytes(pointer).len(),
                    base_holders = pointer.base.holders.len(),
                    ack_count = acks,
                    catalog_files = pointer.catalog.files,
                    lineage = %pointer.catalog.lineage,
                    place = ?record.place,
                    "system_state push: SelfPointer published via mailbox"
                );
            }
            verdict => log_refusal(verdict, pointer.generation, &record.base),
        }
    }

    fn put(&self, meta: &PointerPublications) -> bool {
        match self.db.put_pointer_publications(meta) {
            Ok(()) => true,
            Err(e) => {
                error!(error = %e, "system_state push: cannot write pointer META; nothing sent this tick");
                false
            }
        }
    }
}

/// Put a freshly sealed record into META as `current`.
///
/// Same base as `current` → it replaces `current` in its place and keeps its
/// `to_retire`; the replaced envelope becomes `reached` if it was at the threshold
/// (else the one it kept stays, dr-i52). A new base → the record in its place (if any) is displaced into the new
/// record's `to_retire` (together with what that one was still to retire); if two
/// displaced bases would wait, the older is dropped from the list at once (its place was
/// replaced twice at the postmen, V.17.2) and the sweep retires it. The record of the
/// other place becomes `other`.
pub(crate) fn install(
    meta: &mut PointerPublications,
    mut record: PlacePublication,
    running_base: &SourceBlockId,
    threshold: usize,
) {
    let same_base = meta
        .current
        .as_ref()
        .is_some_and(|c| c.base == *running_base && c.place == record.place);
    if same_base {
        let old = meta.current.take().expect("checked");
        record.reached = reached_of(&old, &meta.kad_near, threshold);
        record.to_retire = old.to_retire;
        meta.current = Some(record);
        return;
    }
    let mut kept: Option<PlacePublication> = None;
    for r in [meta.current.take(), meta.other.take()]
        .into_iter()
        .flatten()
    {
        if r.place == record.place {
            record.to_retire.extend(r.to_retire);
            record.to_retire.push(RetiredPointer {
                base: r.base,
                diffs: r.diffs,
            });
        } else {
            kept = Some(r);
        }
    }
    while record.to_retire.len() > 1 {
        let oldest = record.to_retire.remove(0);
        info!(
            place = ?record.place,
            base = %oldest.base,
            "system_state push: a place replaced twice before the threshold — its oldest base is retired now"
        );
    }
    meta.other = kept;
    meta.current = Some(record);
}

/// dr-i52: what an envelope being replaced in its place (same base) leaves for
/// readiness: itself when it reached the threshold, else the earlier one it kept.
fn reached_of(
    record: &PlacePublication,
    kad_near: &[DeviceId],
    threshold: usize,
) -> Option<ReachedEnvelope> {
    let near = record.near_acks(kad_near);
    if near < threshold {
        return record.reached.clone();
    }
    let (entry, _) = envelope(record)?;
    Some(ReachedEnvelope {
        diffs: record.diffs.clone(),
        generation: record.generation,
        created_at: record.created_at,
        files: record.files,
        acked: record.acks.clone(),
        expires_at: entry.expires_at,
    })
}

/// Merge one publication's answers into `record`. Late acks (after the publication
/// returned, mailbox-i60) are not merged: a record short of the threshold re-offers
/// the same envelope next tick (step 3) and the postman acks it again.
///
/// dr-i63: at `MAX_ACKS_KEPT`, a new ack of the Kademlia-near set takes the place of the
/// first ack from outside it (the near acks are what the threshold counts).
pub(crate) fn absorb(
    record: &mut PlacePublication,
    outcome: &PublishOutcome,
    kad_near: &[DeviceId],
    now_secs: u64,
) {
    for a in &outcome.acks {
        if record.acks.contains(a) {
            continue;
        }
        if record.acks.len() < MAX_ACKS_KEPT {
            record.acks.push(*a);
        } else if kad_near.contains(a)
            && let Some(i) = record.acks.iter().position(|x| !kad_near.contains(x))
        {
            record.acks.remove(i);
            record.acks.push(*a);
        }
    }
    record.last_refusal = refusal_of(outcome.verdict()).map(|kind| PointerRefusal {
        at: now_secs,
        kind,
        expired: outcome.all_expired(),
    });
}

fn refusal_of(verdict: PublishVerdict) -> Option<RefusalKind> {
    let n = |x: usize| u32::try_from(x).unwrap_or(u32::MAX);
    match verdict {
        PublishVerdict::Stored { .. } => None,
        PublishVerdict::AllClockSkew => Some(RefusalKind::ClockSkew),
        PublishVerdict::AllSuperseded => Some(RefusalKind::Superseded),
        PublishVerdict::AllSlotsFull => Some(RefusalKind::SlotsFull),
        PublishVerdict::MixedRefusal {
            clock,
            superseded,
            slots_full,
            other,
        } => Some(RefusalKind::Mixed {
            clock: n(clock),
            superseded: n(superseded),
            slots_full: n(slots_full),
            other: n(other),
        }),
        PublishVerdict::NoAck => Some(RefusalKind::NoAck),
    }
}

/// mailbox-i62: the envelope `place` holds in META was sealed at `now_secs`. A second,
/// different envelope with the same `stored_at` would be refused by every postman that
/// holds the first (`Superseded`, equal time) and would sit refused, re-offered as is,
/// until the next change. Only equality: a `stored_at` ahead of the clock is a clock
/// that went back (or an envelope refused as clock skew, i57) and is not held up here.
fn sealed_this_second(meta: &PointerPublications, place: PointerPlace, now_secs: u64) -> bool {
    meta.in_place(place)
        .and_then(envelope)
        .is_some_and(|(e, _)| e.stored_at == now_secs)
}

/// The record's envelope as sent (decoded from META).
fn envelope(record: &PlacePublication) -> Option<(MailboxEntry, [u8; 64])> {
    match from_cbor_bytes::<MailboxEntry>(&record.entry_cbor) {
        Ok(e) => Some((e, record.target_sig)),
        Err(e) => {
            error!(place = ?record.place, error = %e, "system_state push: the stored pointer envelope does not decode");
            None
        }
    }
}

/// mailbox-i54: the newest state (running base + every diff) is "in the network" when
/// `current` lists exactly it and a postman acked it, or when this tick's new envelope
/// was acked. Otherwise the wait starts (kept if already running) with its reason.
pub(crate) fn update_waiting(
    meta: &mut PointerPublications,
    running: &RunningState<'_>,
    fresh_accepted: bool,
    now_secs: u64,
) {
    let current_of_running = meta.current.as_ref().filter(|c| c.base == *running.base);
    let covered = current_of_running
        .is_some_and(|c| c.diffs.as_slice() == running.diffs && !c.acks.is_empty());
    if fresh_accepted || covered {
        meta.waiting = None;
        return;
    }
    let reason = match current_of_running.and_then(|c| c.last_refusal) {
        Some(PointerRefusal {
            kind: RefusalKind::NoAck,
            ..
        }) => WaitingReason::NoAck,
        Some(_) => WaitingReason::Refused,
        None => WaitingReason::BlocksNotPlaced,
    };
    let since = meta.waiting.map_or(now_secs, |w| w.since);
    meta.waiting = Some(Waiting { since, reason });
}
