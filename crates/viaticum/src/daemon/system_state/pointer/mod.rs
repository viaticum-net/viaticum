// The pointer publisher: two places per catalog history (CROWN-1 C3a, V.16.3-V.16.4,
// V.17; mailbox-i46, i47, i50..i56; dr-i48).
//
// State lives in META (`PointerPublications`), not in RAM: one record per place, each
// with the sealed envelope as sent. One tick:
//   1. build the pointer of the running base over its placed prefix;
//   2. a new envelope is needed when the running base is not the one in `current`
//      (compaction or restart → a NEW base), when the pointer changed structurally,
//      when the refresh interval (30 d / time_scale) elapsed, or when the last attempt
//      was refused by every postman as clock skew and nobody holds it;
//      - the same base → the same place (`current.place`);
//      - a new base → `place_for_new_base` (empty / unconfirmed / weaker base; never
//        by generation); the record it displaces goes to the new record's `to_retire`;
//      the record is written to META BEFORE the envelope is sent (a crash after the
//      send leaves it known, never retired by the startup sweep);
//   3. every other record with fewer than the dr-i39 number of acks re-offers its
//      envelope byte-identical (acks accumulate as distinct postmen); an expired
//      envelope is not re-offered;
//   4. a record with the dr-i39 number of acks retires its `to_retire`; SS blocks
//      outside META and the running candidate are retired (`sweep_ss_ledger`);
//   5. `waiting` is set while the newest catalog state is in no accepted pointer.
//
// The daemon never reads its pointer box (РС3.1): this state is what the node knows.

use std::path::Path;

use tracing::{debug, error, info, warn};
use viaticum_core::db::Db;
use viaticum_core::mailbox::seal::{PointerPlace, RendezvousKeys, seal_self_pointer};
use viaticum_core::mailbox::{MailboxEntry, class_config, scaled_ttl_secs};
use viaticum_core::system_state::SelfPointer;
use viaticum_core::system_state::catalog::{
    PlacePublication, PointerPublications, PointerRefusal, RefusalKind, RetiredPointer, Waiting,
    WaitingReason,
};
use viaticum_core::types::{SourceBlockId, Timestamp, from_cbor_bytes, hex_encode, to_cbor_bytes};

use super::publish::{self, PointerCatalog};
use super::strength::{place_for_new_base, readiness_ack_threshold, sweep_ss_ledger};
use super::{log_refusal, pointer_refresh_interval_secs};
use crate::daemon::mailbox::routing::{MailboxRouter, PublishOutcome, PublishVerdict};

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
        let threshold = match self.db.list_all_peers() {
            Ok(p) => readiness_ack_threshold(p.len()),
            Err(e) => {
                warn!(error = %e, "system_state push: cannot count peers; threshold 3");
                3
            }
        };

        // 1-2. A new envelope for the running base, when due.
        let mut fresh_place: Option<PointerPlace> = None;
        let mut fresh_accepted = false;
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
            if let Some(record) = self.seal_record(&pointer, running.base, place, now_secs) {
                install(&mut meta, record, running.base);
                if self.put(&meta) {
                    let outcome = self.send(meta.current.as_ref().expect("installed")).await;
                    let current = meta.current.as_mut().expect("installed");
                    fresh_accepted = !outcome.acks.is_empty();
                    self.log_fresh(current, &pointer, &outcome);
                    absorb(current, &outcome, now_secs);
                    fresh_place = Some(place);
                }
            }
        }

        // 3. Re-offer the other envelopes that lack the dr-i39 number of acks.
        for slot in [&mut meta.current, &mut meta.other] {
            let Some(record) = slot.as_mut() else {
                continue;
            };
            if Some(record.place) == fresh_place || record.acks.len() >= threshold {
                continue;
            }
            let Some((entry, sig)) = envelope(record) else {
                continue;
            };
            if entry.expires_at <= now_secs {
                continue;
            }
            let outcome = self.router.publish_detailed(entry, Some(sig)).await;
            absorb(record, &outcome, now_secs);
            debug!(
                place = ?record.place,
                acks = record.acks.len(),
                threshold,
                "system_state push: re-offered the pointer envelope"
            );
        }

        // 4. Retire what the records that reached the threshold displaced.
        for record in [meta.current.as_mut(), meta.other.as_mut()]
            .into_iter()
            .flatten()
        {
            if record.acks.len() >= threshold && !record.to_retire.is_empty() {
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
        // Nobody holds an envelope every postman refused as clock skew: re-seal it with
        // the (possibly corrected) clock instead of re-offering it forever.
        let clock_refused = c.acks.is_empty()
            && matches!(
                c.last_refusal,
                Some(PointerRefusal {
                    kind: RefusalKind::ClockSkew,
                    ..
                })
            );
        changed || refresh_due || clock_refused
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
        })
    }

    async fn send(&self, record: &PlacePublication) -> PublishOutcome {
        match envelope(record) {
            Some((entry, sig)) => self.router.publish_detailed(entry, Some(sig)).await,
            None => PublishOutcome::default(),
        }
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
/// `to_retire`. A new base → the record in its place (if any) is displaced into the new
/// record's `to_retire` (together with what that one was still to retire); if two
/// displaced bases would wait, the older is dropped from the list at once (its place was
/// replaced twice at the postmen, V.17.2) and the sweep retires it. The record of the
/// other place becomes `other`.
pub(crate) fn install(
    meta: &mut PointerPublications,
    mut record: PlacePublication,
    running_base: &SourceBlockId,
) {
    let same_base = meta
        .current
        .as_ref()
        .is_some_and(|c| c.base == *running_base && c.place == record.place);
    if same_base {
        let old = meta.current.take().expect("checked");
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

/// Merge one publication's answers into `record`.
pub(crate) fn absorb(record: &mut PlacePublication, outcome: &PublishOutcome, now_secs: u64) {
    for a in &outcome.acks {
        if !record.acks.contains(a) && record.acks.len() < MAX_ACKS_KEPT {
            record.acks.push(*a);
        }
    }
    record.last_refusal =
        refusal_of(outcome.verdict()).map(|kind| PointerRefusal { at: now_secs, kind });
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
