// The 4R SHADOW of a symbol offer (В-0b, 4r-i44, 4r-i50).
//
// Called from `handle_symbol_offer_inner` AFTER the old rule answered. It never delays or
// changes the reply: at most ONE shadow runs at a time, in a blocking task (it scans HOLDINGS
// and PAIR_LEDGER); when the slot is busy the offer's shadow is skipped and counted
// (`skipped_since_last` in the next logged offer shadow). Its only outputs are log lines
// (`four_r_log`); it writes nothing.
//
// The shadow re-reads HOLDINGS after the reply, so the owner's transfer may already have landed
// in the offer's OWN (owner, block) record. ONLY that one record is taken as it was at the
// decision (one point read on the reply path, only when the shadow runs): see
// `holdings_at_decision`. Every OTHER holding, the ledger and the latch are as they are at the
// shadow's re-read, not at the decision (a pressure tick or another transfer may have moved
// them in between); the log line is "4R on the state at the re-read, with the offer's own
// record as the old rule saw it".

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::{debug, warn};
use viaticum_core::db::{Db, DbError};
use viaticum_core::four_r::EvictPhase;
use viaticum_core::four_r_holder::{
    FourRParams, OfferIn, QuotaInputs, ShadowOffer, raw_offer_record, shadow_offer,
};
use viaticum_core::types::{HoldingRecord, IdentityPub, SourceBlockId, Timestamp, hex_encode};

use super::Processor;
use crate::daemon::four_r_log;

/// The raw numbers the old offer rule decided on (one read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OfferSnapshot {
    /// `total_holding_bytes` at the decision.
    pub held_bytes: u64,
    /// Free bytes of the data-dir filesystem at the decision.
    pub disk_free: u64,
}

/// Everything the blocking shadow task needs (owned, `'static`).
pub(super) struct OfferShadowJob {
    pub(super) db: Db,
    pub(super) own_master: IdentityPub,
    pub(super) p: FourRParams,
    pub(super) offer: OfferIn,
    pub(super) snap: OfferSnapshot,
    /// The offer's own (owner, block) holding as it was at the decision (`None`: none).
    pub(super) key_before: Option<HoldingRecord>,
    pub(super) soft: u64,
    pub(super) reserve: u64,
    pub(super) hard: u64,
    pub(super) old_accept: bool,
    pub(super) skipped: Arc<AtomicU64>,
}

/// HOLDINGS for the offer shadow: the re-read `holdings` as they are, except the offer's own
/// (owner, block) record, which is put back as it was at the decision (`key_before`; `None` ⇒
/// removed). Without this, a transfer that landed between the reply and the re-read would be
/// counted twice (`V_parked + V_offer`, and in `H`). Removing the record outright instead would
/// lose what existed BEFORE the offer: a notified record (Р-26 `NotifiedBlock` would never
/// fire) or the earlier symbols of a repair top-up.
pub(super) fn holdings_at_decision(
    mut holdings: Vec<HoldingRecord>,
    offer: &OfferIn,
    key_before: Option<HoldingRecord>,
) -> Vec<HoldingRecord> {
    holdings.retain(|h| !(h.owner_id == offer.owner && h.source_block_id == offer.block));
    holdings.extend(key_before);
    holdings
}

impl Processor {
    /// Launch the offer shadow, or skip it (counted) when the single slot is busy. Returns
    /// immediately either way.
    pub(crate) fn spawn_offer_shadow(
        &self,
        owner: IdentityPub,
        block: SourceBlockId,
        offer_bytes: u64,
        old_accept: bool,
        snap: &OfferSnapshot,
    ) {
        let permit = match self.shadow_offer_slot.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let n = self.shadow_offers_skipped.fetch_add(1, Ordering::Relaxed) + 1;
                debug!(
                    target: "viaticum::four_r",
                    owner = %hex_encode(&owner.0),
                    block_id = %hex_encode(&block.0),
                    skipped_since_last = n,
                    "four_r: offer shadow skipped (slot busy)"
                );
                return;
            }
        };
        // The offer's own record as the old rule saw it — read NOW, before the reply leaves
        // (after it, the owner's transfer may land in this very record).
        let key_before = match self.db.get_holding(&block, &owner) {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    target: "viaticum::four_r",
                    err = %e,
                    "four_r: offer shadow skipped (holding read failed) — reply unaffected"
                );
                return;
            }
        };
        let rt = match tokio::runtime::Handle::try_current() {
            Ok(rt) => rt,
            Err(e) => {
                warn!(
                    target: "viaticum::four_r",
                    err = %e,
                    "four_r: no runtime for the offer shadow — skipped, reply unaffected"
                );
                return;
            }
        };
        let job = OfferShadowJob {
            db: self.db.clone(),
            own_master: self.own_identity,
            p: self.four_r.clone(),
            offer: OfferIn {
                owner,
                block,
                offer_bytes,
            },
            snap: *snap,
            key_before,
            soft: self.soft_quota_bytes,
            reserve: self.disk_reserve_bytes,
            hard: self.hard_quota_bytes,
            old_accept,
            skipped: Arc::clone(&self.shadow_offers_skipped),
        };
        rt.spawn_blocking(move || {
            let _slot = permit; // released when the shadow is done
            if let Err(e) = run_offer_shadow(&job) {
                warn!(
                    target: "viaticum::four_r",
                    err = %e,
                    "four_r: offer shadow failed — reply unaffected"
                );
            }
        });
    }
}

/// One offer shadow: read HOLDINGS (the offer's own record as at the decision), the ledger and
/// the latch; decide as 4R would; log. Returns the decision (tests).
pub(super) fn run_offer_shadow(job: &OfferShadowJob) -> Result<ShadowOffer, DbError> {
    let holdings = holdings_at_decision(
        job.db.list_all_holdings()?,
        &job.offer,
        job.key_before.clone(),
    );
    let ledgers = job.db.list_pair_ledgers()?;
    let latch = job.db.get_four_r_phase()?;
    let quota = QuotaInputs::from_holdings(
        &holdings,
        job.snap.disk_free,
        job.soft,
        job.reserve,
        job.hard,
    );
    let phase = EvictPhase {
        evicting: latch.evicting,
    };
    let out = shadow_offer(
        &holdings,
        &ledgers,
        job.own_master,
        quota,
        phase,
        &job.offer,
        &job.p,
    );
    let now = Timestamp::now().0;
    four_r_log::log_offer(
        &job.offer,
        &out,
        job.old_accept,
        job.skipped.swap(0, Ordering::Relaxed),
    );
    four_r_log::log_record_with(|| {
        raw_offer_record(
            &holdings,
            &ledgers,
            job.own_master,
            quota,
            &job.offer,
            &job.p,
            &out,
            job.old_accept,
            job.snap.held_bytes,
            now,
        )
    });
    Ok(out)
}
