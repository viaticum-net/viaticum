// The 4R SHADOW of the pressure tick (В-0). Called from `check_pressure` AFTER
// `evaluate_pressure` and BEFORE the old path acts, over the SAME holdings snapshot, disk read
// and trust function. Its outputs are log lines (`four_r_log`) and its own latch row
// (`four_r_state`), nothing else: no holding, notice, drop or mailbox entry depends on it.
// Every error is reported to the caller, which logs a `warn!` and carries on with the old path
// (never `?` out of `check_pressure`).

use tracing::warn;
use viaticum_core::budget::PressureResult;
use viaticum_core::db::{Db, DbError};
use viaticum_core::four_r::EvictPhase;
use viaticum_core::four_r_holder::{
    FourRParams, HoldingKey, OldPlan, QuotaInputs, ShadowPressureInput, old_owner_order,
    raw_pressure_record, shadow_pressure_tick,
};
use viaticum_core::types::{FourRPhaseRecord, HoldingRecord, IdentityPub, Timestamp, hex_encode};

use crate::daemon::four_r_log;

/// Why a shadow tick was skipped (the old path is never affected).
#[derive(Debug, thiserror::Error)]
pub(crate) enum ShadowError {
    #[error("4R shadow db read/write: {0}")]
    Db(#[from] DbError),
}

/// The raw quota numbers of the tick, as `check_pressure` read them.
pub(crate) struct ShadowQuota {
    pub disk_free: u64,
    pub soft: u64,
    pub reserve: u64,
    pub hard: u64,
}

/// One shadow pressure tick over the old path's snapshot. See the module header.
#[allow(clippy::too_many_arguments)]
pub(crate) fn shadow_pressure(
    db: &Db,
    holdings: &[HoldingRecord],
    quota: ShadowQuota,
    own_master: IdentityPub,
    trust_fn: &dyn Fn(&IdentityPub) -> f64,
    now: Timestamp,
    result: &PressureResult,
    p: &FourRParams,
) -> Result<(), ShadowError> {
    let ledgers = db.list_pair_ledgers()?;
    let placements = db.list_all_placements()?;
    let peers = db.list_all_peers()?;
    let latch = db.get_four_r_phase()?;

    // The old path's plan, taken from its result before it acts (W-1): exactly what it will
    // then execute.
    let old_plan = OldPlan {
        pressure: result.pressure,
        immediate: result
            .immediate_evictions
            .iter()
            .map(|t| HoldingKey {
                source_block_id: t.source_block_id,
                owner_id: t.owner_id,
            })
            .collect(),
        notices: result
            .drop_notices
            .iter()
            .map(|t| HoldingKey {
                source_block_id: t.source_block_id,
                owner_id: t.owner_id,
            })
            .collect(),
    };
    let input = ShadowPressureInput {
        holdings,
        ledgers: &ledgers,
        placements: &placements,
        peers: &peers,
        own_master,
        quota: QuotaInputs::from_holdings(
            holdings,
            quota.disk_free,
            quota.soft,
            quota.reserve,
            quota.hard,
        ),
        phase_prev: EvictPhase {
            evicting: latch.evicting,
        },
        old_owner_order: old_owner_order(holdings, trust_fn, now.0),
        old_plan,
    };
    let tick = shadow_pressure_tick(&input, p);

    if tick.own_master_bytes > 0 {
        warn!(
            target: "viaticum::four_r",
            own_master = %hex_encode(&own_master.0),
            bytes = tick.own_master_bytes,
            "four_r: holdings of our own master are outside the 4R view"
        );
    }

    // Log the tick BEFORE its latch transition is persisted. An offer shadow reads the latch
    // row concurrently; if tick m+1 wrote its row first, an offer shadow could read the NEW
    // phase and log its record before tick m+1's record — and the replay, which lets an offer
    // carry only the phase of the last two LOGGED ticks, would flag a phase no logged tick had
    // yet produced (a false red). Logged first, an offer that sees the new latch is always
    // logged after the tick that set it.
    four_r_log::log_pressure_tick(&tick, &input.quota, &input.old_plan);
    four_r_log::log_record_with(|| raw_pressure_record(&input, p, &tick, now.0));

    // The latch row changes only on a transition (one writer: this tick). A tick with an
    // invalid measure never transitions (`tick_phase` freezes it, 4r-i66), so it writes nothing.
    if tick.decision.phase.evicting != latch.evicting {
        db.set_four_r_phase(&FourRPhaseRecord {
            evicting: tick.decision.phase.evicting,
            since: Some(now),
        })?;
    }
    Ok(())
}
