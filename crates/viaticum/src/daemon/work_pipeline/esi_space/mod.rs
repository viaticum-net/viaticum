// ESI space of the owner's blocks, as the worker sees it (repair-i8, C-SP §2.6).
//
// Fresh ESIs of a block come from a cursor that never goes back (`esi_high_water`), so a
// block offered to very many devices, or lost and re-placed very often, can reach raptorq's
// limit of 2^24 numbers. There the worker offers only what is left (defer-not-refuse) and
// the block is "not repairable: ESI numbers used up" — visible in `status`
// (`blocks_esi_exhausted`) and the Dashboard, warned about once a real-time day per block.
// No reuse of old numbers (repair-i11, future, gated on a measurement).
//
// RAM only: recomputed on each plan of the block; empty after a restart until the worker
// plans the block again.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use viaticum_core::constants::MAX_ESI_EXCLUSIVE;
use viaticum_core::types::SourceBlockId;

#[cfg(test)]
mod tests;

/// Real time between two "not repairable" WARNs of one block (not scaled by `time_scale`).
pub(crate) const EXHAUSTED_WARN_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Above this cursor a block has used half its ESI space: one WARN per block, the signal to
/// measure for repair-i11.
pub(crate) const HALF_ESI_SPACE: u32 = MAX_ESI_EXCLUSIVE / 2;

/// Blocks the worker found out of ESI numbers, and the WARN bookkeeping.
#[derive(Debug, Default)]
pub struct EsiSpace {
    inner: Mutex<EsiSpaceInner>,
}

#[derive(Debug, Default)]
struct EsiSpaceInner {
    /// Not repairable now → when its last WARN was logged.
    exhausted: HashMap<SourceBlockId, Instant>,
    /// Blocks already warned about passing half the space.
    past_half: HashSet<SourceBlockId>,
}

/// What `note_plan` logged (for tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct EsiNotice {
    pub warned_exhausted: bool,
    pub warned_past_half: bool,
}

impl EsiSpace {
    /// Record one plan of `block`: `cut` — the plan wanted fresh numbers beyond 2^24 and got
    /// fewer (or none); `high_water` — the block's cursor after the plan.
    pub(crate) fn note_plan(
        &self,
        block: SourceBlockId,
        cut: bool,
        high_water: u32,
        now: Instant,
    ) -> EsiNotice {
        let mut notice = EsiNotice::default();
        let Ok(mut inner) = self.inner.lock() else {
            tracing::error!("work_pipeline: ESI space mutex poisoned; block not recorded");
            return notice;
        };
        if high_water > HALF_ESI_SPACE && inner.past_half.insert(block) {
            tracing::warn!(
                block_id = %block,
                high_water,
                limit = MAX_ESI_EXCLUSIVE,
                "work_pipeline: ESI cursor past half of the ESI space for block"
            );
            notice.warned_past_half = true;
        }
        if !cut {
            inner.exhausted.remove(&block);
            return notice;
        }
        let due = inner
            .exhausted
            .get(&block)
            .is_none_or(|last| now.saturating_duration_since(*last) >= EXHAUSTED_WARN_INTERVAL);
        if due {
            tracing::warn!(
                block_id = %block,
                high_water,
                limit = MAX_ESI_EXCLUSIVE,
                "work_pipeline: ESI space exhausted for block — not repairable"
            );
            inner.exhausted.insert(block, now);
            notice.warned_exhausted = true;
        }
        notice
    }

    /// Blocks not repairable now (ESI space used up), in no particular order.
    pub fn exhausted_blocks(&self) -> Vec<SourceBlockId> {
        match self.inner.lock() {
            Ok(inner) => inner.exhausted.keys().copied().collect(),
            Err(_) => {
                tracing::error!("work_pipeline: ESI space mutex poisoned; reporting none");
                Vec::new()
            }
        }
    }
}
