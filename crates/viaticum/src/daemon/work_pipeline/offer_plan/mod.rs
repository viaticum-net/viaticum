// Offer plan for one block: which holders get offers and which ESIs each one gets.
//
// The allocation (`compute_allocation_with_importance`) decides per-holder counts; this
// module turns the counts into ESI ranges (repair-i9, the "reject" part):
//
//   - a device that already has an `Offered` row of this block — left there by a
//     `SymbolReject` (QuotaExceeded is normal in a greedy network) or by a delivery that did
//     not finish — gets its OWN range(s) back. Same (block, device) binding → same bytes; at
//     the holder a repeated ESI is idempotent (`processor/symbol.rs`: a rejected offer stores
//     nothing, an accepted one replaces the entry for `(device, block)`, an already-held ESI
//     is answered `Stored` and never counted twice);
//   - only the part of the share the own range does not cover comes as fresh numbers from
//     the cursor;
//   - condition: no row of ANOTHER device (any status) overlaps the own range; otherwise the
//     device gets fresh numbers for its whole share.
//
// So repeated rejects no longer move the cursor: cursor ≤ namespace start + Σ over distinct
// devices of their largest share. Before this, every tick (30 s cooldown after an offer)
// planned all shares from the cursor again and a block every peer refused ran into raptorq's
// `assert!(esi < 2^24)` within hours.
//
// Out of scope (slice C-SP K1b): the same rule for every row status (`Lost`, `Deleting`), a
// persistent `esi_high_water`, and the path at the ESI ceiling.

use std::sync::{Arc, Mutex};

use viaticum_core::cluster::{ClusterState, esi_namespace_start};
use viaticum_core::db::Db;
use viaticum_core::erasure::binding_seed;
use viaticum_core::placement::{
    HolderAllocation, HolderCandidate, PlacementError, compute_allocation_with_importance,
};
use viaticum_core::types::{
    DeviceId, Event, EventEntry, PlacementStatus, SourceBlockRecord, SymbolPlacement, Timestamp,
};

use super::worker::{ExcludedHolders, get_existing_holder_ids, resolve_primary_file_id};

#[cfg(test)]
mod tests;

/// One holder's offer in a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlannedOffer {
    pub device_id: DeviceId,
    /// Symbols the allocation wanted for this holder.
    pub share: u32,
    /// ESI ranges offered: ascending, disjoint, merged. At least `share` symbols — an own
    /// range larger than the share is kept whole (see `assign_esi_ranges`).
    pub esi_ranges: Vec<(u32, u32)>,
}

/// Result of planning one block.
#[derive(Debug)]
pub(crate) enum OfferPlan {
    /// Every pool peer holds the block or awaits a PoS verdict (repair-i2).
    NoCandidates(ExcludedHolders),
    /// The allocation came back empty.
    EmptyAllocation,
    /// The allocation failed.
    AllocationFailed(PlacementError),
    /// Offers to send; `cursor` is where fresh numbers started.
    Planned {
        cursor: u32,
        offers: Vec<PlannedOffer>,
    },
}

/// Start of this device's ESI namespace: `device_index · 2^20` in a cluster, else 0.
pub(crate) fn namespace_start(
    cluster_state: Option<&Arc<Mutex<ClusterState>>>,
    device_id: &DeviceId,
) -> u32 {
    cluster_state
        .and_then(|cs| {
            cs.lock()
                .ok()
                .and_then(|guard| guard.get_device(device_id).map(|e| e.device_index))
        })
        .map(esi_namespace_start)
        .unwrap_or(0)
}

/// Next fresh ESI: max end over EVERY row of the block, whatever its status, never below the
/// namespace (repair-i8). A `Lost`/`Deleting` row counts too: its holder may still have those
/// ESIs on disk (a PoS `Fail` leaves the bad bytes there, a DropNotice holds until its
/// deadline), so its numbers must not come back as "fresh" — to another device, or to the same
/// one (repair-i10: a device with a `Lost` row gets fresh numbers only; `reusable_own_ranges`
/// reuses `Offered` rows alone). Before, a `Fail` on the TOP range dropped the cursor onto it,
/// repair re-offered the same ESIs to the same holder, the holder answered "already held" by
/// file length and the placement went back to `Alive` with the bad symbol: a Fail→Lost→Alive
/// loop, never healed. Residual (C-SP K1b): a removed row takes its range out of the cursor —
/// a persistent `esi_high_water` closes that.
pub(crate) fn esi_cursor(placements: &[SymbolPlacement], namespace_start: u32) -> u32 {
    placements
        .iter()
        .flat_map(|p| p.esi_ranges.iter())
        .map(|(start, count)| start.saturating_add(*count))
        .max()
        .unwrap_or(0)
        .max(namespace_start)
}

/// Plan the offers of one block for this pool: exclude holders that hold or may hold it
/// (repair-i2), allocate, assign ESI ranges (repair-i9). Reads the DB, writes nothing.
pub(crate) fn plan_offers(
    db: &Db,
    block: &SourceBlockRecord,
    pool: &[HolderCandidate],
    namespace_start: u32,
) -> anyhow::Result<OfferPlan> {
    let placements = db.list_placements_for_block(&block.block_id)?;
    let cursor = esi_cursor(&placements, namespace_start);

    let excluded = get_existing_holder_ids(db, &block.block_id)?;
    let candidates: Vec<HolderCandidate> = pool
        .iter()
        .filter(|c| !excluded.ids.contains(&c.device_id))
        .cloned()
        .collect();
    if candidates.is_empty() {
        return Ok(OfferPlan::NoCandidates(excluded));
    }

    let allocations = match compute_allocation_with_importance(
        &candidates,
        block.encrypted_size.unwrap_or(0),
        block.importance,
        cursor,
    ) {
        Ok(a) if a.is_empty() => return Ok(OfferPlan::EmptyAllocation),
        Ok(a) => a,
        Err(e) => return Ok(OfferPlan::AllocationFailed(e)),
    };

    Ok(OfferPlan::Planned {
        cursor,
        offers: assign_esi_ranges(&allocations, &placements, cursor),
    })
}

/// ESI ranges for each allocation (repair-i9, reject part). Only `device_id` and
/// `symbol_count` of an allocation are used; its `start_esi` is replaced.
///
/// A device with a reusable own range (`reusable_own_ranges`) gets it back first, then fresh
/// numbers for the rest of its share. An own range LARGER than the share is kept whole, not
/// narrowed (repair-i9-a): the row is the device's reservation, and a narrowed row would burn
/// fresh numbers again every time the share swings back up — the cut part is no longer in any
/// row, so it cannot come back to the device (a persistent `esi_high_water` would not change
/// that). Cost: the offer can exceed the share (more QuotaFull in a greedy network, extra
/// symbols if accepted). The real fix — offer a subset of the reservation, narrow the row on
/// `Offered→Alive` — is tracked in private tech-debt «Повтор оффера несёт весь
/// зарезервированный диапазон» (2026-09-30).
pub(crate) fn assign_esi_ranges(
    allocations: &[HolderAllocation],
    placements: &[SymbolPlacement],
    cursor: u32,
) -> Vec<PlannedOffer> {
    let mut next_fresh = cursor;
    allocations
        .iter()
        .map(|alloc| {
            let mut ranges = reusable_own_ranges(&alloc.device_id, placements).unwrap_or_default();
            let own: u32 = ranges.iter().map(|&(_, count)| count).sum();
            if alloc.symbol_count > own {
                let fresh = alloc.symbol_count - own;
                ranges.push((next_fresh, fresh));
                next_fresh = next_fresh.saturating_add(fresh);
            }
            PlannedOffer {
                device_id: alloc.device_id,
                share: alloc.symbol_count,
                esi_ranges: merge_ranges(ranges),
            }
        })
        .collect()
}

/// The device's own ranges from its `Offered` row of this block, if no row of another
/// device overlaps them.
fn reusable_own_ranges(
    device_id: &DeviceId,
    placements: &[SymbolPlacement],
) -> Option<Vec<(u32, u32)>> {
    let own = placements
        .iter()
        .find(|p| p.holder_id == *device_id && p.status == PlacementStatus::Offered)?;
    let ranges = merge_ranges(own.esi_ranges.clone());
    if ranges.is_empty() {
        return None;
    }
    let overlapped = placements
        .iter()
        .filter(|p| p.holder_id != *device_id)
        .any(|p| ranges_overlap(&ranges, &p.esi_ranges));
    (!overlapped).then_some(ranges)
}

fn ranges_overlap(a: &[(u32, u32)], b: &[(u32, u32)]) -> bool {
    a.iter().any(|&(a_start, a_count)| {
        b.iter().any(|&(b_start, b_count)| {
            let (a_start, a_end) = (u64::from(a_start), u64::from(a_start) + u64::from(a_count));
            let (b_start, b_end) = (u64::from(b_start), u64::from(b_start) + u64::from(b_count));
            a_count > 0 && b_count > 0 && a_start < b_end && b_start < a_end
        })
    })
}

/// Sort, drop empty ranges, merge overlapping and adjacent ones.
fn merge_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.retain(|&(_, count)| count > 0);
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (start, count) in ranges {
        let end = start.saturating_add(count);
        match merged.last_mut() {
            Some((m_start, m_count)) if start <= m_start.saturating_add(*m_count) => {
                let m_end = m_start.saturating_add(*m_count).max(end);
                *m_count = m_end - *m_start;
            }
            _ => merged.push((start, count)),
        }
    }
    merged
}

/// Every ESI the plan needs, ascending and merged — what to encode (once) for this plan.
pub(crate) fn union_ranges(offers: &[PlannedOffer]) -> Vec<(u32, u32)> {
    merge_ranges(
        offers
            .iter()
            .flat_map(|o| o.esi_ranges.iter().copied())
            .collect(),
    )
}

/// Write the plan's rows as `Offered` (one txn) plus a `SymbolsPlaced` event per range.
/// Overwrites the holder's previous non-may-hold row of this block (repair-i2 keeps
/// `Alive`/`Uncertain`/`PresumedLost` holders out of the plan).
pub(crate) fn record_offers(
    db: &Db,
    owner_device: DeviceId,
    block: &SourceBlockRecord,
    offers: &[PlannedOffer],
    now: Timestamp,
) -> anyhow::Result<()> {
    let file_id = resolve_primary_file_id(db, block)?;
    let mut txn = db.write_txn()?;
    for offer in offers {
        txn.upsert_placement(&SymbolPlacement {
            source_block_id: block.block_id,
            holder_id: offer.device_id,
            file_id,
            esi_ranges: offer.esi_ranges.clone(),
            binding_seed: binding_seed(&block.block_id, &offer.device_id),
            status: PlacementStatus::Offered,
            last_verified: None,
            placed_at: now,
            consecutive_misses: 0,
        })?;
        for &esi_range in &offer.esi_ranges {
            txn.append_event(&EventEntry {
                timestamp: now,
                device_id: owner_device,
                event: Event::SymbolsPlaced {
                    source_block_id: block.block_id,
                    holder_id: offer.device_id,
                    esi_range,
                },
            })?;
        }
    }
    txn.commit()?;
    Ok(())
}
