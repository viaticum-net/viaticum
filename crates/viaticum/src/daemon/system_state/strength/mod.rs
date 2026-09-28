// How well an SS block is stored, which pointer place a new base takes, and which SS
// blocks the owner keeps (CROWN-1 V.16.3-V.16.4, V.17.1-V.17.5; mailbox-i50, i56;
// dr-i41, dr-i48, dr-i49).
//
// Strength of a block = live symbols / k_eff. A placement is live when its status may
// hold symbols AND its holder was seen within `W = 7 days / time_scale`. SS blocks get
// no PoS (Bug-B), so `last_seen` is the only signal that a holder is still there; it is
// an estimate, not a proof of storage (a holder that is online but silently lost its
// symbols counts as live). The same function is the DR readiness estimator (dr-i49).

use std::collections::HashSet;

use viaticum_core::constants::DECODE_OVERHEAD;
use viaticum_core::db::{Db, DbError};
use viaticum_core::mailbox::scaled_ttl_secs;
use viaticum_core::mailbox::seal::PointerPlace;
use viaticum_core::system_state::catalog::{PlacePublication, PointerPublications};
use viaticum_core::types::SourceBlockId;

#[cfg(test)]
mod tests;

/// A holder not seen for this long (divided by time_scale) no longer counts (V.17.1).
pub(crate) const HOLDER_SEEN_WINDOW_SECS: u64 = 7 * 24 * 3600;

/// dr-i39: distinct postmen that must hold the pointer for "DR ready", and until which
/// the same envelope is re-offered (i47): 3; in a circle of fewer than 6 known peers,
/// half of the others (rounded up), at least 1.
pub(crate) fn readiness_ack_threshold(known_peers: usize) -> usize {
    if known_peers >= 6 {
        3
    } else {
        known_peers.div_ceil(2).max(1)
    }
}

/// `W` of V.17.1 at this time scale.
pub(crate) fn holder_seen_window_secs(time_scale: u64) -> u64 {
    scaled_ttl_secs(HOLDER_SEEN_WINDOW_SECS, time_scale)
}

/// live symbols / k_eff of one block (0 for a block without a record).
pub(crate) fn block_strength(
    db: &Db,
    block: &SourceBlockId,
    now_secs: u64,
    time_scale: u64,
) -> Result<f64, DbError> {
    let Some(record) = db.get_source_block(block)? else {
        return Ok(0.0);
    };
    let k_eff = record.k.saturating_add(DECODE_OVERHEAD).max(1);
    let seen_after = now_secs.saturating_sub(holder_seen_window_secs(time_scale));
    let mut live: u64 = 0;
    for p in db.list_placements_for_block(block)? {
        if !p.status.may_hold_symbols() {
            continue;
        }
        let seen = db
            .get_peer(&p.holder_id)?
            .is_some_and(|peer| peer.last_seen.0 >= seen_after);
        if seen {
            live += u64::from(p.symbol_count());
        }
    }
    Ok(live as f64 / f64::from(k_eff))
}

/// Strength of a pointer: the weakest of its blocks (base and every diff). Used for DR
/// readiness (dr-i41: every block of the accepted pointer must be recoverable).
// `status` reads it from the next commit on ([cross:C] dispatch).
#[allow(dead_code)]
pub(crate) fn pointer_strength(
    db: &Db,
    base: &SourceBlockId,
    diffs: &[SourceBlockId],
    now_secs: u64,
    time_scale: u64,
) -> Result<f64, DbError> {
    let mut min = block_strength(db, base, now_secs, time_scale)?;
    for d in diffs {
        min = min.min(block_strength(db, d, now_secs, time_scale)?);
    }
    Ok(min)
}

/// The place a NEW base goes to (mailbox-i56): an empty place first, then a place whose
/// record no postman acked (it may never have left this machine), then the place whose
/// BASE is weaker (diffs do not count, V.17.5); a tie → the older record. Never derived
/// from `generation`.
pub(crate) fn place_for_new_base(
    db: &Db,
    meta: &PointerPublications,
    now_secs: u64,
    time_scale: u64,
) -> Result<PointerPlace, DbError> {
    // Rank: (class, strength, created_at) — lower is displaced first.
    //   class 0 = empty, 1 = unconfirmed, 2 = confirmed.
    let rank = |r: Option<&PlacePublication>| -> Result<(u8, f64, u64), DbError> {
        Ok(match r {
            None => (0, 0.0, 0),
            Some(r) if r.acks.is_empty() => (1, 0.0, r.created_at.0),
            Some(r) => (
                2,
                block_strength(db, &r.base, now_secs, time_scale)?,
                r.created_at.0,
            ),
        })
    };
    let a = rank(meta.in_place(PointerPlace::A))?;
    let b = rank(meta.in_place(PointerPlace::B))?;
    let b_weaker = match b.0.cmp(&a.0) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => {
            if (a.1 - b.1).abs() > 1e-9 {
                b.1 < a.1
            } else {
                b.2 < a.2
            }
        }
    };
    Ok(if b_weaker {
        PointerPlace::B
    } else {
        PointerPlace::A
    })
}

/// SS blocks the owner keeps (V.16.3): bases + diffs of both places, of everything
/// waiting to be retired, and of the running candidate (base + all its diffs, placed or
/// not). Everything else in the SS ledger is retired.
pub(crate) fn ss_blocks_to_keep(
    meta: Option<&PointerPublications>,
    candidate: Option<(&SourceBlockId, &[SourceBlockId])>,
) -> HashSet<SourceBlockId> {
    let mut keep = HashSet::new();
    if let Some(meta) = meta {
        for r in [meta.current.as_ref(), meta.other.as_ref()]
            .into_iter()
            .flatten()
        {
            keep.insert(r.base);
            keep.extend(r.diffs.iter().copied());
            for t in &r.to_retire {
                keep.insert(t.base);
                keep.extend(t.diffs.iter().copied());
            }
        }
    }
    if let Some((base, diffs)) = candidate {
        keep.insert(*base);
        keep.extend(diffs.iter().copied());
    }
    keep
}

/// Retire every SS-ledger block outside `ss_blocks_to_keep(meta, candidate)`. Only
/// blocks still in the ledger are touched (V.17.2 NOTE-2). Returns how many.
pub(crate) fn sweep_ss_ledger(
    db: &Db,
    data_dir: &std::path::Path,
    meta: Option<&PointerPublications>,
    candidate: Option<(&SourceBlockId, &[SourceBlockId])>,
) -> Result<usize, DbError> {
    let keep = ss_blocks_to_keep(meta, candidate);
    let mut retired = 0;
    for (block, _generation) in db.list_ss_blocks()? {
        if !keep.contains(&block) {
            super::publish::retire_ss_block(db, data_dir, &block);
            retired += 1;
        }
    }
    Ok(retired)
}
