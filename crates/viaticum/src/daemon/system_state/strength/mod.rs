// How well an SS block is stored, which pointer place a new base takes, and which SS
// blocks the owner keeps (CROWN-1 V.16.3-V.16.4, V.17.1-V.17.5; mailbox-i50, i56,
// i58; dr-i41, dr-i48, dr-i49).
//
// Strength of a block = live symbols / k_eff. A placement is live when its status may
// hold symbols AND its holder was seen within `W = 7 days / time_scale`. SS blocks get
// no PoS (Bug-B), so `last_seen` is the only signal that a holder is still there; it is
// an estimate, not a proof of storage (a holder that is online but silently lost its
// symbols counts as live). The same function is the DR readiness estimator (dr-i49).

use std::collections::HashSet;

use viaticum_core::constants::DECODE_OVERHEAD;
use viaticum_core::db::{Db, DbError};
use viaticum_core::mailbox::seal::PointerPlace;
use viaticum_core::mailbox::{MailboxEntry, scaled_ttl_secs};
use viaticum_core::system_state::catalog::{PlacePublication, PointerPublications};
use viaticum_core::types::{SourceBlockId, from_cbor_bytes};

#[cfg(test)]
mod tests;

/// A holder not seen for this long (divided by time_scale) no longer counts (V.17.1).
pub(crate) const HOLDER_SEEN_WINDOW_SECS: u64 = 7 * 24 * 3600;

/// dr-i39: distinct postmen that must hold the pointer for "DR ready", and until which
/// the same envelope is re-offered (i47): 3; in a circle of fewer than 6 known peers,
/// half of the others (rounded up), at least 1. dr-i63 (Ilya 2026-10-03): the peers are
/// the Kademlia-near set DR asks (`PointerPublications::kad_near`), and only their acks
/// count.
pub(crate) fn readiness_ack_threshold(known_peers: usize) -> usize {
    if known_peers >= 6 {
        3
    } else {
        known_peers.div_ceil(2).max(1)
    }
}

/// dr-i63: how many postmen DR's Kademlia lookup returns (libp2p-kad's K).
pub(crate) const KAD_NEAR_K: usize = 20;

/// dr-i63: the dr-i39 threshold of this history — over the Kademlia-near set, but never
/// below what the circle the node knows calls for: a poor lookup (2 near peers in a
/// network of 40) must not make one ack "ready" (review W8).
pub(crate) fn dr_ack_threshold(kad_near: usize, known_peers: usize) -> usize {
    readiness_ack_threshold(kad_near.max(known_peers.min(KAD_NEAR_K)))
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

/// The place a NEW base goes to (mailbox-i56): an empty place first — a record whose
/// envelope has expired counts as empty, the postmen no longer hold it (mailbox-i58) —
/// then a place whose record no postman acked (it may never have left this machine),
/// then the place whose BASE is weaker (diffs do not count, V.17.5); a tie → the older
/// record. Never derived from `generation`.
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
            Some(r) if envelope_expired(r, now_secs) => (0, 0.0, r.created_at.0),
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

/// The record's envelope is past its `expires_at`. A record whose envelope does not
/// decode (never expected: META holds what was sealed) is not called expired.
pub(crate) fn envelope_expired(r: &PlacePublication, now_secs: u64) -> bool {
    from_cbor_bytes::<MailboxEntry>(&r.entry_cbor).is_ok_and(|e| e.expires_at <= now_secs)
}

/// SS blocks the owner keeps (V.16.3): bases + diffs of both places, of the earlier
/// envelope a place keeps for readiness (dr-i52), of everything waiting to be retired,
/// and of the running candidate (base + all its diffs, placed or not). Everything else
/// in the SS ledger is retired.
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
            if let Some(reached) = &r.reached {
                keep.extend(reached.diffs.iter().copied());
            }
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

/// What `status` says about DR readiness (dr-i9, dr-i39, dr-i41, dr-i49, dr-i53;
/// mailbox-i49, i54), read from META only.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PointerReadiness {
    /// The place readiness is reported for, by its standing envelope (dr-i52): its
    /// `created_at`, files, acks of the Kademlia-near set (dr-i63). The newest
    /// restorable place when there is one (dr-i53), else the newest place at least one
    /// postman acked.
    pub accepted: Option<(u64, u32, u32)>,
    /// Every postman holding the shown place's own envelope, the trust-top included
    /// (dr-i63: only the near ones count for readiness).
    pub held: u32,
    /// dr-i63: the size of the Kademlia-near set DR asks.
    pub near_set: u32,
    /// dr-i39 number of acks needed.
    pub threshold: u32,
    /// Blocks (base + diffs) of the accepted pointer, and how many of them are
    /// recoverable by the owner's estimate (strength ≥ 1).
    pub blocks_total: u32,
    pub blocks_placed: u32,
    /// dr-i53: at least one place is restorable (its standing envelope has the
    /// threshold acks and every block recoverable).
    pub ready: bool,
    /// dr-i53: `created_at` of the catalog state DR restores for sure when ready — the
    /// newest restorable place. DR tries the fresher head first, so a newer place
    /// short of the threshold, if DR reaches it, gives a newer state.
    pub restores_state_of: Option<u64>,
    /// The last refusal of the place of the newest base.
    pub refusal: Option<viaticum_core::system_state::catalog::RefusalKind>,
    pub waiting: Option<viaticum_core::system_state::catalog::Waiting>,
}

/// DR readiness from META and the owner's placements. Read-only. dr-i53: ready when at
/// least one place of the history is restorable — a new base collecting its first acks
/// in one place does not hide a restorable state in the other. dr-i63: the dr-i39
/// threshold is over META's Kademlia-near set and counts only its acks; a place any
/// postman holds is shown, ready or not.
pub(crate) fn pointer_readiness(
    db: &Db,
    now_secs: u64,
    time_scale: u64,
) -> Result<PointerReadiness, DbError> {
    let mut r = PointerReadiness {
        threshold: u32::try_from(readiness_ack_threshold(0)).unwrap_or(u32::MAX),
        ..PointerReadiness::default()
    };
    let Some(meta) = db.pointer_publications()? else {
        return Ok(r);
    };
    let known_peers = db.list_all_peers()?.len();
    let threshold = dr_ack_threshold(meta.kad_near.len(), known_peers);
    r.threshold = u32::try_from(threshold).unwrap_or(u32::MAX);
    r.near_set = u32::try_from(meta.kad_near.len()).unwrap_or(u32::MAX);
    r.waiting = meta.waiting;
    r.refusal = meta
        .current
        .as_ref()
        .and_then(|c| c.last_refusal)
        .map(|x| x.kind);
    // dr-i53: every place by its standing envelope; ready when one is restorable.
    let mut places = Vec::with_capacity(2);
    for rec in [meta.current.as_ref(), meta.other.as_ref()]
        .into_iter()
        .flatten()
    {
        let st = standing(rec, &meta.kad_near, threshold, now_secs);
        if st.acks == 0 && st.held == 0 {
            continue;
        }
        let blocks: Vec<&SourceBlockId> = std::iter::once(st.base).chain(st.diffs).collect();
        let mut placed = 0usize;
        for b in &blocks {
            if block_strength(db, b, now_secs, time_scale)? >= 1.0 {
                placed += 1;
            }
        }
        places.push(PlaceReadiness {
            held: st.held,
            ready: st.acks >= threshold && placed == blocks.len(),
            total: blocks.len(),
            placed,
            st,
        });
    }
    // The newest restorable place; else the newest acked one (`current` first).
    let shown = places
        .iter()
        .filter(|p| p.ready)
        .max_by_key(|p| p.st.created_at)
        .or_else(|| places.first());
    if let Some(p) = shown {
        let n = |x: usize| u32::try_from(x).unwrap_or(u32::MAX);
        r.accepted = Some((p.st.created_at, p.st.files, n(p.st.acks)));
        r.held = n(p.held);
        r.blocks_total = n(p.total);
        r.blocks_placed = n(p.placed);
        r.ready = p.ready;
        r.restores_state_of = p.ready.then_some(p.st.created_at);
    }
    Ok(r)
}

/// One place judged for readiness (dr-i53).
struct PlaceReadiness<'a> {
    st: Standing<'a>,
    /// Every postman holding the record's own envelope.
    held: usize,
    placed: usize,
    total: usize,
    ready: bool,
}

/// The envelope a place stands on for readiness (dr-i52).
struct Standing<'a> {
    base: &'a SourceBlockId,
    diffs: &'a [SourceBlockId],
    created_at: u64,
    files: u32,
    /// Acks of the Kademlia-near set (dr-i63).
    acks: usize,
    /// Every postman that acked the envelope stood on.
    held: usize,
}

/// A place stands on its own envelope, unless that one is short of the threshold and
/// an earlier envelope of the same base that reached it is still unexpired: then on
/// that one, so a new envelope collecting acks does not make readiness blink.
fn standing<'a>(
    r: &'a PlacePublication,
    kad_near: &[viaticum_core::types::DeviceId],
    threshold: usize,
    now_secs: u64,
) -> Standing<'a> {
    let near = r.near_acks(kad_near);
    match r.reached.as_ref() {
        Some(e) if near < threshold && e.expires_at > now_secs => Standing {
            base: &r.base,
            diffs: &e.diffs,
            created_at: e.created_at.0,
            files: e.files,
            acks: e.acked.iter().filter(|a| kad_near.contains(a)).count(),
            held: e.acked.len(),
        },
        _ => Standing {
            base: &r.base,
            diffs: &r.diffs,
            created_at: r.created_at.0,
            files: r.files,
            acks: near,
            held: r.acks.len(),
        },
    }
}
