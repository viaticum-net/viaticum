//! Measures of the shadow that are not decisions: the κ = 0 classes (§10 R2 — did we ever
//! ask this owner to store for us?) and the divergence between the old and the new owner
//! order.

use std::collections::{HashMap, HashSet};

use crate::budget::eviction_priority;
use crate::types::{
    HoldingRecord, HoldingStatus, IdentityPub, PeerRecord, PlacementStatus, SymbolPlacement,
};

/// Our placements at the devices of one master.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Presence {
    /// At least one placement row of ours at a device of this master.
    pub any: bool,
    /// At least one of them is `Alive` or `Uncertain` (the held set).
    pub held: bool,
}

/// The class of a zero-service owner (κ < [`super::ZERO_KAPPA_EPS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ZeroKappaClass {
    /// No placement row of ours at any device of this master.
    NeverAsked,
    /// Rows exist, none Alive/Uncertain: declined or in-flight offer (`Offered`, `Accepted`),
    /// accepted then lost/dropped (`Lost`, `PresumedLost`), or our own deletion (`Deleting`)
    /// — NOT only "refused".
    Asked,
    /// Alive/Uncertain present but not confirmed (a new pair, or "accepted and never
    /// proved", `4r-i1`).
    ServingUnconfirmed,
}

/// Presence of our placements by the holder's MASTER (Д-M: `PeerRecord::master_identity`).
/// A placement at a device without a `PeerRecord`, or whose record still carries the
/// placeholder master `[0; 32]`, is skipped (it would fold unrelated devices into one
/// "zero person"; the cost is an over-count of "never asked").
pub fn placement_presence_by_master(
    placements: &[SymbolPlacement],
    peers: &[PeerRecord],
) -> HashMap<IdentityPub, Presence> {
    let placeholder = IdentityPub([0u8; 32]);
    let master_of: HashMap<_, _> = peers
        .iter()
        .filter(|p| p.master_identity != placeholder)
        .map(|p| (p.device_id, p.master_identity))
        .collect();
    let mut out: HashMap<IdentityPub, Presence> = HashMap::new();
    for pl in placements {
        let Some(master) = master_of.get(&pl.holder_id) else {
            continue;
        };
        let e = out.entry(*master).or_default();
        e.any = true;
        if matches!(
            pl.status,
            PlacementStatus::Alive | PlacementStatus::Uncertain
        ) {
            e.held = true;
        }
    }
    out
}

/// The κ = 0 class from the presence of our placements at that master.
pub fn zero_kappa_class(p: Option<&Presence>) -> ZeroKappaClass {
    match p {
        Some(p) if p.held => ZeroKappaClass::ServingUnconfirmed,
        Some(p) if p.any => ZeroKappaClass::Asked,
        _ => ZeroKappaClass::NeverAsked,
    }
}

/// The OLD path's owner order — exactly `budget::evaluate_pressure`'s candidate sort:
/// priority = `eviction_priority(ι, trust(owner), received_at, now)`, MarkedForDelete clamped
/// to `min(0, p)`, stable sort by `partial_cmp` (ties and NaN keep input order, which is the
/// order `list_all_holdings` returns); owners by their first appearance.
pub fn old_owner_order(
    holdings: &[HoldingRecord],
    owner_trust: impl Fn(&IdentityPub) -> f64,
    now_secs: u64,
) -> Vec<IdentityPub> {
    // Trust is per owner: ask once per owner (the daemon's closure reads PEERS), not once per
    // holding — the same values `evaluate_pressure` got, at O(owners) lookups.
    let mut trust: HashMap<IdentityPub, f64> = HashMap::new();
    let mut cands: Vec<(&HoldingRecord, f64)> = holdings
        .iter()
        .map(|r| {
            let t = *trust
                .entry(r.owner_id)
                .or_insert_with(|| owner_trust(&r.owner_id));
            let p = eviction_priority(r.importance, t, r.received_at, now_secs);
            let p = if r.status == HoldingStatus::MarkedForDelete {
                0.0f64.min(p)
            } else {
                p
            };
            (r, p)
        })
        .collect();
    cands.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut seen: HashSet<IdentityPub> = HashSet::new();
    let mut out = Vec::new();
    for (r, _) in cands {
        if seen.insert(r.owner_id) {
            out.push(r.owner_id);
        }
    }
    out
}

/// How far the new owner order is from the old one.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderDivergence {
    pub first_old: Option<IdentityPub>,
    pub first_new: Option<IdentityPub>,
    /// Owners present in both orders.
    pub common: u32,
    /// |top-10(old) ∩ top-10(new)|.
    pub top10_overlap: u32,
    /// Kendall τ over the common owners (strict permutations: τ_b = τ_a). `None` when
    /// `common < 2`.
    pub kendall_tau: Option<f64>,
}

/// Compare two owner orders (first = evicted first).
pub fn compare_owner_orders(old: &[IdentityPub], new: &[IdentityPub]) -> OrderDivergence {
    let in_new: HashSet<&IdentityPub> = new.iter().collect();
    let in_old: HashSet<&IdentityPub> = old.iter().collect();
    let old_c: Vec<&IdentityPub> = old.iter().filter(|m| in_new.contains(m)).collect();
    let new_rank: HashMap<&IdentityPub, usize> = new
        .iter()
        .filter(|m| in_old.contains(m))
        .enumerate()
        .map(|(i, m)| (m, i))
        .collect();
    let top_new: HashSet<&IdentityPub> = new.iter().take(10).collect();
    let top10_overlap = old.iter().take(10).filter(|m| top_new.contains(m)).count() as u32;
    let n = old_c.len();
    let kendall_tau = if n < 2 {
        None
    } else {
        // Positions in `old_c` are the old ranks 0..n; compare with the new ranks.
        let r: Vec<usize> = old_c.iter().map(|m| new_rank[m]).collect();
        let mut s: i64 = 0;
        for i in 0..n {
            for j in (i + 1)..n {
                s += if r[i] < r[j] { 1 } else { -1 };
            }
        }
        Some(s as f64 / (n * (n - 1) / 2) as f64)
    };
    OrderDivergence {
        first_old: old.first().copied(),
        first_new: new.first().copied(),
        common: n as u32,
        top10_overlap,
        kendall_tau,
    }
}
